package bacnet

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// DefaultPort is the standard BACnet/IP UDP port.
const DefaultPort = 47808

// ClientOptions configures a Client.
type ClientOptions struct {
	// LocalAddr is the local UDP address to bind, e.g. "0.0.0.0:0" or
	// "127.0.0.1:0". An empty value binds an ephemeral port on all interfaces.
	LocalAddr string
	Timeout   time.Duration
	Retries   int
}

// Client is a minimal BACnet/IP client supporting unicast Who-Is, ReadProperty,
// ReadPropertyMultiple and WriteProperty against a fixed set of hosts. A single
// Client can be used concurrently against many different devices.
type Client struct {
	conn    *net.UDPConn
	timeout time.Duration
	retries int

	mu      sync.Mutex
	nextID  uint8
	pending map[uint8]*pendingRequest

	iamMu   sync.Mutex
	iamSubs map[chan iamEvent]struct{}
}

type apduOrError struct {
	apdu APDU
	err  error
}

// pendingRequest is an outstanding confirmed request, awaiting a reply
// from its destination with its invoke ID.
type pendingRequest struct {
	to      *net.UDPAddr
	service uint8
	ch      chan apduOrError
}

type iamEvent struct {
	from net.IP
	iam  IAm
}

// NewClient creates a Client bound to opts.LocalAddr and starts its receive loop.
func NewClient(opts ClientOptions) (*Client, error) {
	localAddr := opts.LocalAddr
	if localAddr == "" {
		localAddr = "0.0.0.0:0"
	}
	addr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("bacnet: resolve local address: %w", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("bacnet: listen: %w", err)
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	retries := opts.Retries
	if retries < 0 {
		retries = 0
	}
	c := &Client{
		conn:    conn,
		timeout: timeout,
		retries: retries,
		pending: make(map[uint8]*pendingRequest),
		iamSubs: make(map[chan iamEvent]struct{}),
	}
	go c.readLoop()
	return c, nil
}

// LocalAddr returns the local UDP address the client is bound to.
func (c *Client) LocalAddr() net.Addr { return c.conn.LocalAddr() }

// Close shuts down the client's socket.
func (c *Client) Close() error { return c.conn.Close() }

func (c *Client) readLoop() {
	// Large enough for any UDP datagram: a maximal 1476-byte APDU plus NPDU
	// routing information and a forwarded BVLC header exceeds 1500 bytes.
	buf := make([]byte, 65535)
	for {
		n, addr, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		c.handleIncoming(pkt, addr)
	}
}

func (c *Client) handleIncoming(pkt []byte, from *net.UDPAddr) {
	apdu, err := DecodeIncomingPacket(pkt)
	if err != nil {
		return
	}
	switch apdu.Type {
	case PDUSimpleACK, PDUComplexACK, PDUError, PDUReject, PDUAbort:
		c.mu.Lock()
		req, ok := c.pending[apdu.InvokeID]
		c.mu.Unlock()
		// Invoke IDs are only unique per peer, so a reply must also come
		// from the address the request went to.
		// Reject/Abort PDUs carry no service choice; the others must answer
		// the requested service, so a late reply to an earlier request that
		// reused this invoke ID isn't taken for this one's.
		sameService := apdu.Type == PDUReject || apdu.Type == PDUAbort || apdu.ServiceChoice == req.service
		if ok && req.to.IP.Equal(from.IP) && sameService {
			select {
			case req.ch <- apduOrError{apdu: apdu}:
			default: // a duplicate reply to a retransmitted request
			}
		}
	case PDUUnconfirmedRequest:
		if apdu.ServiceChoice == ServiceUnconfirmedIAm {
			iam, err := DecodeIAm(apdu.Params)
			if err != nil {
				return
			}
			c.iamMu.Lock()
			for ch := range c.iamSubs {
				select {
				case ch <- iamEvent{from: from.IP, iam: iam}:
				default:
				}
			}
			c.iamMu.Unlock()
		}
	}
}

func resolveDeviceAddr(hostPort string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
		port = ""
	}
	if port == "" {
		return net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, DefaultPort))
	}
	return net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
}

// WhoIs sends a unicast Who-Is request to hostPort and waits for a matching
// I-Am reply, retrying up to c.retries times on timeout.
func (c *Client) WhoIs(ctx context.Context, hostPort string) (IAm, error) {
	addr, err := resolveDeviceAddr(hostPort)
	if err != nil {
		return IAm{}, err
	}

	ch := make(chan iamEvent, 8)
	c.iamMu.Lock()
	c.iamSubs[ch] = struct{}{}
	c.iamMu.Unlock()
	defer func() {
		c.iamMu.Lock()
		delete(c.iamSubs, ch)
		c.iamMu.Unlock()
	}()

	pkt := EncodeUnicastPacket(EncodeUnconfirmedRequestAPDU(ServiceUnconfirmedWhoIs, EncodeWhoIsRequest(WhoIsRequest{})))
	for attempt := 0; attempt <= c.retries; attempt++ {
		if _, err := c.conn.WriteToUDP(pkt, addr); err != nil {
			return IAm{}, fmt.Errorf("bacnet: send who-is to %s: %w", addr, err)
		}
		deadline := time.Now().Add(c.timeout)
		for {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				break
			}
			select {
			case ev := <-ch:
				if ev.from.Equal(addr.IP) {
					return ev.iam, nil
				}
			case <-time.After(remaining):
			case <-ctx.Done():
				return IAm{}, ctx.Err()
			}
		}
	}
	return IAm{}, fmt.Errorf("%w: who-is to %s", ErrTimeout, addr)
}

// DeviceInstance returns the device instance number of the BACnet device at
// hostPort. It asks with Who-Is first; since a device may broadcast its
// I-Am reply to the standard port, where this client (on its own port)
// never sees it, it then falls back to reading the Device object's
// object-identifier through the wildcard instance (clause 12.11.1).
func (c *Client) DeviceInstance(ctx context.Context, hostPort string) (uint32, error) {
	iam, whoIsErr := c.WhoIs(ctx, hostPort)
	if whoIsErr == nil {
		return iam.Device.Instance, nil
	}
	if ctx.Err() != nil {
		return 0, whoIsErr
	}
	values, err := c.ReadProperty(ctx, hostPort, ObjectIdentifier{Type: ObjectDevice, Instance: DeviceInstanceWildcard}, PropObjectID, nil)
	if err != nil {
		return 0, fmt.Errorf("%w; reading the wildcard device's object-identifier also failed: %w", whoIsErr, err)
	}
	if len(values) != 1 || values[0].Kind != KindObjectID || values[0].Object.Type != ObjectDevice {
		return 0, fmt.Errorf("%w; unexpected wildcard device object-identifier %v", whoIsErr, values)
	}
	return values[0].Object.Instance, nil
}

func (c *Client) doConfirmedRequest(ctx context.Context, addr *net.UDPAddr, serviceChoice uint8, params []byte) (APDU, error) {
	c.mu.Lock()
	var invokeID uint8
	found := false
	for range 256 {
		invokeID = c.nextID
		c.nextID++
		if _, inUse := c.pending[invokeID]; !inUse {
			found = true
			break
		}
	}
	if !found {
		c.mu.Unlock()
		return APDU{}, fmt.Errorf("bacnet: too many outstanding requests")
	}
	ch := make(chan apduOrError, 1)
	c.pending[invokeID] = &pendingRequest{to: addr, service: serviceChoice, ch: ch}
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, invokeID)
		c.mu.Unlock()
	}()

	pkt := EncodeUnicastPacket(EncodeConfirmedRequestAPDU(invokeID, serviceChoice, params))
	for attempt := 0; attempt <= c.retries; attempt++ {
		if _, err := c.conn.WriteToUDP(pkt, addr); err != nil {
			return APDU{}, fmt.Errorf("bacnet: send to %s: %w", addr, err)
		}
		select {
		case result := <-ch:
			return result.apdu, result.err
		case <-time.After(c.timeout):
			continue
		case <-ctx.Done():
			return APDU{}, ctx.Err()
		}
	}
	return APDU{}, fmt.Errorf("%w: request to %s", ErrTimeout, addr)
}

// serviceError translates an unexpected reply APDU (Error/Reject/Abort) into
// a Go error, or reports a protocol mismatch.
func serviceError(apdu APDU, wantType PDUType) error {
	switch apdu.Type {
	case PDUError:
		bacErr, err := DecodeBACnetError(apdu.Params)
		if err != nil {
			return err
		}
		return bacErr
	case PDUReject:
		return &RejectError{Reason: apdu.RejectReason}
	case PDUAbort:
		return &AbortError{Reason: apdu.AbortReason}
	default:
		return fmt.Errorf("bacnet: unexpected APDU type %d, wanted %d", apdu.Type, wantType)
	}
}

// ReadProperty reads a single property, optionally at an array index, from a
// BACnet device reachable at hostPort.
func (c *Client) ReadProperty(ctx context.Context, hostPort string, obj ObjectIdentifier, prop PropertyIdentifier, arrayIndex *uint32) ([]Value, error) {
	addr, err := resolveDeviceAddr(hostPort)
	if err != nil {
		return nil, err
	}
	params := EncodeReadPropertyRequest(ReadPropertyRequest{Object: obj, Property: prop, ArrayIndex: arrayIndex})
	apdu, err := c.doConfirmedRequest(ctx, addr, ServiceConfirmedReadProperty, params)
	if err != nil {
		return nil, err
	}
	if apdu.Type != PDUComplexACK {
		return nil, serviceError(apdu, PDUComplexACK)
	}
	ack, err := DecodeReadPropertyACK(apdu.Params)
	if err != nil {
		return nil, err
	}
	return ack.Values, nil
}

// ReadPropertyMultiple reads several properties, potentially across several
// objects, in a single request.
func (c *Client) ReadPropertyMultiple(ctx context.Context, hostPort string, specs []ReadAccessSpec) ([]ReadAccessResult, error) {
	addr, err := resolveDeviceAddr(hostPort)
	if err != nil {
		return nil, err
	}
	params := EncodeReadPropertyMultipleRequest(specs)
	apdu, err := c.doConfirmedRequest(ctx, addr, ServiceConfirmedReadPropertyMultiple, params)
	if err != nil {
		return nil, err
	}
	if apdu.Type != PDUComplexACK {
		return nil, serviceError(apdu, PDUComplexACK)
	}
	return DecodeReadPropertyMultipleACK(apdu.Params)
}

// WriteProperty writes value to a property, optionally at a given priority
// (1-16) for commandable properties. A Value of KindNull relinquishes that
// priority.
func (c *Client) WriteProperty(ctx context.Context, hostPort string, obj ObjectIdentifier, prop PropertyIdentifier, value Value, priority *uint8) error {
	addr, err := resolveDeviceAddr(hostPort)
	if err != nil {
		return err
	}
	params := EncodeWritePropertyRequest(WritePropertyRequest{Object: obj, Property: prop, Value: value, Priority: priority})
	apdu, err := c.doConfirmedRequest(ctx, addr, ServiceConfirmedWriteProperty, params)
	if err != nil {
		return err
	}
	if apdu.Type != PDUSimpleACK {
		return serviceError(apdu, PDUSimpleACK)
	}
	return nil
}
