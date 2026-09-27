package bacnetmock

import (
	"log/slog"
	"net"
	"sync/atomic"

	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/bacnet"
)

// Server is a UDP listener that answers BACnet/IP requests against a Device,
// encoding/decoding real wire packets via internal/bacnet. It is intended
// only for tests, in place of a physical BACnet/IP controller.
type Server struct {
	device *Device
	conn   *net.UDPConn
	log    *slog.Logger
	done   chan struct{}

	ignoreWhoIs atomic.Bool
}

// SetIgnoreWhoIs makes the server stop answering Who-Is, like a device
// whose I-Am is broadcast where the client can't receive it.
func (s *Server) SetIgnoreWhoIs(ignore bool) { s.ignoreWhoIs.Store(ignore) }

// Listen starts a mock BACnet/IP server for device on addr (e.g.
// "127.0.0.1:0" to pick an ephemeral port). Call Addr to discover the port
// that was bound, and Close to shut it down.
func Listen(addr string, device *Device) (*Server, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	s := &Server{
		device: device,
		conn:   conn,
		log:    slog.Default().With("component", "bacnetmock"),
		done:   make(chan struct{}),
	}
	go s.serve()
	return s, nil
}

// Addr returns the address the mock server is listening on.
func (s *Server) Addr() *net.UDPAddr { return s.conn.LocalAddr().(*net.UDPAddr) }

// Close stops the server.
func (s *Server) Close() error {
	close(s.done)
	return s.conn.Close()
}

func (s *Server) serve() {
	buf := make([]byte, 65535)
	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				return
			}
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go s.handlePacket(pkt, addr)
	}
}

func (s *Server) handlePacket(pkt []byte, from *net.UDPAddr) {
	apdu, err := bacnet.DecodeIncomingPacket(pkt)
	if err != nil {
		s.log.Debug("dropping malformed packet", "from", from, "err", err)
		return
	}
	switch apdu.Type {
	case bacnet.PDUUnconfirmedRequest:
		s.handleUnconfirmed(apdu, from)
	case bacnet.PDUConfirmedRequest:
		s.handleConfirmed(apdu, from)
	}
}

func (s *Server) handleUnconfirmed(apdu bacnet.APDU, from *net.UDPAddr) {
	if apdu.ServiceChoice != bacnet.ServiceUnconfirmedWhoIs || s.ignoreWhoIs.Load() {
		return
	}
	req, err := bacnet.DecodeWhoIsRequest(apdu.Params)
	if err != nil {
		return
	}
	if req.LowLimit != nil && s.device.Instance() < *req.LowLimit {
		return
	}
	if req.HighLimit != nil && s.device.Instance() > *req.HighLimit {
		return
	}
	params := bacnet.EncodeIAm(bacnet.IAm{
		Device:                bacnet.ObjectIdentifier{Type: bacnet.ObjectDevice, Instance: s.device.Instance()},
		MaxAPDULength:         1476,
		SegmentationSupported: 3, // no-segmentation
		VendorID:              s.device.vendorID,
	})
	pkt := bacnet.EncodeUnicastPacket(bacnet.EncodeUnconfirmedRequestAPDU(bacnet.ServiceUnconfirmedIAm, params))
	_, _ = s.conn.WriteToUDP(pkt, from)
}

func (s *Server) handleConfirmed(apdu bacnet.APDU, from *net.UDPAddr) {
	switch apdu.ServiceChoice {
	case bacnet.ServiceConfirmedReadProperty:
		s.handleReadProperty(apdu, from)
	case bacnet.ServiceConfirmedWriteProperty:
		s.handleWriteProperty(apdu, from)
	case bacnet.ServiceConfirmedReadPropertyMultiple:
		s.handleReadPropertyMultiple(apdu, from)
	default:
		pkt := bacnet.EncodeUnicastPacket(bacnet.EncodeRejectAPDU(apdu.InvokeID, 9)) // 9 = unrecognized-service
		_, _ = s.conn.WriteToUDP(pkt, from)
	}
}

func (s *Server) sendError(invokeID uint8, serviceChoice uint8, from *net.UDPAddr, bacErr *bacnet.BACnetError) {
	pkt := bacnet.EncodeUnicastPacket(bacnet.EncodeErrorAPDU(invokeID, serviceChoice, *bacErr))
	_, _ = s.conn.WriteToUDP(pkt, from)
}

func (s *Server) handleReadProperty(apdu bacnet.APDU, from *net.UDPAddr) {
	req, err := bacnet.DecodeReadPropertyRequest(apdu.Params)
	if err != nil {
		s.log.Debug("malformed ReadProperty request", "err", err)
		return
	}
	values, bacErr := s.device.readProperty(req.Object.Type, req.Object.Instance, req.Property, req.ArrayIndex)
	if bacErr != nil {
		s.sendError(apdu.InvokeID, apdu.ServiceChoice, from, bacErr)
		return
	}
	ack := bacnet.EncodeReadPropertyACK(bacnet.ReadPropertyACK{
		Object:     req.Object,
		Property:   req.Property,
		ArrayIndex: req.ArrayIndex,
		Values:     values,
	})
	s.sendComplexACK(apdu, ack, from)
}

func (s *Server) handleWriteProperty(apdu bacnet.APDU, from *net.UDPAddr) {
	req, err := bacnet.DecodeWritePropertyRequest(apdu.Params)
	if err != nil {
		s.log.Debug("malformed WriteProperty request", "err", err)
		return
	}
	if bacErr := s.device.writeProperty(req.Object.Type, req.Object.Instance, req.Property, req.Value, req.Priority); bacErr != nil {
		s.sendError(apdu.InvokeID, apdu.ServiceChoice, from, bacErr)
		return
	}
	pkt := bacnet.EncodeUnicastPacket(bacnet.EncodeSimpleACKAPDU(apdu.InvokeID, apdu.ServiceChoice))
	_, _ = s.conn.WriteToUDP(pkt, from)
}

func (s *Server) handleReadPropertyMultiple(apdu bacnet.APDU, from *net.UDPAddr) {
	specs, err := bacnet.DecodeReadPropertyMultipleRequest(apdu.Params)
	if err != nil {
		s.log.Debug("malformed ReadPropertyMultiple request", "err", err)
		return
	}
	results := make([]bacnet.ReadAccessResult, 0, len(specs))
	for _, spec := range specs {
		result := bacnet.ReadAccessResult{Object: spec.Object}
		for _, ref := range spec.Properties {
			values, bacErr := s.device.readProperty(spec.Object.Type, spec.Object.Instance, ref.Property, ref.ArrayIndex)
			result.Results = append(result.Results, bacnet.PropertyResult{
				Property:   ref.Property,
				ArrayIndex: ref.ArrayIndex,
				Values:     values,
				Err:        bacErr,
			})
		}
		results = append(results, result)
	}
	ack := bacnet.EncodeReadPropertyMultipleACK(results)
	s.sendComplexACK(apdu, ack, from)
}

// maxAPDU is the largest APDU the proxy's client accepts (it declares
// max-APDU-length-accepted 1476 and no segmentation).
const maxAPDU = 1476

// sendComplexACK sends ack, or, like a real device that can't segment a
// reply the client won't accept segmented, an Abort with reason
// segmentation-not-supported when it doesn't fit in one APDU.
func (s *Server) sendComplexACK(req bacnet.APDU, ack []byte, from *net.UDPAddr) {
	reply := bacnet.EncodeComplexACKAPDU(req.InvokeID, req.ServiceChoice, ack)
	if len(reply) > maxAPDU {
		reply = bacnet.EncodeAbortAPDU(req.InvokeID, bacnet.AbortReasonSegmentationNotSupported)
	}
	_, _ = s.conn.WriteToUDP(bacnet.EncodeUnicastPacket(reply), from)
}
