package bacnetmock

import (
	"log/slog"
	"net"

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
}

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
	buf := make([]byte, 1500)
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
	if apdu.ServiceChoice != bacnet.ServiceUnconfirmedWhoIs {
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
	values, bacErr := s.device.readProperty(req.Object.Type, req.Object.Instance, req.Property)
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
	pkt := bacnet.EncodeUnicastPacket(bacnet.EncodeComplexACKAPDU(apdu.InvokeID, apdu.ServiceChoice, ack))
	_, _ = s.conn.WriteToUDP(pkt, from)
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
			values, bacErr := s.device.readProperty(spec.Object.Type, spec.Object.Instance, ref.Property)
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
	pkt := bacnet.EncodeUnicastPacket(bacnet.EncodeComplexACKAPDU(apdu.InvokeID, apdu.ServiceChoice, ack))
	_, _ = s.conn.WriteToUDP(pkt, from)
}
