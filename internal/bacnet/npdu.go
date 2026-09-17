package bacnet

import "fmt"

// encodeNPDU wraps apdu in a minimal Network Layer PDU: protocol version 1,
// no destination/source network addressing (we always address BACnet/IP
// devices directly, without BACnet routers).
func encodeNPDU(apdu []byte) []byte {
	return append([]byte{0x01, 0x00}, apdu...)
}

// decodeNPDU strips an NPDU header and returns the enclosed APDU. It
// tolerates (by skipping) destination/source network address fields in case
// a peer includes them, but rejects network-layer-message NPDUs, which this
// proxy never needs to send or interpret.
func decodeNPDU(buf []byte) ([]byte, error) {
	if len(buf) < 2 {
		return nil, fmt.Errorf("bacnet: truncated NPDU header")
	}
	control := buf[1]
	pos := 2
	if control&0x80 != 0 {
		return nil, fmt.Errorf("bacnet: network layer message NPDUs are not supported")
	}
	if control&0x20 != 0 { // destination specifier present
		if len(buf) < pos+3 {
			return nil, fmt.Errorf("bacnet: truncated NPDU destination address")
		}
		dlen := int(buf[pos+2])
		pos += 3 + dlen + 1 // DNET(2)+DLEN(1)+DADR(dlen)+DHOPCOUNT(1)
	}
	if control&0x08 != 0 { // source specifier present
		if len(buf) < pos+3 {
			return nil, fmt.Errorf("bacnet: truncated NPDU source address")
		}
		slen := int(buf[pos+2])
		pos += 3 + slen
	}
	if len(buf) < pos+1 {
		return nil, fmt.Errorf("bacnet: NPDU has no enclosed APDU")
	}
	return buf[pos:], nil
}
