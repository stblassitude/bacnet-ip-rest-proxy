package bacnet

import "fmt"

// BACnet Virtual Link Control (BACnet/IP, ASHRAE 135 Annex J) function codes
// we support. This proxy only ever talks unicast to specific configured
// hosts, so broadcast/forwarding functions are not implemented.
const (
	bvlcTypeIP                byte = 0x81
	bvlcFuncOriginalUnicast   byte = 0x0A
	bvlcFuncOriginalBroadcast byte = 0x0B
)

// EncodeUnicastPacket wraps an APDU in an NPDU and a BACnet/IP BVLC header
// addressed as an Original-Unicast-NPDU.
func EncodeUnicastPacket(apdu []byte) []byte {
	npdu := encodeNPDU(apdu)
	total := 4 + len(npdu)
	buf := []byte{bvlcTypeIP, bvlcFuncOriginalUnicast, byte(total >> 8), byte(total)}
	return append(buf, npdu...)
}

// DecodeIncomingPacket strips the BVLC and NPDU headers from a received
// BACnet/IP packet and decodes the enclosed APDU.
func DecodeIncomingPacket(pkt []byte) (APDU, error) {
	if len(pkt) < 4 {
		return APDU{}, fmt.Errorf("bacnet: truncated BVLC header")
	}
	if pkt[0] != bvlcTypeIP {
		return APDU{}, fmt.Errorf("bacnet: unsupported BVLC type 0x%02x", pkt[0])
	}
	switch pkt[1] {
	case bvlcFuncOriginalUnicast, bvlcFuncOriginalBroadcast:
	default:
		return APDU{}, fmt.Errorf("bacnet: unsupported BVLC function 0x%02x", pkt[1])
	}
	length := int(pkt[2])<<8 | int(pkt[3])
	if length != len(pkt) {
		return APDU{}, fmt.Errorf("bacnet: BVLC length %d does not match packet length %d", length, len(pkt))
	}
	apduBytes, err := decodeNPDU(pkt[4:])
	if err != nil {
		return APDU{}, err
	}
	return DecodeAPDU(apduBytes)
}
