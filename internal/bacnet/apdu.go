package bacnet

import "fmt"

// PDUType is the APDU type carried in the top nibble of the first octet
// (ASHRAE 135 clause 20.1.2). Only unsegmented PDUs are supported.
type PDUType uint8

const (
	PDUConfirmedRequest   PDUType = 0x0
	PDUUnconfirmedRequest PDUType = 0x1
	PDUSimpleACK          PDUType = 0x2
	PDUComplexACK         PDUType = 0x3
	PDUSegmentACK         PDUType = 0x4
	PDUError              PDUType = 0x5
	PDUReject             PDUType = 0x6
	PDUAbort              PDUType = 0x7
)

// Confirmed service choice codes we implement (ASHRAE 135 clause 21).
const (
	ServiceConfirmedReadProperty         uint8 = 12
	ServiceConfirmedReadPropertyMultiple uint8 = 14
	ServiceConfirmedWriteProperty        uint8 = 15
)

// Unconfirmed service choice codes we implement.
const (
	ServiceUnconfirmedIAm   uint8 = 0
	ServiceUnconfirmedWhoIs uint8 = 8
)

// APDU is a decoded Application Layer PDU. Which fields are meaningful
// depends on Type.
type APDU struct {
	Type          PDUType
	InvokeID      uint8
	ServiceChoice uint8
	RejectReason  uint8
	AbortReason   uint8
	Params        []byte
}

// EncodeConfirmedRequestAPDU builds a Confirmed-Request APDU. We always
// declare max-segments-accepted=0 and segmented-response-accepted=0 (control
// bit SA), since this proxy neither sends nor accepts segmented PDUs.
func EncodeConfirmedRequestAPDU(invokeID uint8, serviceChoice uint8, params []byte) []byte {
	// byte0: PDU type 0000, SEG=0, MOR=0, SA=0, reserved=0
	// byte1: max-segments-accepted (0) << 4 | max-APDU-length-accepted (5 == up to 1476 bytes)
	buf := []byte{0x00, 0x05, invokeID, serviceChoice}
	return append(buf, params...)
}

func EncodeUnconfirmedRequestAPDU(serviceChoice uint8, params []byte) []byte {
	buf := []byte{byte(PDUUnconfirmedRequest) << 4, serviceChoice}
	return append(buf, params...)
}

func EncodeSimpleACKAPDU(invokeID uint8, serviceChoice uint8) []byte {
	return []byte{byte(PDUSimpleACK) << 4, invokeID, serviceChoice}
}

func EncodeComplexACKAPDU(invokeID uint8, serviceChoice uint8, params []byte) []byte {
	buf := []byte{byte(PDUComplexACK) << 4, invokeID, serviceChoice}
	return append(buf, params...)
}

func EncodeErrorAPDU(invokeID uint8, serviceChoice uint8, bacErr BACnetError) []byte {
	buf := []byte{byte(PDUError) << 4, invokeID, serviceChoice}
	buf = AppendContextValue(buf, true, 0, EnumeratedValue(uint32(bacErr.Class)))
	buf = AppendContextValue(buf, true, 1, EnumeratedValue(uint32(bacErr.Code)))
	return buf
}

func EncodeRejectAPDU(invokeID uint8, reason uint8) []byte {
	return []byte{byte(PDUReject) << 4, invokeID, reason}
}

func EncodeAbortAPDU(invokeID uint8, reason uint8) []byte {
	return []byte{byte(PDUAbort)<<4 | 0x01, invokeID, reason} // bit0 = sent by server
}

// DecodeAPDU parses the APDU-type-specific fixed header. Segmented PDUs are
// rejected as unsupported.
func DecodeAPDU(buf []byte) (APDU, error) {
	if len(buf) < 1 {
		return APDU{}, fmt.Errorf("bacnet: empty APDU")
	}
	pduType := PDUType(buf[0] >> 4)
	switch pduType {
	case PDUConfirmedRequest:
		if buf[0]&0x08 != 0 {
			return APDU{}, fmt.Errorf("bacnet: segmented confirmed requests are not supported")
		}
		if len(buf) < 4 {
			return APDU{}, fmt.Errorf("bacnet: truncated confirmed-request APDU")
		}
		return APDU{Type: pduType, InvokeID: buf[2], ServiceChoice: buf[3], Params: buf[4:]}, nil
	case PDUUnconfirmedRequest:
		if len(buf) < 2 {
			return APDU{}, fmt.Errorf("bacnet: truncated unconfirmed-request APDU")
		}
		return APDU{Type: pduType, ServiceChoice: buf[1], Params: buf[2:]}, nil
	case PDUSimpleACK:
		if len(buf) < 3 {
			return APDU{}, fmt.Errorf("bacnet: truncated simple-ack APDU")
		}
		return APDU{Type: pduType, InvokeID: buf[1], ServiceChoice: buf[2]}, nil
	case PDUComplexACK:
		if buf[0]&0x08 != 0 {
			return APDU{}, fmt.Errorf("bacnet: segmented complex-acks are not supported")
		}
		if len(buf) < 3 {
			return APDU{}, fmt.Errorf("bacnet: truncated complex-ack APDU")
		}
		return APDU{Type: pduType, InvokeID: buf[1], ServiceChoice: buf[2], Params: buf[3:]}, nil
	case PDUError:
		if len(buf) < 3 {
			return APDU{}, fmt.Errorf("bacnet: truncated error APDU")
		}
		return APDU{Type: pduType, InvokeID: buf[1], ServiceChoice: buf[2], Params: buf[3:]}, nil
	case PDUReject:
		if len(buf) < 3 {
			return APDU{}, fmt.Errorf("bacnet: truncated reject APDU")
		}
		return APDU{Type: pduType, InvokeID: buf[1], RejectReason: buf[2]}, nil
	case PDUAbort:
		if len(buf) < 3 {
			return APDU{}, fmt.Errorf("bacnet: truncated abort APDU")
		}
		return APDU{Type: pduType, InvokeID: buf[1], AbortReason: buf[2]}, nil
	default:
		return APDU{}, fmt.Errorf("bacnet: unsupported APDU type %d", pduType)
	}
}
