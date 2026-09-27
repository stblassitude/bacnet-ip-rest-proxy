package bacnet

import "fmt"

// ErrorClass is a BACnet error-class enumeration value (ASHRAE 135 clause 21).
type ErrorClass uint32

const (
	ErrorClassDevice        ErrorClass = 0
	ErrorClassObject        ErrorClass = 1
	ErrorClassProperty      ErrorClass = 2
	ErrorClassResources     ErrorClass = 3
	ErrorClassSecurity      ErrorClass = 4
	ErrorClassServices      ErrorClass = 5
	ErrorClassCommunication ErrorClass = 7
)

// ErrorCode is a BACnet error-code enumeration value. Only the subset this
// proxy actually produces or needs to recognize is defined.
type ErrorCode uint32

const (
	ErrorCodeOther             ErrorCode = 0
	ErrorCodeTimeout           ErrorCode = 30
	ErrorCodeUnknownObject     ErrorCode = 31
	ErrorCodeUnknownProperty   ErrorCode = 32
	ErrorCodeValueOutOfRange   ErrorCode = 37
	ErrorCodeWriteAccessDenied ErrorCode = 39
	ErrorCodeInvalidArrayIndex ErrorCode = 42
)

// Abort and reject reasons (ASHRAE 135 clause 21) the proxy needs to
// recognize.
const (
	AbortReasonBufferOverflow           uint8 = 1
	AbortReasonSegmentationNotSupported uint8 = 4
	RejectReasonUnrecognizedService     uint8 = 9
)

// BACnetError is the payload of a BACnet Error-PDU.
type BACnetError struct {
	Class ErrorClass
	Code  ErrorCode
}

func (e *BACnetError) Error() string {
	return fmt.Sprintf("bacnet: error (class=%d, code=%d)", e.Class, e.Code)
}

// RejectError is returned when a peer responds with a Reject-PDU.
type RejectError struct{ Reason uint8 }

func (e *RejectError) Error() string { return fmt.Sprintf("bacnet: reject (reason=%d)", e.Reason) }

// AbortError is returned when a peer responds with an Abort-PDU.
type AbortError struct{ Reason uint8 }

func (e *AbortError) Error() string { return fmt.Sprintf("bacnet: abort (reason=%d)", e.Reason) }

// ErrTimeout is wrapped into the error returned by Client methods when a
// device does not respond within the configured timeout/retries.
var ErrTimeout = fmt.Errorf("bacnet: request timed out")

// DecodeBACnetError decodes the payload of an Error-PDU.
func DecodeBACnetError(params []byte) (*BACnetError, error) {
	bacErr, _, err := decodeErrorSequence(params)
	return bacErr, err
}

// appendErrorSequence appends a BACnet Error (ASHRAE 135 clause 21:
// SEQUENCE { error-class ENUMERATED, error-code ENUMERATED }), which is
// encoded as two application-tagged Enumerated values.
func appendErrorSequence(buf []byte, e BACnetError) []byte {
	buf = AppendValue(buf, EnumeratedValue(uint32(e.Class)))
	return AppendValue(buf, EnumeratedValue(uint32(e.Code)))
}

// decodeErrorSequence decodes a BACnet Error at the start of buf, returning
// it and the number of bytes consumed. Besides the standard application
// tags it also accepts context tags 0 and 1, the encoding used by some
// services' error choices and by earlier versions of this package.
func decodeErrorSequence(buf []byte) (*BACnetError, int, error) {
	names := [2]string{"error-class", "error-code"}
	var vals [2]uint32
	pos := 0
	for i := range vals {
		th, err := decodeTagHeader(buf[pos:])
		ok := err == nil && !th.IsOpening() && !th.IsClosing() &&
			((!th.Context && th.Number == TagEnumerated) || (th.Context && th.Number == uint8(i)))
		start := pos + th.Header
		if !ok || start+int(th.LVT) > len(buf) {
			return nil, 0, fmt.Errorf("bacnet: malformed error: missing %s", names[i])
		}
		vals[i] = uint32(decodeUnsignedData(buf[start : start+int(th.LVT)]))
		pos = start + int(th.LVT)
	}
	return &BACnetError{Class: ErrorClass(vals[0]), Code: ErrorCode(vals[1])}, pos, nil
}
