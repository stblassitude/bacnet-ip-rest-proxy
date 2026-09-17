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

func DecodeBACnetError(params []byte) (*BACnetError, error) {
	th, err := decodeTagHeader(params)
	if err != nil || !th.Context || th.Number != 0 {
		return nil, fmt.Errorf("bacnet: malformed error PDU: missing error-class")
	}
	classData := params[th.Header : th.Header+int(th.LVT)]
	pos := th.Header + int(th.LVT)

	th2, err := decodeTagHeader(params[pos:])
	if err != nil || !th2.Context || th2.Number != 1 {
		return nil, fmt.Errorf("bacnet: malformed error PDU: missing error-code")
	}
	codeStart := pos + th2.Header
	codeData := params[codeStart : codeStart+int(th2.LVT)]

	return &BACnetError{
		Class: ErrorClass(decodeUnsignedData(classData)),
		Code:  ErrorCode(decodeUnsignedData(codeData)),
	}, nil
}
