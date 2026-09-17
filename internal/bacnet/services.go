package bacnet

import "fmt"

// --- generic context-tagged primitive decode helpers ---

// peekContextTag reports the context tag number at the start of buf, if any.
func peekContextTag(buf []byte) (uint8, tagInfo, bool) {
	if len(buf) == 0 {
		return 0, tagInfo{}, false
	}
	th, err := decodeTagHeader(buf)
	if err != nil || !th.Context {
		return 0, tagInfo{}, false
	}
	return th.Number, th, true
}

// decodeContextData reads a non-constructed context-tagged primitive whose
// tag number must equal want, returning its raw data bytes and total bytes
// consumed (header + data).
func decodeContextData(buf []byte, want uint8) ([]byte, int, error) {
	th, err := decodeTagHeader(buf)
	if err != nil {
		return nil, 0, err
	}
	if !th.Context || th.Number != want || th.IsOpening() || th.IsClosing() {
		return nil, 0, fmt.Errorf("bacnet: expected context tag %d, got context=%v number=%d", want, th.Context, th.Number)
	}
	if uint32(len(buf)-th.Header) < th.LVT {
		return nil, 0, fmt.Errorf("bacnet: truncated context tag %d value", want)
	}
	data := buf[th.Header : th.Header+int(th.LVT)]
	return data, th.Header + int(th.LVT), nil
}

func decodeContextUnsigned(buf []byte, want uint8) (uint64, int, error) {
	data, n, err := decodeContextData(buf, want)
	if err != nil {
		return 0, 0, err
	}
	return decodeUnsignedData(data), n, nil
}

func decodeContextEnumerated(buf []byte, want uint8) (uint32, int, error) {
	v, n, err := decodeContextUnsigned(buf, want)
	return uint32(v), n, err
}

func decodeContextObjectID(buf []byte, want uint8) (ObjectIdentifier, int, error) {
	data, n, err := decodeContextData(buf, want)
	if err != nil {
		return ObjectIdentifier{}, 0, err
	}
	oid, err := decodeObjectIDData(data)
	return oid, n, err
}

func expectOpening(buf []byte, want uint8) (int, error) {
	th, err := decodeTagHeader(buf)
	if err != nil {
		return 0, err
	}
	if !th.IsOpening() || th.Number != want {
		return 0, fmt.Errorf("bacnet: expected opening tag %d", want)
	}
	return th.Header, nil
}

func expectClosing(buf []byte, want uint8) (int, error) {
	th, err := decodeTagHeader(buf)
	if err != nil {
		return 0, err
	}
	if !th.IsClosing() || th.Number != want {
		return 0, fmt.Errorf("bacnet: expected closing tag %d", want)
	}
	return th.Header, nil
}

// --- ReadProperty ---

type ReadPropertyRequest struct {
	Object     ObjectIdentifier
	Property   PropertyIdentifier
	ArrayIndex *uint32
}

func EncodeReadPropertyRequest(r ReadPropertyRequest) []byte {
	var buf []byte
	buf = AppendContextValue(buf, true, 0, ObjectIDValue(r.Object.Type, r.Object.Instance))
	buf = AppendContextValue(buf, true, 1, EnumeratedValue(uint32(r.Property)))
	if r.ArrayIndex != nil {
		buf = AppendContextValue(buf, true, 2, UnsignedValue(uint64(*r.ArrayIndex)))
	}
	return buf
}

func DecodeReadPropertyRequest(buf []byte) (ReadPropertyRequest, error) {
	var r ReadPropertyRequest
	pos := 0
	oid, n, err := decodeContextObjectID(buf[pos:], 0)
	if err != nil {
		return r, err
	}
	r.Object = oid
	pos += n

	prop, n, err := decodeContextEnumerated(buf[pos:], 1)
	if err != nil {
		return r, err
	}
	r.Property = PropertyIdentifier(prop)
	pos += n

	if tag, _, ok := peekContextTag(buf[pos:]); ok && tag == 2 {
		idx, n, err := decodeContextUnsigned(buf[pos:], 2)
		if err != nil {
			return r, err
		}
		v := uint32(idx)
		r.ArrayIndex = &v
		pos += n
	}
	return r, nil
}

type ReadPropertyACK struct {
	Object     ObjectIdentifier
	Property   PropertyIdentifier
	ArrayIndex *uint32
	Values     []Value
}

func EncodeReadPropertyACK(a ReadPropertyACK) []byte {
	var buf []byte
	buf = AppendContextValue(buf, true, 0, ObjectIDValue(a.Object.Type, a.Object.Instance))
	buf = AppendContextValue(buf, true, 1, EnumeratedValue(uint32(a.Property)))
	if a.ArrayIndex != nil {
		buf = AppendContextValue(buf, true, 2, UnsignedValue(uint64(*a.ArrayIndex)))
	}
	buf = appendOpeningTag(buf, 3)
	for _, v := range a.Values {
		buf = AppendValue(buf, v)
	}
	buf = appendClosingTag(buf, 3)
	return buf
}

func DecodeReadPropertyACK(buf []byte) (ReadPropertyACK, error) {
	var a ReadPropertyACK
	pos := 0
	oid, n, err := decodeContextObjectID(buf[pos:], 0)
	if err != nil {
		return a, err
	}
	a.Object = oid
	pos += n

	prop, n, err := decodeContextEnumerated(buf[pos:], 1)
	if err != nil {
		return a, err
	}
	a.Property = PropertyIdentifier(prop)
	pos += n

	if tag, _, ok := peekContextTag(buf[pos:]); ok && tag == 2 {
		idx, n, err := decodeContextUnsigned(buf[pos:], 2)
		if err != nil {
			return a, err
		}
		v := uint32(idx)
		a.ArrayIndex = &v
		pos += n
	}

	n, err = expectOpening(buf[pos:], 3)
	if err != nil {
		return a, err
	}
	pos += n

	values, n, err := decodeApplicationValues(buf[pos:])
	if err != nil {
		return a, err
	}
	a.Values = values
	pos += n

	if _, err := expectClosing(buf[pos:], 3); err != nil {
		return a, err
	}
	return a, nil
}

// --- WriteProperty ---

type WritePropertyRequest struct {
	Object     ObjectIdentifier
	Property   PropertyIdentifier
	ArrayIndex *uint32
	Value      Value
	Priority   *uint8
}

func EncodeWritePropertyRequest(w WritePropertyRequest) []byte {
	var buf []byte
	buf = AppendContextValue(buf, true, 0, ObjectIDValue(w.Object.Type, w.Object.Instance))
	buf = AppendContextValue(buf, true, 1, EnumeratedValue(uint32(w.Property)))
	if w.ArrayIndex != nil {
		buf = AppendContextValue(buf, true, 2, UnsignedValue(uint64(*w.ArrayIndex)))
	}
	buf = appendOpeningTag(buf, 3)
	buf = AppendValue(buf, w.Value)
	buf = appendClosingTag(buf, 3)
	if w.Priority != nil {
		buf = AppendContextValue(buf, true, 4, UnsignedValue(uint64(*w.Priority)))
	}
	return buf
}

func DecodeWritePropertyRequest(buf []byte) (WritePropertyRequest, error) {
	var w WritePropertyRequest
	pos := 0
	oid, n, err := decodeContextObjectID(buf[pos:], 0)
	if err != nil {
		return w, err
	}
	w.Object = oid
	pos += n

	prop, n, err := decodeContextEnumerated(buf[pos:], 1)
	if err != nil {
		return w, err
	}
	w.Property = PropertyIdentifier(prop)
	pos += n

	if tag, _, ok := peekContextTag(buf[pos:]); ok && tag == 2 {
		idx, n, err := decodeContextUnsigned(buf[pos:], 2)
		if err != nil {
			return w, err
		}
		v := uint32(idx)
		w.ArrayIndex = &v
		pos += n
	}

	n, err = expectOpening(buf[pos:], 3)
	if err != nil {
		return w, err
	}
	pos += n

	val, n, err := decodeApplicationValue(buf[pos:])
	if err != nil {
		return w, err
	}
	w.Value = val
	pos += n

	n, err = expectClosing(buf[pos:], 3)
	if err != nil {
		return w, err
	}
	pos += n

	if pos < len(buf) {
		if tag, _, ok := peekContextTag(buf[pos:]); ok && tag == 4 {
			pr, n, err := decodeContextUnsigned(buf[pos:], 4)
			if err != nil {
				return w, err
			}
			p := uint8(pr)
			w.Priority = &p
			pos += n
		}
	}
	return w, nil
}

// --- ReadPropertyMultiple ---

type PropertyReference struct {
	Property   PropertyIdentifier
	ArrayIndex *uint32
}

type ReadAccessSpec struct {
	Object     ObjectIdentifier
	Properties []PropertyReference
}

func EncodeReadPropertyMultipleRequest(specs []ReadAccessSpec) []byte {
	var buf []byte
	for _, s := range specs {
		buf = AppendContextValue(buf, true, 0, ObjectIDValue(s.Object.Type, s.Object.Instance))
		buf = appendOpeningTag(buf, 1)
		for _, p := range s.Properties {
			buf = AppendContextValue(buf, true, 0, EnumeratedValue(uint32(p.Property)))
			if p.ArrayIndex != nil {
				buf = AppendContextValue(buf, true, 1, UnsignedValue(uint64(*p.ArrayIndex)))
			}
		}
		buf = appendClosingTag(buf, 1)
	}
	return buf
}

func DecodeReadPropertyMultipleRequest(buf []byte) ([]ReadAccessSpec, error) {
	var specs []ReadAccessSpec
	pos := 0
	for pos < len(buf) {
		var s ReadAccessSpec
		oid, n, err := decodeContextObjectID(buf[pos:], 0)
		if err != nil {
			return nil, err
		}
		s.Object = oid
		pos += n

		n, err = expectOpening(buf[pos:], 1)
		if err != nil {
			return nil, err
		}
		pos += n

		for {
			if _, th, ok := peekContextTag(buf[pos:]); ok && th.IsClosing() && th.Number == 1 {
				break
			}
			prop, n, err := decodeContextEnumerated(buf[pos:], 0)
			if err != nil {
				return nil, err
			}
			ref := PropertyReference{Property: PropertyIdentifier(prop)}
			pos += n
			if tag, th, ok := peekContextTag(buf[pos:]); ok && tag == 1 && !th.IsOpening() && !th.IsClosing() {
				idx, n, err := decodeContextUnsigned(buf[pos:], 1)
				if err != nil {
					return nil, err
				}
				v := uint32(idx)
				ref.ArrayIndex = &v
				pos += n
			}
			s.Properties = append(s.Properties, ref)
		}

		n, err = expectClosing(buf[pos:], 1)
		if err != nil {
			return nil, err
		}
		pos += n

		specs = append(specs, s)
	}
	return specs, nil
}

type PropertyResult struct {
	Property   PropertyIdentifier
	ArrayIndex *uint32
	Values     []Value
	Err        *BACnetError
}

type ReadAccessResult struct {
	Object  ObjectIdentifier
	Results []PropertyResult
}

func EncodeReadPropertyMultipleACK(results []ReadAccessResult) []byte {
	var buf []byte
	for _, r := range results {
		buf = AppendContextValue(buf, true, 0, ObjectIDValue(r.Object.Type, r.Object.Instance))
		buf = appendOpeningTag(buf, 1)
		for _, pr := range r.Results {
			buf = AppendContextValue(buf, true, 2, EnumeratedValue(uint32(pr.Property)))
			if pr.ArrayIndex != nil {
				buf = AppendContextValue(buf, true, 3, UnsignedValue(uint64(*pr.ArrayIndex)))
			}
			if pr.Err != nil {
				buf = appendOpeningTag(buf, 5)
				buf = AppendContextValue(buf, true, 0, EnumeratedValue(uint32(pr.Err.Class)))
				buf = AppendContextValue(buf, true, 1, EnumeratedValue(uint32(pr.Err.Code)))
				buf = appendClosingTag(buf, 5)
			} else {
				buf = appendOpeningTag(buf, 4)
				for _, v := range pr.Values {
					buf = AppendValue(buf, v)
				}
				buf = appendClosingTag(buf, 4)
			}
		}
		buf = appendClosingTag(buf, 1)
	}
	return buf
}

func DecodeReadPropertyMultipleACK(buf []byte) ([]ReadAccessResult, error) {
	var results []ReadAccessResult
	pos := 0
	for pos < len(buf) {
		var r ReadAccessResult
		oid, n, err := decodeContextObjectID(buf[pos:], 0)
		if err != nil {
			return nil, err
		}
		r.Object = oid
		pos += n

		n, err = expectOpening(buf[pos:], 1)
		if err != nil {
			return nil, err
		}
		pos += n

		for {
			if _, th, ok := peekContextTag(buf[pos:]); ok && th.IsClosing() && th.Number == 1 {
				break
			}
			var pr PropertyResult
			prop, n, err := decodeContextEnumerated(buf[pos:], 2)
			if err != nil {
				return nil, err
			}
			pr.Property = PropertyIdentifier(prop)
			pos += n

			if tag, th, ok := peekContextTag(buf[pos:]); ok && tag == 3 && !th.IsOpening() && !th.IsClosing() {
				idx, n, err := decodeContextUnsigned(buf[pos:], 3)
				if err != nil {
					return nil, err
				}
				v := uint32(idx)
				pr.ArrayIndex = &v
				pos += n
			}

			tag, th, ok := peekContextTag(buf[pos:])
			if !ok || !th.IsOpening() {
				return nil, fmt.Errorf("bacnet: expected opening tag 4 or 5, got context=%v number=%d", ok, tag)
			}
			switch tag {
			case 4:
				pos += th.Header
				values, n, err := decodeApplicationValues(buf[pos:])
				if err != nil {
					return nil, err
				}
				pr.Values = values
				pos += n
				if _, err := expectClosing(buf[pos:], 4); err != nil {
					return nil, err
				}
				pos += 1
			case 5:
				pos += th.Header
				class, n, err := decodeContextEnumerated(buf[pos:], 0)
				if err != nil {
					return nil, err
				}
				pos += n
				code, n, err := decodeContextEnumerated(buf[pos:], 1)
				if err != nil {
					return nil, err
				}
				pos += n
				pr.Err = &BACnetError{Class: ErrorClass(class), Code: ErrorCode(code)}
				if _, err := expectClosing(buf[pos:], 5); err != nil {
					return nil, err
				}
				pos += 1
			default:
				return nil, fmt.Errorf("bacnet: unexpected tag %d in ReadAccessResult", tag)
			}
			r.Results = append(r.Results, pr)
		}

		n, err = expectClosing(buf[pos:], 1)
		if err != nil {
			return nil, err
		}
		pos += n

		results = append(results, r)
	}
	return results, nil
}

// --- Who-Is / I-Am ---

type WhoIsRequest struct {
	LowLimit  *uint32
	HighLimit *uint32
}

func EncodeWhoIsRequest(r WhoIsRequest) []byte {
	if r.LowLimit == nil || r.HighLimit == nil {
		return nil
	}
	var buf []byte
	buf = AppendContextValue(buf, true, 0, UnsignedValue(uint64(*r.LowLimit)))
	buf = AppendContextValue(buf, true, 1, UnsignedValue(uint64(*r.HighLimit)))
	return buf
}

func DecodeWhoIsRequest(buf []byte) (WhoIsRequest, error) {
	var r WhoIsRequest
	if len(buf) == 0 {
		return r, nil
	}
	low, n, err := decodeContextUnsigned(buf, 0)
	if err != nil {
		return r, err
	}
	l := uint32(low)
	r.LowLimit = &l
	high, _, err := decodeContextUnsigned(buf[n:], 1)
	if err != nil {
		return r, err
	}
	h := uint32(high)
	r.HighLimit = &h
	return r, nil
}

type IAm struct {
	Device                ObjectIdentifier
	MaxAPDULength         uint32
	SegmentationSupported uint32
	VendorID              uint32
}

func EncodeIAm(v IAm) []byte {
	var buf []byte
	buf = AppendValue(buf, ObjectIDValue(v.Device.Type, v.Device.Instance))
	buf = AppendValue(buf, UnsignedValue(uint64(v.MaxAPDULength)))
	buf = AppendValue(buf, EnumeratedValue(v.SegmentationSupported))
	buf = AppendValue(buf, UnsignedValue(uint64(v.VendorID)))
	return buf
}

func DecodeIAm(buf []byte) (IAm, error) {
	var v IAm
	values, _, err := decodeApplicationValues(buf)
	if err != nil {
		return v, err
	}
	if len(values) != 4 {
		return v, fmt.Errorf("bacnet: I-Am must carry 4 values, got %d", len(values))
	}
	if values[0].Kind != KindObjectID {
		return v, fmt.Errorf("bacnet: I-Am device identifier has wrong tag")
	}
	v.Device = values[0].Object
	v.MaxAPDULength = uint32(values[1].Unsigned)
	v.SegmentationSupported = values[2].Enum
	v.VendorID = uint32(values[3].Unsigned)
	return v, nil
}
