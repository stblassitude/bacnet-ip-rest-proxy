package bacnet

import (
	"encoding/binary"
	"fmt"
	"math"
)

// ValueKind identifies which field of Value is populated.
type ValueKind int

const (
	KindNull ValueKind = iota
	KindBoolean
	KindUnsigned
	KindSigned
	KindReal
	KindDouble
	KindOctetString
	KindCharacterString
	KindBitString
	KindEnumerated
	KindDate
	KindTime
	KindObjectID
)

// Date is a BACnet Date value. A field value of -1 means "unspecified"
// (wire value 255), matching BACnet's wildcard-date semantics.
type Date struct {
	Year, Month, Day, DayOfWeek int
}

// Time is a BACnet Time value. A field value of -1 means "unspecified".
type Time struct {
	Hour, Minute, Second, Hundredth int
}

// BitString is a BACnet bit string value, one bool per bit, MSB first.
type BitString struct {
	Bits []bool
}

// ObjectIdentifier identifies a single BACnet object.
type ObjectIdentifier struct {
	Type     ObjectType
	Instance uint32
}

// Value is a decoded BACnet primitive value.
type Value struct {
	Kind     ValueKind
	Bool     bool
	Unsigned uint64
	Signed   int64
	Real     float32
	Double   float64
	Octets   []byte
	Str      string
	Bits     BitString
	Enum     uint32
	Date     Date
	Time     Time
	Object   ObjectIdentifier
}

func NullValue() Value               { return Value{Kind: KindNull} }
func BoolValue(v bool) Value         { return Value{Kind: KindBoolean, Bool: v} }
func UnsignedValue(v uint64) Value   { return Value{Kind: KindUnsigned, Unsigned: v} }
func SignedValue(v int64) Value      { return Value{Kind: KindSigned, Signed: v} }
func RealValue(v float32) Value      { return Value{Kind: KindReal, Real: v} }
func DoubleValue(v float64) Value    { return Value{Kind: KindDouble, Double: v} }
func CharStringValue(v string) Value { return Value{Kind: KindCharacterString, Str: v} }
func EnumeratedValue(v uint32) Value { return Value{Kind: KindEnumerated, Enum: v} }
func BitStringValue(b []bool) Value  { return Value{Kind: KindBitString, Bits: BitString{Bits: b}} }
func ObjectIDValue(t ObjectType, i uint32) Value {
	return Value{Kind: KindObjectID, Object: ObjectIdentifier{Type: t, Instance: i}}
}

// applicationTagFor returns the fixed application tag number for a Value's kind.
func applicationTagFor(k ValueKind) uint8 {
	switch k {
	case KindNull:
		return TagNull
	case KindBoolean:
		return TagBoolean
	case KindUnsigned:
		return TagUnsignedInt
	case KindSigned:
		return TagSignedInt
	case KindReal:
		return TagReal
	case KindDouble:
		return TagDouble
	case KindOctetString:
		return TagOctetString
	case KindCharacterString:
		return TagCharacterString
	case KindBitString:
		return TagBitString
	case KindEnumerated:
		return TagEnumerated
	case KindDate:
		return TagDate
	case KindTime:
		return TagTime
	case KindObjectID:
		return TagObjectID
	}
	panic("bacnet: unknown value kind")
}

// AppendValue appends v application-tagged (context=false) to buf. Used for
// values embedded directly in unconfirmed services such as I-Am.
func AppendValue(buf []byte, v Value) []byte {
	return AppendContextValue(buf, false, applicationTagFor(v.Kind), v)
}

// AppendContextValue appends v using tagNumber as either the application tag
// (context=false, tagNumber must be v's fixed application tag) or a
// context-specific tag number (context=true) that wraps v's data bytes.
func AppendContextValue(buf []byte, context bool, tagNumber uint8, v Value) []byte {
	switch v.Kind {
	case KindNull:
		return appendTagHeader(buf, tagNumber, context, 0)
	case KindBoolean:
		if !context {
			lvt := uint32(0)
			if v.Bool {
				lvt = 1
			}
			return appendTagHeader(buf, tagNumber, false, lvt)
		}
		data := byte(0)
		if v.Bool {
			data = 1
		}
		buf = appendTagHeader(buf, tagNumber, true, 1)
		return append(buf, data)
	case KindUnsigned:
		data := minUnsignedBytes(v.Unsigned)
		buf = appendTagHeader(buf, tagNumber, context, uint32(len(data)))
		return append(buf, data...)
	case KindSigned:
		data := minSignedBytes(v.Signed)
		buf = appendTagHeader(buf, tagNumber, context, uint32(len(data)))
		return append(buf, data...)
	case KindReal:
		var tmp [4]byte
		binary.BigEndian.PutUint32(tmp[:], math.Float32bits(v.Real))
		buf = appendTagHeader(buf, tagNumber, context, 4)
		return append(buf, tmp[:]...)
	case KindDouble:
		var tmp [8]byte
		binary.BigEndian.PutUint64(tmp[:], math.Float64bits(v.Double))
		buf = appendTagHeader(buf, tagNumber, context, 8)
		return append(buf, tmp[:]...)
	case KindOctetString:
		buf = appendTagHeader(buf, tagNumber, context, uint32(len(v.Octets)))
		return append(buf, v.Octets...)
	case KindCharacterString:
		data := append([]byte{0}, []byte(v.Str)...) // charset 0 = ANSI X3.4 / UTF-8
		buf = appendTagHeader(buf, tagNumber, context, uint32(len(data)))
		return append(buf, data...)
	case KindBitString:
		data := encodeBitStringData(v.Bits.Bits)
		buf = appendTagHeader(buf, tagNumber, context, uint32(len(data)))
		return append(buf, data...)
	case KindEnumerated:
		data := minUnsignedBytes(uint64(v.Enum))
		buf = appendTagHeader(buf, tagNumber, context, uint32(len(data)))
		return append(buf, data...)
	case KindDate:
		data := encodeDateData(v.Date)
		buf = appendTagHeader(buf, tagNumber, context, 4)
		return append(buf, data...)
	case KindTime:
		data := encodeTimeData(v.Time)
		buf = appendTagHeader(buf, tagNumber, context, 4)
		return append(buf, data...)
	case KindObjectID:
		var tmp [4]byte
		binary.BigEndian.PutUint32(tmp[:], (uint32(v.Object.Type)<<22)|(v.Object.Instance&0x3FFFFF))
		buf = appendTagHeader(buf, tagNumber, context, 4)
		return append(buf, tmp[:]...)
	}
	panic("bacnet: unknown value kind")
}

func encodeBitStringData(bits []bool) []byte {
	unused := (8 - len(bits)%8) % 8
	nBytes := (len(bits) + 7) / 8
	out := make([]byte, 1+nBytes)
	out[0] = byte(unused)
	for i, b := range bits {
		if b {
			out[1+i/8] |= 0x80 >> uint(i%8)
		}
	}
	return out
}

func decodeBitStringData(data []byte) (BitString, error) {
	if len(data) < 1 {
		return BitString{}, fmt.Errorf("bacnet: empty bit string")
	}
	unused := int(data[0])
	total := (len(data)-1)*8 - unused
	if total < 0 {
		return BitString{}, fmt.Errorf("bacnet: invalid bit string unused-bits count")
	}
	bits := make([]bool, total)
	for i := 0; i < total; i++ {
		byt := data[1+i/8]
		bits[i] = byt&(0x80>>uint(i%8)) != 0
	}
	return BitString{Bits: bits}, nil
}

func encodeDateData(d Date) []byte {
	enc := func(v, unspecified int) byte {
		if v < 0 {
			return byte(unspecified)
		}
		return byte(v)
	}
	return []byte{
		enc(d.Year-1900, 255),
		enc(d.Month, 255),
		enc(d.Day, 255),
		enc(d.DayOfWeek, 255),
	}
}

func decodeDateData(data []byte) (Date, error) {
	if len(data) != 4 {
		return Date{}, fmt.Errorf("bacnet: date must be 4 bytes, got %d", len(data))
	}
	dec := func(v byte) int {
		if v == 255 {
			return -1
		}
		return int(v)
	}
	year := -1
	if data[0] != 255 {
		year = int(data[0]) + 1900
	}
	return Date{Year: year, Month: dec(data[1]), Day: dec(data[2]), DayOfWeek: dec(data[3])}, nil
}

func encodeTimeData(t Time) []byte {
	enc := func(v int) byte {
		if v < 0 {
			return 255
		}
		return byte(v)
	}
	return []byte{enc(t.Hour), enc(t.Minute), enc(t.Second), enc(t.Hundredth)}
}

func decodeTimeData(data []byte) (Time, error) {
	if len(data) != 4 {
		return Time{}, fmt.Errorf("bacnet: time must be 4 bytes, got %d", len(data))
	}
	dec := func(v byte) int {
		if v == 255 {
			return -1
		}
		return int(v)
	}
	return Time{Hour: dec(data[0]), Minute: dec(data[1]), Second: dec(data[2]), Hundredth: dec(data[3])}, nil
}

func decodeObjectIDData(data []byte) (ObjectIdentifier, error) {
	if len(data) != 4 {
		return ObjectIdentifier{}, fmt.Errorf("bacnet: object identifier must be 4 bytes, got %d", len(data))
	}
	raw := binary.BigEndian.Uint32(data)
	return ObjectIdentifier{Type: ObjectType(raw >> 22), Instance: raw & 0x3FFFFF}, nil
}

// decodeApplicationValue decodes exactly one application-tagged primitive
// value starting at buf[0], returning the value and the number of bytes
// consumed (header + data).
func decodeApplicationValue(buf []byte) (Value, int, error) {
	th, err := decodeTagHeader(buf)
	if err != nil {
		return Value{}, 0, err
	}
	if th.Context {
		return Value{}, 0, fmt.Errorf("bacnet: expected application tag, got context tag %d", th.Number)
	}
	if th.Number == TagBoolean {
		return Value{Kind: KindBoolean, Bool: th.LVT != 0}, th.Header, nil
	}
	data := buf[th.Header:]
	if uint32(len(data)) < th.LVT {
		return Value{}, 0, fmt.Errorf("bacnet: truncated value data")
	}
	data = data[:th.LVT]
	consumed := th.Header + int(th.LVT)
	switch th.Number {
	case TagNull:
		return Value{Kind: KindNull}, consumed, nil
	case TagUnsignedInt:
		return Value{Kind: KindUnsigned, Unsigned: decodeUnsignedData(data)}, consumed, nil
	case TagSignedInt:
		return Value{Kind: KindSigned, Signed: decodeSignedData(data)}, consumed, nil
	case TagReal:
		if len(data) != 4 {
			return Value{}, 0, fmt.Errorf("bacnet: real must be 4 bytes, got %d", len(data))
		}
		return Value{Kind: KindReal, Real: math.Float32frombits(binary.BigEndian.Uint32(data))}, consumed, nil
	case TagDouble:
		if len(data) != 8 {
			return Value{}, 0, fmt.Errorf("bacnet: double must be 8 bytes, got %d", len(data))
		}
		return Value{Kind: KindDouble, Double: math.Float64frombits(binary.BigEndian.Uint64(data))}, consumed, nil
	case TagOctetString:
		octets := make([]byte, len(data))
		copy(octets, data)
		return Value{Kind: KindOctetString, Octets: octets}, consumed, nil
	case TagCharacterString:
		if len(data) < 1 {
			return Value{}, 0, fmt.Errorf("bacnet: empty character string")
		}
		return Value{Kind: KindCharacterString, Str: string(data[1:])}, consumed, nil
	case TagBitString:
		bs, err := decodeBitStringData(data)
		if err != nil {
			return Value{}, 0, err
		}
		return Value{Kind: KindBitString, Bits: bs}, consumed, nil
	case TagEnumerated:
		return Value{Kind: KindEnumerated, Enum: uint32(decodeUnsignedData(data))}, consumed, nil
	case TagDate:
		d, err := decodeDateData(data)
		if err != nil {
			return Value{}, 0, err
		}
		return Value{Kind: KindDate, Date: d}, consumed, nil
	case TagTime:
		t, err := decodeTimeData(data)
		if err != nil {
			return Value{}, 0, err
		}
		return Value{Kind: KindTime, Time: t}, consumed, nil
	case TagObjectID:
		oid, err := decodeObjectIDData(data)
		if err != nil {
			return Value{}, 0, err
		}
		return Value{Kind: KindObjectID, Object: oid}, consumed, nil
	default:
		return Value{}, 0, fmt.Errorf("bacnet: unsupported application tag %d", th.Number)
	}
}

// decodeApplicationValues decodes a run of application-tagged values from
// buf until it is exhausted or a context closing tag is encountered
// (whichever the caller checks for). Used for array/list properties.
func decodeApplicationValues(buf []byte) ([]Value, int, error) {
	var values []Value
	pos := 0
	for pos < len(buf) {
		th, err := decodeTagHeader(buf[pos:])
		if err != nil {
			return nil, 0, err
		}
		if th.Context {
			break
		}
		v, n, err := decodeApplicationValue(buf[pos:])
		if err != nil {
			return nil, 0, err
		}
		values = append(values, v)
		pos += n
	}
	return values, pos, nil
}

func decodeUnsignedData(data []byte) uint64 {
	var v uint64
	for _, b := range data {
		v = v<<8 | uint64(b)
	}
	return v
}

func decodeSignedData(data []byte) int64 {
	if len(data) == 0 {
		return 0
	}
	v := int64(int8(data[0]))
	for _, b := range data[1:] {
		v = v<<8 | int64(b)
	}
	return v
}
