package bacnet

import (
	"reflect"
	"testing"
)

func roundTripApplication(t *testing.T, v Value) Value {
	t.Helper()
	buf := AppendValue(nil, v)
	got, n, err := decodeApplicationValue(buf)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if n != len(buf) {
		t.Fatalf("decode consumed %d bytes, want %d", n, len(buf))
	}
	return got
}

func TestValueRoundTrip(t *testing.T) {
	cases := []Value{
		NullValue(),
		BoolValue(true),
		BoolValue(false),
		UnsignedValue(0),
		UnsignedValue(255),
		UnsignedValue(4194303),
		UnsignedValue(1 << 40),
		SignedValue(0),
		SignedValue(-1),
		SignedValue(127),
		SignedValue(-128),
		SignedValue(-70000),
		RealValue(72.5),
		RealValue(-1),
		DoubleValue(1234.5678),
		CharStringValue("hello, bacnet"),
		CharStringValue(""),
		EnumeratedValue(9),
		BitStringValue([]bool{true, false, true, true, false}),
		ObjectIDValue(ObjectAnalogInput, 12345),
		{Kind: KindDate, Date: Date{Year: 2024, Month: 3, Day: 17, DayOfWeek: 7}},
		{Kind: KindDate, Date: Date{Year: -1, Month: -1, Day: -1, DayOfWeek: -1}},
		{Kind: KindTime, Time: Time{Hour: 13, Minute: 5, Second: 0, Hundredth: 0}},
		{Kind: KindTime, Time: Time{Hour: -1, Minute: -1, Second: -1, Hundredth: -1}},
		{Kind: KindOctetString, Octets: []byte{0xDE, 0xAD, 0xBE, 0xEF}},
	}
	for _, c := range cases {
		got := roundTripApplication(t, c)
		if !reflect.DeepEqual(got, c) {
			t.Errorf("round trip mismatch: got %+v, want %+v", got, c)
		}
	}
}

func TestValueRoundTripContextTagged(t *testing.T) {
	v := RealValue(21.5)
	buf := AppendContextValue(nil, true, 3, v)
	th, err := decodeTagHeader(buf)
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	if !th.Context || th.Number != 3 {
		t.Fatalf("got context=%v number=%d, want context tag 3", th.Context, th.Number)
	}
	data := buf[th.Header : th.Header+int(th.LVT)]

	// The data bytes for a context-tagged value are identical to an
	// application-tagged value of the same kind; reuse the application
	// decoder by prefixing the fixed application tag header for Real.
	fake := append([]byte{byte(TagReal<<4) | 4}, data...)
	got, _, err := decodeApplicationValue(fake)
	if err != nil {
		t.Fatalf("decode data: %v", err)
	}
	if got.Real != v.Real {
		t.Errorf("got %v, want %v", got.Real, v.Real)
	}
}

func TestBitStringUnusedBits(t *testing.T) {
	bits := []bool{true, false, true}
	data := encodeBitStringData(bits)
	if data[0] != 5 { // 8 - 3 = 5 unused bits
		t.Fatalf("unused bits = %d, want 5", data[0])
	}
	got, err := decodeBitStringData(data)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Bits, bits) {
		t.Fatalf("got %v, want %v", got.Bits, bits)
	}
}

func TestDecodeApplicationValuesArray(t *testing.T) {
	var buf []byte
	buf = AppendValue(buf, ObjectIDValue(ObjectAnalogInput, 1))
	buf = AppendValue(buf, ObjectIDValue(ObjectBinaryOutput, 2))
	buf = appendClosingTag(buf, 3) // sentinel the decoder should stop before

	values, n, err := decodeApplicationValues(buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 2 {
		t.Fatalf("got %d values, want 2", len(values))
	}
	if n != len(buf)-1 {
		t.Fatalf("consumed %d bytes, want %d (stopping before closing tag)", n, len(buf)-1)
	}
}
