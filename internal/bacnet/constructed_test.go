package bacnet

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

// eventTimeStampsACK is a ReadProperty-ACK for analog-input,1
// event-time-stamps: a BACnetARRAY[3] of BACnetTimeStamp, each a CHOICE of
// [0] time, [1] sequence-number or [2] date-time (ASHRAE 135 clause 21).
var eventTimeStampsACK = []byte{
	0x0C, 0x00, 0x00, 0x00, 0x01, // [0] analog-input,1
	0x19, 0x82, // [1] event-time-stamps (130)
	0x3E,                         // [3] opening: property value
	0x2E,                         // [2] opening: date-time
	0xA4, 0x7A, 0x09, 0x1B, 0xFF, // Date 2022-09-27, day of week unspecified
	0xB4, 0x0C, 0x1E, 0x00, 0x00, // Time 12:30:00.00
	0x2F,       // [2] closing
	0x19, 0x05, // [1] sequence-number 5
	0x0C, 0x0C, 0x1E, 0x00, 0x00, // [0] time 12:30:00.00
	0x3F, // [3] closing
}

func TestDecodeConstructedPropertyValue(t *testing.T) {
	ack, err := DecodeReadPropertyACK(eventTimeStampsACK)
	if err != nil {
		t.Fatal(err)
	}
	want := []Value{
		ConstructedValue(2,
			Value{Kind: KindDate, Date: Date{Year: 2022, Month: 9, Day: 27, DayOfWeek: -1}},
			Value{Kind: KindTime, Time: Time{Hour: 12, Minute: 30}},
		),
		ContextPrimitiveValue(1, []byte{0x05}),
		ContextPrimitiveValue(0, []byte{0x0C, 0x1E, 0x00, 0x00}),
	}
	if !reflect.DeepEqual(ack.Values, want) {
		t.Fatalf("got  %+v\nwant %+v", ack.Values, want)
	}

	// Encoding the decoded values reproduces the original bytes.
	got := EncodeReadPropertyACK(ack)
	if !bytes.Equal(got, eventTimeStampsACK) {
		t.Fatalf("re-encoded:\ngot  % X\nwant % X", got, eventTimeStampsACK)
	}
}

func TestDecodeConstructedInReadPropertyMultiple(t *testing.T) {
	// The same property value, inside a ReadPropertyMultiple-ACK.
	value := eventTimeStampsACK[8 : len(eventTimeStampsACK)-1]
	ack := append([]byte{0x0C, 0x00, 0x00, 0x00, 0x01, 0x1E, 0x29, 0x82, 0x4E}, value...)
	ack = append(ack, 0x4F, 0x1F)
	results, err := DecodeReadPropertyMultipleACK(ack)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(results[0].Results[0].Values); n != 3 {
		t.Fatalf("got %d values, want 3", n)
	}
}

func TestDecodeConstructedRejectsMalformed(t *testing.T) {
	cases := map[string]struct {
		buf  []byte
		want string
	}{
		"mismatched closing tag": {[]byte{0x2E, 0x91, 0x01, 0x1F}, "expected closing tag 2"},
		"unterminated":           {[]byte{0x2E, 0x91, 0x01}, "truncated tag header"},
		"truncated primitive":    {[]byte{0x0C, 0x0C, 0x1E}, "truncated context tag 0"},
		"nested too deeply":      {append(bytes.Repeat([]byte{0x0E}, maxNesting+1), bytes.Repeat([]byte{0x0F}, maxNesting+1)...), "nested deeper"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := decodeValues(c.buf)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error containing %q", err, c.want)
			}
		})
	}
}

func TestExtendedTagMarkers(t *testing.T) {
	got := AppendValue(nil, ConstructedValue(20, ContextPrimitiveValue(20, []byte{0x01})))
	want := []byte{0xFE, 0x14, 0xF9, 0x14, 0x01, 0xFF, 0x14}
	if !bytes.Equal(got, want) {
		t.Fatalf("got % X, want % X", got, want)
	}
	values, n, err := decodeValues(got)
	if err != nil || n != len(got) || len(values) != 1 || values[0].Tag != 20 || values[0].Items[0].Tag != 20 {
		t.Fatalf("round trip: got %+v, %d, %v", values, n, err)
	}
}
