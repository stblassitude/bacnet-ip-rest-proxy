package bacnet

import (
	"bytes"
	"testing"
)

// Like errors_test.go, these use byte sequences written out from ASHRAE 135
// rather than produced by this package's encoders.

func TestConfirmedRequestSetsExpectingReply(t *testing.T) {
	got := EncodeUnicastPacket(EncodeConfirmedRequestAPDU(7, ServiceConfirmedReadProperty, []byte{0x0C, 0x00, 0x00, 0x00, 0x01, 0x19, 0x55}))
	want := []byte{
		0x81, 0x0A, 0x00, 0x11, // BVLC: Original-Unicast-NPDU, length 17
		0x01, 0x04, // NPDU: version 1, data-expecting-reply
		0x00, 0x05, 0x07, 0x0C, // Confirmed-Request, max APDU 1476, invoke 7, ReadProperty
		0x0C, 0x00, 0x00, 0x00, 0x01, 0x19, 0x55, // analog-input,1 present-value
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got  % X\nwant % X", got, want)
	}

	got = EncodeUnicastPacket(EncodeUnconfirmedRequestAPDU(ServiceUnconfirmedWhoIs, nil))
	want = []byte{0x81, 0x0A, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08}
	if !bytes.Equal(got, want) {
		t.Fatalf("who-is: got % X, want % X", got, want)
	}
}

// simpleACK is a SimpleACK for invoke ID 1, WriteProperty.
var simpleACK = []byte{0x20, 0x01, 0x0F}

func TestDecodeRoutedReply(t *testing.T) {
	cases := []struct {
		name string
		npdu []byte
	}{
		{"source only", []byte{0x01, 0x08, 0x00, 0x05, 0x01, 0x07}},
		// Destination, then source, then hop count (clause 6.2).
		{"destination and source", []byte{0x01, 0x28, 0x00, 0x03, 0x00, 0x00, 0x05, 0x02, 0x07, 0x08, 0xFE}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pkt := append([]byte{0x81, 0x0A, 0x00, byte(4 + len(c.npdu) + len(simpleACK))}, c.npdu...)
			pkt = append(pkt, simpleACK...)
			apdu, err := DecodeIncomingPacket(pkt)
			if err != nil {
				t.Fatal(err)
			}
			if apdu.Type != PDUSimpleACK || apdu.InvokeID != 1 || apdu.ServiceChoice != ServiceConfirmedWriteProperty {
				t.Fatalf("got %+v, want a SimpleACK for invoke 1, WriteProperty", apdu)
			}
		})
	}
}

func TestDecodeForwardedNPDU(t *testing.T) {
	pkt := []byte{
		0x81, 0x04, 0x00, 0x13, // BVLC: Forwarded-NPDU, length 19
		0x0A, 0x00, 0x00, 0x05, 0xBA, 0xC0, // original source 10.0.0.5:47808
		0x01, 0x00, // NPDU
		0x10, 0x00, // Unconfirmed-Request, I-Am
		0xC4, 0x02, 0x00, 0x03, 0xE9, // device,1001
	}
	apdu, err := DecodeIncomingPacket(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if apdu.Type != PDUUnconfirmedRequest || apdu.ServiceChoice != ServiceUnconfirmedIAm {
		t.Fatalf("got %+v, want an I-Am", apdu)
	}
}

func TestDecodeCharacterStringCharsets(t *testing.T) {
	cases := []struct {
		name string
		enc  []byte
		want string
	}{
		{"UTF-8", []byte{0x75, 0x07, 0x00, 'A', 'u', 0xC3, 0x9F, 'e', 'n'}, "Außen"},
		{"ISO 8859-1", []byte{0x75, 0x06, 0x05, 'A', 'u', 0xDF, 'e', 'n'}, "Außen"},
		{"UCS-2", []byte{0x75, 0x05, 0x04, 0x00, 'A', 0x00, 0xDF}, "Aß"},
		{"UCS-4", []byte{0x75, 0x05, 0x03, 0x00, 0x00, 0x00, 0xDF}, "ß"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, n, err := decodeApplicationValue(c.enc)
			if err != nil {
				t.Fatal(err)
			}
			if n != len(c.enc) || v.Kind != KindCharacterString || v.Str != c.want {
				t.Fatalf("got %q (%d bytes), want %q (%d bytes)", v.Str, n, c.want, len(c.enc))
			}
		})
	}
}

func TestObjectTypeAndPropertyNames(t *testing.T) {
	if got := ObjectType(17).String(); got != "schedule" {
		t.Errorf("type 17: got %q, want schedule", got)
	}
	if got := ObjectType(56).String(); got != "network-port" {
		t.Errorf("type 56: got %q, want network-port", got)
	}
	for in, want := range map[string]ObjectType{"trend-log": 20, "object-type(600)": 600, "600": 600} {
		got, err := ParseObjectType(in)
		if err != nil || got != want {
			t.Errorf("ParseObjectType(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	if _, err := ParseObjectType("object-type(1024)"); err == nil {
		t.Error("an object type beyond 10 bits must be rejected")
	}
	for in, want := range map[string]PropertyIdentifier{"present-value": 85, "property(1234)": 1234, "1234": 1234} {
		got, err := ParsePropertyIdentifier(in)
		if err != nil || got != want {
			t.Errorf("ParsePropertyIdentifier(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
}
