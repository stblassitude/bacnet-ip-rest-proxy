package bacnet

import (
	"bytes"
	"testing"
)

// The byte sequences below are written out by hand from ASHRAE 135, not
// produced by this package's encoders, so encoder and decoder can't agree
// on a non-standard encoding unnoticed.

func TestEncodeErrorAPDUUsesApplicationTags(t *testing.T) {
	got := EncodeErrorAPDU(1, ServiceConfirmedReadProperty, BACnetError{Class: ErrorClassObject, Code: ErrorCodeUnknownObject})
	// Error-PDU, invoke ID 1, ReadProperty, then error-class and error-code
	// as application-tagged Enumerated (tag 9, length 1).
	want := []byte{0x50, 0x01, 0x0C, 0x91, 0x01, 0x91, 0x1F}
	if !bytes.Equal(got, want) {
		t.Fatalf("got % X, want % X", got, want)
	}
}

func TestDecodeBACnetErrorStandardEncoding(t *testing.T) {
	bacErr, err := DecodeBACnetError([]byte{0x91, 0x01, 0x91, 0x1F})
	if err != nil {
		t.Fatal(err)
	}
	if bacErr.Class != ErrorClassObject || bacErr.Code != ErrorCodeUnknownObject {
		t.Fatalf("got %+v, want class object, code unknown-object", bacErr)
	}
}

func TestDecodeReadPropertyMultipleACKWithPropertyError(t *testing.T) {
	ack := []byte{
		0x0C, 0x00, 0x00, 0x00, 0x01, // [0] analog-input,1
		0x1E,       // [1] opening: list of results
		0x29, 0x4D, // [2] object-name
		0x4E,                                 // [4] opening: property-value
		0x75, 0x05, 0x00, 'T', 'e', 's', 't', // CharacterString "Test" (UTF-8)
		0x4F,       // [4] closing
		0x29, 0x1C, // [2] description
		0x5E,       // [5] opening: property-access-error
		0x91, 0x02, // error-class property
		0x91, 0x20, // error-code unknown-property
		0x5F, // [5] closing
		0x1F, // [1] closing
	}
	results, err := DecodeReadPropertyMultipleACK(ack)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || len(results[0].Results) != 2 {
		t.Fatalf("got %+v, want one object with two property results", results)
	}
	name := results[0].Results[0]
	if name.Err != nil || len(name.Values) != 1 || name.Values[0].Str != "Test" {
		t.Errorf("object-name: got %+v, want \"Test\"", name)
	}
	desc := results[0].Results[1]
	if desc.Err == nil || desc.Err.Class != ErrorClassProperty || desc.Err.Code != ErrorCodeUnknownProperty {
		t.Errorf("description: got %+v, want a property/unknown-property error", desc)
	}
}
