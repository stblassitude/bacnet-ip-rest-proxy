package bacnet

import "testing"

func TestTagHeaderExtendedLengths(t *testing.T) {
	cases := []struct {
		name   string
		length uint32
	}{
		{"inline", 4},
		{"short-extended", 200},
		{"two-byte", 60000},
		{"four-byte", 100000},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			buf := appendTagHeader(nil, TagOctetString, false, c.length)
			th, err := decodeTagHeader(buf)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if th.LVT != c.length {
				t.Fatalf("got length %d, want %d", th.LVT, c.length)
			}
			if th.Number != TagOctetString {
				t.Fatalf("got tag number %d, want %d", th.Number, TagOctetString)
			}
		})
	}
}

func TestTagHeaderExtendedTagNumber(t *testing.T) {
	buf := appendTagHeader(nil, 20, true, 0)
	th, err := decodeTagHeader(buf)
	if err != nil {
		t.Fatal(err)
	}
	if th.Number != 20 || !th.Context {
		t.Fatalf("got number=%d context=%v, want 20/true", th.Number, th.Context)
	}
}

func TestOpeningClosingTags(t *testing.T) {
	buf := appendOpeningTag(nil, 3)
	th, err := decodeTagHeader(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !th.IsOpening() || th.Number != 3 {
		t.Fatalf("got opening=%v number=%d, want opening tag 3", th.IsOpening(), th.Number)
	}

	buf = appendClosingTag(nil, 3)
	th, err = decodeTagHeader(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !th.IsClosing() || th.Number != 3 {
		t.Fatalf("got closing=%v number=%d, want closing tag 3", th.IsClosing(), th.Number)
	}
}

func TestDecodeTagHeaderTruncated(t *testing.T) {
	cases := [][]byte{
		{},
		{0xF0},            // extended tag number, missing 2nd byte
		{0x05},            // extended length flag, missing length byte
		{0x05, 254},       // 2-byte length, missing bytes
		{0x05, 255, 0, 0}, // 4-byte length, missing bytes
	}
	for i, buf := range cases {
		if _, err := decodeTagHeader(buf); err == nil {
			t.Errorf("case %d: expected error for %v, got nil", i, buf)
		}
	}
}

func TestMinUnsignedSignedBytes(t *testing.T) {
	if got := minUnsignedBytes(0); len(got) != 1 || got[0] != 0 {
		t.Fatalf("minUnsignedBytes(0) = %v", got)
	}
	if got := minUnsignedBytes(256); len(got) != 2 {
		t.Fatalf("minUnsignedBytes(256) length = %d, want 2", len(got))
	}
	if got := minSignedBytes(0); len(got) != 1 || got[0] != 0 {
		t.Fatalf("minSignedBytes(0) = %v", got)
	}
	if got := minSignedBytes(-1); len(got) != 1 || got[0] != 0xFF {
		t.Fatalf("minSignedBytes(-1) = %v", got)
	}
	if got := minSignedBytes(127); len(got) != 1 {
		t.Fatalf("minSignedBytes(127) length = %d, want 1", len(got))
	}
	if got := minSignedBytes(128); len(got) != 2 {
		t.Fatalf("minSignedBytes(128) length = %d, want 2 (sign bit would collide)", len(got))
	}
	if got := minSignedBytes(-129); len(got) != 2 {
		t.Fatalf("minSignedBytes(-129) length = %d, want 2", len(got))
	}
}
