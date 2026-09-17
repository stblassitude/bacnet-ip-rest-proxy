// Package bacnet implements the minimal subset of the BACnet/IP wire protocol
// (ASHRAE 135) needed by this proxy: Who-Is/I-Am, ReadProperty,
// ReadPropertyMultiple and WriteProperty, unsegmented only.
package bacnet

import (
	"encoding/binary"
	"fmt"
)

// Application tag numbers (ASHRAE 135 clause 20.2.1).
const (
	TagNull            uint8 = 0
	TagBoolean         uint8 = 1
	TagUnsignedInt     uint8 = 2
	TagSignedInt       uint8 = 3
	TagReal            uint8 = 4
	TagDouble          uint8 = 5
	TagOctetString     uint8 = 6
	TagCharacterString uint8 = 7
	TagBitString       uint8 = 8
	TagEnumerated      uint8 = 9
	TagDate            uint8 = 10
	TagTime            uint8 = 11
	TagObjectID        uint8 = 12
)

// openingLVT / closingLVT are the reserved LVT values (context-tagged only)
// that mark the start/end of a constructed (sequence-valued) context tag.
const (
	openingLVT uint32 = 6
	closingLVT uint32 = 7
)

// appendTagHeader appends a BACnet tag header for a value of the given
// (extended) length. context selects application (false) vs context (true)
// tag class.
func appendTagHeader(buf []byte, tagNumber uint8, context bool, length uint32) []byte {
	var first byte
	if context {
		first |= 0x08
	}
	if tagNumber < 15 {
		first |= tagNumber << 4
	} else {
		first |= 0xF0
	}
	if length <= 4 {
		first |= byte(length)
		buf = append(buf, first)
	} else {
		first |= 0x05
		buf = append(buf, first)
	}
	if tagNumber >= 15 {
		buf = append(buf, tagNumber)
	}
	if length > 4 {
		switch {
		case length <= 253:
			buf = append(buf, byte(length))
		case length <= 65535:
			buf = append(buf, 254)
			var tmp [2]byte
			binary.BigEndian.PutUint16(tmp[:], uint16(length))
			buf = append(buf, tmp[:]...)
		default:
			buf = append(buf, 255)
			var tmp [4]byte
			binary.BigEndian.PutUint32(tmp[:], length)
			buf = append(buf, tmp[:]...)
		}
	}
	return buf
}

// appendOpeningTag / appendClosingTag bracket constructed context-tagged data.
func appendOpeningTag(buf []byte, tagNumber uint8) []byte {
	return append(buf, byte(tagNumber<<4)|0x08|byte(openingLVT))
}

func appendClosingTag(buf []byte, tagNumber uint8) []byte {
	return append(buf, byte(tagNumber<<4)|0x08|byte(closingLVT))
}

// tagInfo describes a decoded tag header.
type tagInfo struct {
	Number  uint8
	Context bool
	LVT     uint32 // length in bytes, or openingLVT/closingLVT for constructed markers
	Header  int    // number of octets the header itself occupied
}

func (t tagInfo) IsOpening() bool { return t.Context && t.LVT == openingLVT }
func (t tagInfo) IsClosing() bool { return t.Context && t.LVT == closingLVT }

// decodeTagHeader parses a tag header at the start of buf.
func decodeTagHeader(buf []byte) (tagInfo, error) {
	if len(buf) < 1 {
		return tagInfo{}, fmt.Errorf("bacnet: truncated tag header")
	}
	first := buf[0]
	t := tagInfo{
		Context: first&0x08 != 0,
		Number:  first >> 4,
	}
	pos := 1
	if t.Number == 0x0F {
		if len(buf) < 2 {
			return tagInfo{}, fmt.Errorf("bacnet: truncated extended tag number")
		}
		t.Number = buf[1]
		pos = 2
	}
	lvt := uint32(first & 0x07)
	switch lvt {
	case 6, 7:
		// opening/closing tag marker, only meaningful for context tags.
		t.LVT = lvt
	case 5:
		if len(buf) < pos+1 {
			return tagInfo{}, fmt.Errorf("bacnet: truncated extended length")
		}
		lenByte := buf[pos]
		pos++
		switch {
		case lenByte < 254:
			t.LVT = uint32(lenByte)
		case lenByte == 254:
			if len(buf) < pos+2 {
				return tagInfo{}, fmt.Errorf("bacnet: truncated 2-byte length")
			}
			t.LVT = uint32(binary.BigEndian.Uint16(buf[pos:]))
			pos += 2
		default: // 255
			if len(buf) < pos+4 {
				return tagInfo{}, fmt.Errorf("bacnet: truncated 4-byte length")
			}
			t.LVT = binary.BigEndian.Uint32(buf[pos:])
			pos += 4
		}
	default:
		t.LVT = lvt
	}
	t.Header = pos
	return t, nil
}

// minUnsignedBytes returns the minimal big-endian encoding of v (at least 1 byte).
func minUnsignedBytes(v uint64) []byte {
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], v)
	i := 0
	for i < 7 && tmp[i] == 0 {
		i++
	}
	return tmp[i:]
}

// minSignedBytes returns the minimal big-endian two's-complement encoding of v.
func minSignedBytes(v int64) []byte {
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], uint64(v))
	i := 0
	for i < 7 {
		b := tmp[i]
		next := tmp[i+1]
		// Stop shrinking once the sign bit of the next byte would flip.
		if (b == 0x00 && next&0x80 == 0) || (b == 0xFF && next&0x80 != 0) {
			i++
			continue
		}
		break
	}
	return tmp[i:]
}
