package api

import (
	"fmt"

	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/bacnet"
)

// jsonValue converts a decoded BACnet Value to its REST JSON representation.
// See README/API design: Real/Unsigned/Integer -> number, Boolean -> bool,
// Enumerated -> string (falling back to the raw number if unrecognized),
// CharacterString -> string, Date/Time -> string, BitString -> []bool,
// ObjectIdentifier -> {type, instance}.
func jsonValue(v bacnet.Value) any {
	switch v.Kind {
	case bacnet.KindNull:
		return nil
	case bacnet.KindBoolean:
		return v.Bool
	case bacnet.KindUnsigned:
		return v.Unsigned
	case bacnet.KindSigned:
		return v.Signed
	case bacnet.KindReal:
		return v.Real
	case bacnet.KindDouble:
		return v.Double
	case bacnet.KindOctetString:
		return v.Octets
	case bacnet.KindCharacterString:
		return v.Str
	case bacnet.KindBitString:
		return v.Bits.Bits
	case bacnet.KindEnumerated:
		return v.Enum
	case bacnet.KindDate:
		return fmt.Sprintf("%04d-%02d-%02d", v.Date.Year, v.Date.Month, v.Date.Day)
	case bacnet.KindTime:
		return fmt.Sprintf("%02d:%02d:%02d.%02d", v.Time.Hour, v.Time.Minute, v.Time.Second, v.Time.Hundredth)
	case bacnet.KindObjectID:
		return map[string]any{"type": v.Object.Type.String(), "instance": v.Object.Instance}
	default:
		return nil
	}
}

// jsonValues renders a slice of Values as a bare JSON value when there is
// exactly one (the common case for atomic properties), or a JSON array
// otherwise (for array/list properties such as object-list, priority-array).
func jsonValues(values []bacnet.Value) any {
	if len(values) == 1 {
		return jsonValue(values[0])
	}
	out := make([]any, len(values))
	for i, v := range values {
		out[i] = jsonValue(v)
	}
	return out
}

// propertyValue is the response body of GET .../{property}.
type propertyValue struct {
	Value any `json:"value"`
}

// writeRequest is the request body of PUT .../{property}.
type writeRequest struct {
	// Value is a JSON number, string, or bool matching the property's
	// BACnet type; null relinquishes the given priority on a commandable
	// property.
	Value    any    `json:"value"`
	Priority *uint8 `json:"priority,omitempty"`
}

// objectSummary is one entry of GET /devices/{id}/objects.
type objectSummary struct {
	Type     string `json:"type"`
	Instance uint32 `json:"instance"`
}

// deviceSummary is one entry of GET /devices.
type deviceSummary struct {
	ID      string `json:"id"`
	Address string `json:"address"`
}

// errorBody is the JSON error envelope returned for any non-2xx response.
type errorBody struct {
	Error            string `json:"error"`
	BACnetErrorClass string `json:"bacnetErrorClass,omitempty"`
	BACnetErrorCode  string `json:"bacnetErrorCode,omitempty"`
}

// valueForWrite converts a JSON write request value into a bacnet.Value
// appropriate for objType/prop. A nil raw value relinquishes the property
// (BACnet Null). present-value's BACnet type depends on the object type:
// Real for analog objects, Enumerated (0/1) for binary objects, Unsigned
// (1-based state index) for multi-state objects. Any other property falls
// back to inferring the BACnet type directly from the JSON value's shape.
func valueForWrite(objType bacnet.ObjectType, prop bacnet.PropertyIdentifier, raw any) (bacnet.Value, error) {
	if raw == nil {
		return bacnet.NullValue(), nil
	}
	if prop == bacnet.PropPresentValue {
		switch objType {
		case bacnet.ObjectAnalogInput, bacnet.ObjectAnalogOutput, bacnet.ObjectAnalogValue:
			f, ok := raw.(float64)
			if !ok {
				return bacnet.Value{}, fmt.Errorf("present-value for an analog object must be a number")
			}
			return bacnet.RealValue(float32(f)), nil
		case bacnet.ObjectBinaryInput, bacnet.ObjectBinaryOutput, bacnet.ObjectBinaryValue:
			return binaryPresentValue(raw)
		case bacnet.ObjectMultiStateInput, bacnet.ObjectMultiStateOutput, bacnet.ObjectMultiStateValue:
			f, ok := raw.(float64)
			if !ok || f < 1 || f != float64(uint64(f)) {
				return bacnet.Value{}, fmt.Errorf("present-value for a multi-state object must be a positive integer state index")
			}
			return bacnet.UnsignedValue(uint64(f)), nil
		}
	}
	return valueFromJSONShape(raw)
}

func binaryPresentValue(raw any) (bacnet.Value, error) {
	switch v := raw.(type) {
	case bool:
		if v {
			return bacnet.EnumeratedValue(1), nil
		}
		return bacnet.EnumeratedValue(0), nil
	case float64:
		if v == 0 || v == 1 {
			return bacnet.EnumeratedValue(uint32(v)), nil
		}
	case string:
		switch v {
		case "active":
			return bacnet.EnumeratedValue(1), nil
		case "inactive":
			return bacnet.EnumeratedValue(0), nil
		}
	}
	return bacnet.Value{}, fmt.Errorf(`present-value for a binary object must be true/false, 0/1, or "active"/"inactive"`)
}

func valueFromJSONShape(raw any) (bacnet.Value, error) {
	switch v := raw.(type) {
	case bool:
		return bacnet.BoolValue(v), nil
	case float64:
		return bacnet.RealValue(float32(v)), nil
	case string:
		return bacnet.CharStringValue(v), nil
	default:
		return bacnet.Value{}, fmt.Errorf("unsupported value type %T", raw)
	}
}
