package bacnet

import (
	"fmt"
	"strconv"
	"strings"
)

// ObjectType is a BACnet object type enumeration value (ASHRAE 135 clause 21).
type ObjectType uint32

const (
	ObjectAnalogInput  ObjectType = iota // 0
	ObjectAnalogOutput                   // 1
	ObjectAnalogValue                    // 2
	ObjectBinaryInput                    // 3
	ObjectBinaryOutput                   // 4
	ObjectBinaryValue                    // 5
)

const (
	ObjectDevice           ObjectType = 8
	ObjectMultiStateInput  ObjectType = 13
	ObjectMultiStateOutput ObjectType = 14
	ObjectMultiStateValue  ObjectType = 19
)

// DeviceInstanceWildcard addresses "whatever device object exists at the
// unicast destination", per ASHRAE 135 clause 16.10.
const DeviceInstanceWildcard uint32 = 4194303

// objectTypeNames covers every standard object type (BACnetObjectType,
// ASHRAE 135-2020 clause 21), so any object a device lists can be named.
var objectTypeNames = func() map[ObjectType]string {
	names := []string{
		"analog-input", "analog-output", "analog-value", "binary-input",
		"binary-output", "binary-value", "calendar", "command", "device",
		"event-enrollment", "file", "group", "loop", "multi-state-input",
		"multi-state-output", "notification-class", "program", "schedule",
		"averaging", "multi-state-value", "trend-log", "life-safety-point",
		"life-safety-zone", "accumulator", "pulse-converter", "event-log",
		"global-group", "trend-log-multiple", "load-control",
		"structured-view", "access-door", "timer", "access-credential",
		"access-point", "access-rights", "access-user", "access-zone",
		"credential-data-input", "network-security", "bitstring-value",
		"characterstring-value", "datepattern-value", "date-value",
		"datetimepattern-value", "datetime-value", "integer-value",
		"large-analog-value", "octetstring-value", "positive-integer-value",
		"timepattern-value", "time-value", "notification-forwarder",
		"alert-enrollment", "channel", "lighting-output",
		"binary-lighting-output", "network-port", "elevator-group",
		"escalator", "lift", "staging", "audit-log", "audit-reporter",
		"color", "color-temperature",
	}
	m := make(map[ObjectType]string, len(names))
	for i, name := range names {
		m[ObjectType(i)] = name
	}
	return m
}()

var objectTypeByName = func() map[string]ObjectType {
	m := make(map[string]ObjectType, len(objectTypeNames))
	for k, v := range objectTypeNames {
		m[v] = k
	}
	return m
}()

func (t ObjectType) String() string {
	if name, ok := objectTypeNames[t]; ok {
		return name
	}
	return fmt.Sprintf("object-type(%d)", uint32(t))
}

// ParseObjectType maps a REST-facing object type name (e.g. "analog-input")
// to its BACnet enumeration value. Proprietary or otherwise unnamed types
// are accepted as their number, bare or in the "object-type(N)" form
// String produces.
func ParseObjectType(name string) (ObjectType, error) {
	if t, ok := objectTypeByName[name]; ok {
		return t, nil
	}
	if n, ok := parseNumbered(name, "object-type", 1023); ok { // 10-bit field
		return ObjectType(n), nil
	}
	return 0, fmt.Errorf("bacnet: unknown object type %q", name)
}

// PropertyIdentifier is a BACnet property identifier enumeration value
// (ASHRAE 135 clause 21).
type PropertyIdentifier uint32

const (
	PropObjectID           PropertyIdentifier = 75
	PropObjectName         PropertyIdentifier = 77
	PropObjectType         PropertyIdentifier = 79
	PropPresentValue       PropertyIdentifier = 85
	PropDescription        PropertyIdentifier = 28
	PropStatusFlags        PropertyIdentifier = 111
	PropEventState         PropertyIdentifier = 36
	PropOutOfService       PropertyIdentifier = 81
	PropUnits              PropertyIdentifier = 117
	PropPriorityArray      PropertyIdentifier = 87
	PropRelinquishDefault  PropertyIdentifier = 104
	PropObjectList         PropertyIdentifier = 76
	PropVendorName         PropertyIdentifier = 121
	PropModelName          PropertyIdentifier = 70
	PropFirmwareRevision   PropertyIdentifier = 44
	PropApplicationVersion PropertyIdentifier = 12
	PropNumberOfStates     PropertyIdentifier = 74
)

var propertyNames = map[PropertyIdentifier]string{
	PropObjectID:           "object-identifier",
	PropObjectName:         "object-name",
	PropObjectType:         "object-type",
	PropPresentValue:       "present-value",
	PropDescription:        "description",
	PropStatusFlags:        "status-flags",
	PropEventState:         "event-state",
	PropOutOfService:       "out-of-service",
	PropUnits:              "units",
	PropPriorityArray:      "priority-array",
	PropRelinquishDefault:  "relinquish-default",
	PropObjectList:         "object-list",
	PropVendorName:         "vendor-name",
	PropModelName:          "model-name",
	PropFirmwareRevision:   "firmware-revision",
	PropApplicationVersion: "application-software-version",
	PropNumberOfStates:     "number-of-states",
}

var propertyByName = func() map[string]PropertyIdentifier {
	m := make(map[string]PropertyIdentifier, len(propertyNames))
	for k, v := range propertyNames {
		m[v] = k
	}
	return m
}()

func (p PropertyIdentifier) String() string {
	if name, ok := propertyNames[p]; ok {
		return name
	}
	return fmt.Sprintf("property(%d)", uint32(p))
}

// ParsePropertyIdentifier maps a REST-facing property name (e.g.
// "present-value") to its BACnet enumeration value. Properties without a
// name here are accepted as their number, bare or in the "property(N)"
// form String produces.
func ParsePropertyIdentifier(name string) (PropertyIdentifier, error) {
	if p, ok := propertyByName[name]; ok {
		return p, nil
	}
	if n, ok := parseNumbered(name, "property", 4194303); ok { // 22-bit enumeration
		return PropertyIdentifier(n), nil
	}
	return 0, fmt.Errorf("bacnet: unknown property %q", name)
}

// parseNumbered parses "N" or "prefix(N)" with 0 <= N <= limit.
func parseNumbered(s, prefix string, limit uint64) (uint32, bool) {
	if inner, ok := strings.CutPrefix(s, prefix+"("); ok {
		s, ok = strings.CutSuffix(inner, ")")
		if !ok {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil || n > limit {
		return 0, false
	}
	return uint32(n), true
}

// Commandable reports whether a property supports priority-array writes
// (and therefore relinquish via a null value at a given priority).
func Commandable(objType ObjectType, prop PropertyIdentifier) bool {
	if prop != PropPresentValue {
		return false
	}
	switch objType {
	case ObjectAnalogOutput, ObjectBinaryOutput, ObjectMultiStateOutput,
		ObjectAnalogValue, ObjectBinaryValue, ObjectMultiStateValue:
		return true
	default:
		return false
	}
}
