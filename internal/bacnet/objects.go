package bacnet

import "fmt"

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

var objectTypeNames = map[ObjectType]string{
	ObjectAnalogInput:      "analog-input",
	ObjectAnalogOutput:     "analog-output",
	ObjectAnalogValue:      "analog-value",
	ObjectBinaryInput:      "binary-input",
	ObjectBinaryOutput:     "binary-output",
	ObjectBinaryValue:      "binary-value",
	ObjectDevice:           "device",
	ObjectMultiStateInput:  "multi-state-input",
	ObjectMultiStateOutput: "multi-state-output",
	ObjectMultiStateValue:  "multi-state-value",
}

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
// to its BACnet enumeration value.
func ParseObjectType(name string) (ObjectType, error) {
	if t, ok := objectTypeByName[name]; ok {
		return t, nil
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
// "present-value") to its BACnet enumeration value.
func ParsePropertyIdentifier(name string) (PropertyIdentifier, error) {
	if p, ok := propertyByName[name]; ok {
		return p, nil
	}
	return 0, fmt.Errorf("bacnet: unknown property %q", name)
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
