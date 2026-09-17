// Package bacnetmock provides an in-memory BACnet/IP device that speaks the
// real wire protocol (via internal/bacnet's encoder/decoder), for use as a
// test fixture in place of physical hardware.
package bacnetmock

import (
	"sort"
	"sync"

	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/bacnet"
)

// objectKey identifies one object in a Device's store.
type objectKey struct {
	Type     bacnet.ObjectType
	Instance uint32
}

// property holds a single property's value, or, for commandable
// present-value properties, its BACnet priority array.
type property struct {
	value       bacnet.Value      // non-commandable value, or the relinquish-default
	priorities  [16]*bacnet.Value // 1-indexed as [0..15] == priority 1..16
	commandable bool
}

func effectiveValue(p *property) bacnet.Value {
	if p.commandable {
		for _, v := range p.priorities {
			if v != nil {
				return *v
			}
		}
	}
	return p.value
}

// Device is an in-memory BACnet object/property store plus the device's own
// identity (instance number, vendor info).
type Device struct {
	mu         sync.RWMutex
	instance   uint32
	vendorID   uint32
	vendorName string
	modelName  string
	objects    map[objectKey]map[bacnet.PropertyIdentifier]*property
}

// NewDevice creates an empty mock device with the given BACnet device
// instance number, and seeds its own Device object.
func NewDevice(instance uint32) *Device {
	d := &Device{
		instance:   instance,
		vendorID:   999,
		vendorName: "bacnet-ip-rest-proxy mock",
		modelName:  "mock-device",
		objects:    make(map[objectKey]map[bacnet.PropertyIdentifier]*property),
	}
	d.objects[objectKey{bacnet.ObjectDevice, instance}] = map[bacnet.PropertyIdentifier]*property{
		bacnet.PropObjectName: {value: bacnet.CharStringValue("mock-device")},
		bacnet.PropVendorName: {value: bacnet.CharStringValue(d.vendorName)},
		bacnet.PropModelName:  {value: bacnet.CharStringValue(d.modelName)},
	}
	return d
}

// Instance returns the device's BACnet device-instance number.
func (d *Device) Instance() uint32 { return d.instance }

// AddObject creates obj with an initial set of non-commandable properties.
// present-value is seeded via values[bacnet.PropPresentValue] and, for
// commandable object types (outputs/values), also becomes priority 16 (the
// lowest priority, matching a typical "default" relinquish value).
func (d *Device) AddObject(objType bacnet.ObjectType, instance uint32, values map[bacnet.PropertyIdentifier]bacnet.Value) {
	d.mu.Lock()
	defer d.mu.Unlock()
	key := objectKey{objType, instance}
	props := make(map[bacnet.PropertyIdentifier]*property, len(values))
	for prop, v := range values {
		p := &property{value: v}
		if bacnet.Commandable(objType, prop) {
			p.commandable = true
			p.priorities[15] = &v
		}
		props[prop] = p
	}
	d.objects[key] = props
}

// SetProperty overwrites a non-commandable property's value directly
// (bypassing priority arrays); used to seed test fixtures.
func (d *Device) SetProperty(objType bacnet.ObjectType, instance uint32, prop bacnet.PropertyIdentifier, v bacnet.Value) {
	d.mu.Lock()
	defer d.mu.Unlock()
	key := objectKey{objType, instance}
	if d.objects[key] == nil {
		d.objects[key] = make(map[bacnet.PropertyIdentifier]*property)
	}
	d.objects[key][prop] = &property{value: v}
}

func (d *Device) objectList() []bacnet.Value {
	d.mu.RLock()
	defer d.mu.RUnlock()
	keys := make([]objectKey, 0, len(d.objects))
	for k := range d.objects {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Type != keys[j].Type {
			return keys[i].Type < keys[j].Type
		}
		return keys[i].Instance < keys[j].Instance
	})
	values := make([]bacnet.Value, len(keys))
	for i, k := range keys {
		values[i] = bacnet.ObjectIDValue(k.Type, k.Instance)
	}
	return values
}

// readProperty returns the current value(s) for one property, honoring the
// synthetic object-list property on the Device object, or a BACnet error.
func (d *Device) readProperty(objType bacnet.ObjectType, instance uint32, prop bacnet.PropertyIdentifier) ([]bacnet.Value, *bacnet.BACnetError) {
	if objType == bacnet.ObjectDevice && instance == d.instance && prop == bacnet.PropObjectList {
		return d.objectList(), nil
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	props, ok := d.objects[objectKey{objType, instance}]
	if !ok {
		return nil, &bacnet.BACnetError{Class: bacnet.ErrorClassObject, Code: bacnet.ErrorCodeUnknownObject}
	}
	p, ok := props[prop]
	if !ok {
		return nil, &bacnet.BACnetError{Class: bacnet.ErrorClassProperty, Code: bacnet.ErrorCodeUnknownProperty}
	}
	return []bacnet.Value{effectiveValue(p)}, nil
}

// writeProperty writes value at the given priority (1-16, default 16 when
// nil) to a commandable present-value, or returns write-access-denied for
// non-commandable properties. A KindNull value relinquishes that priority.
func (d *Device) writeProperty(objType bacnet.ObjectType, instance uint32, prop bacnet.PropertyIdentifier, value bacnet.Value, priority *uint8) *bacnet.BACnetError {
	d.mu.Lock()
	defer d.mu.Unlock()
	props, ok := d.objects[objectKey{objType, instance}]
	if !ok {
		return &bacnet.BACnetError{Class: bacnet.ErrorClassObject, Code: bacnet.ErrorCodeUnknownObject}
	}
	p, ok := props[prop]
	if !ok {
		return &bacnet.BACnetError{Class: bacnet.ErrorClassProperty, Code: bacnet.ErrorCodeUnknownProperty}
	}
	if !p.commandable {
		return &bacnet.BACnetError{Class: bacnet.ErrorClassProperty, Code: bacnet.ErrorCodeWriteAccessDenied}
	}
	prio := uint8(16)
	if priority != nil {
		prio = *priority
	}
	if prio < 1 || prio > 16 {
		return &bacnet.BACnetError{Class: bacnet.ErrorClassProperty, Code: bacnet.ErrorCodeValueOutOfRange}
	}
	idx := int(prio) - 1
	if value.Kind == bacnet.KindNull {
		p.priorities[idx] = nil
	} else {
		v := value
		p.priorities[idx] = &v
	}
	return nil
}
