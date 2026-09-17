package bacnet_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/bacnet"
	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/bacnetmock"
)

func newTestFixture(t *testing.T) (*bacnet.Client, *bacnetmock.Server, *bacnetmock.Device) {
	t.Helper()
	device := bacnetmock.NewDevice(1001)
	device.AddObject(bacnet.ObjectAnalogInput, 1, map[bacnet.PropertyIdentifier]bacnet.Value{
		bacnet.PropObjectName:   bacnet.CharStringValue("Room Temp"),
		bacnet.PropPresentValue: bacnet.RealValue(21.5),
		bacnet.PropUnits:        bacnet.EnumeratedValue(62), // degrees-celsius
	})
	device.AddObject(bacnet.ObjectAnalogOutput, 2, map[bacnet.PropertyIdentifier]bacnet.Value{
		bacnet.PropObjectName:   bacnet.CharStringValue("Damper Cmd"),
		bacnet.PropPresentValue: bacnet.RealValue(0),
	})

	server, err := bacnetmock.Listen("127.0.0.1:0", device)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	client, err := bacnet.NewClient(bacnet.ClientOptions{
		LocalAddr: "127.0.0.1:0",
		Timeout:   500 * time.Millisecond,
		Retries:   2,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	return client, server, device
}

func TestWhoIsIAm(t *testing.T) {
	client, server, device := newTestFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	iam, err := client.WhoIs(ctx, server.Addr().String())
	if err != nil {
		t.Fatalf("who-is: %v", err)
	}
	if iam.Device.Instance != device.Instance() {
		t.Errorf("got device instance %d, want %d", iam.Device.Instance, device.Instance())
	}
	if iam.Device.Type != bacnet.ObjectDevice {
		t.Errorf("got object type %v, want device", iam.Device.Type)
	}
}

func TestReadProperty(t *testing.T) {
	client, server, _ := newTestFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	values, err := client.ReadProperty(ctx, server.Addr().String(),
		bacnet.ObjectIdentifier{Type: bacnet.ObjectAnalogInput, Instance: 1}, bacnet.PropPresentValue, nil)
	if err != nil {
		t.Fatalf("read-property: %v", err)
	}
	if len(values) != 1 || values[0].Kind != bacnet.KindReal || values[0].Real != 21.5 {
		t.Fatalf("got %+v, want a single real value 21.5", values)
	}
}

func TestReadPropertyUnknownObject(t *testing.T) {
	client, server, _ := newTestFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := client.ReadProperty(ctx, server.Addr().String(),
		bacnet.ObjectIdentifier{Type: bacnet.ObjectAnalogInput, Instance: 99}, bacnet.PropPresentValue, nil)
	var bacErr *bacnet.BACnetError
	if !errors.As(err, &bacErr) {
		t.Fatalf("got err %v, want *bacnet.BACnetError", err)
	}
	if bacErr.Code != bacnet.ErrorCodeUnknownObject {
		t.Fatalf("got error code %d, want unknown-object (%d)", bacErr.Code, bacnet.ErrorCodeUnknownObject)
	}
}

func TestReadPropertyUnknownProperty(t *testing.T) {
	client, server, _ := newTestFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := client.ReadProperty(ctx, server.Addr().String(),
		bacnet.ObjectIdentifier{Type: bacnet.ObjectAnalogInput, Instance: 1}, bacnet.PropDescription, nil)
	var bacErr *bacnet.BACnetError
	if !errors.As(err, &bacErr) {
		t.Fatalf("got err %v, want *bacnet.BACnetError", err)
	}
	if bacErr.Code != bacnet.ErrorCodeUnknownProperty {
		t.Fatalf("got error code %d, want unknown-property (%d)", bacErr.Code, bacnet.ErrorCodeUnknownProperty)
	}
}

func TestWritePropertyCommandable(t *testing.T) {
	client, server, _ := newTestFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	obj := bacnet.ObjectIdentifier{Type: bacnet.ObjectAnalogOutput, Instance: 2}
	priority := uint8(8)
	if err := client.WriteProperty(ctx, server.Addr().String(), obj, bacnet.PropPresentValue, bacnet.RealValue(55), &priority); err != nil {
		t.Fatalf("write-property: %v", err)
	}

	values, err := client.ReadProperty(ctx, server.Addr().String(), obj, bacnet.PropPresentValue, nil)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if values[0].Real != 55 {
		t.Fatalf("got %v after write, want 55", values[0].Real)
	}

	// Relinquishing that priority should fall back to the next set priority
	// (here, the seeded default at priority 16, present-value 0).
	if err := client.WriteProperty(ctx, server.Addr().String(), obj, bacnet.PropPresentValue, bacnet.NullValue(), &priority); err != nil {
		t.Fatalf("relinquish: %v", err)
	}
	values, err = client.ReadProperty(ctx, server.Addr().String(), obj, bacnet.PropPresentValue, nil)
	if err != nil {
		t.Fatalf("read after relinquish: %v", err)
	}
	if values[0].Real != 0 {
		t.Fatalf("got %v after relinquish, want 0 (default)", values[0].Real)
	}
}

func TestWritePropertyNonCommandableDenied(t *testing.T) {
	client, server, _ := newTestFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	obj := bacnet.ObjectIdentifier{Type: bacnet.ObjectAnalogInput, Instance: 1}
	err := client.WriteProperty(ctx, server.Addr().String(), obj, bacnet.PropPresentValue, bacnet.RealValue(1), nil)
	var bacErr *bacnet.BACnetError
	if !errors.As(err, &bacErr) {
		t.Fatalf("got err %v, want *bacnet.BACnetError", err)
	}
	if bacErr.Code != bacnet.ErrorCodeWriteAccessDenied {
		t.Fatalf("got error code %d, want write-access-denied (%d)", bacErr.Code, bacnet.ErrorCodeWriteAccessDenied)
	}
}

func TestReadPropertyMultiple(t *testing.T) {
	client, server, _ := newTestFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	specs := []bacnet.ReadAccessSpec{{
		Object: bacnet.ObjectIdentifier{Type: bacnet.ObjectAnalogInput, Instance: 1},
		Properties: []bacnet.PropertyReference{
			{Property: bacnet.PropObjectName},
			{Property: bacnet.PropPresentValue},
			{Property: bacnet.PropDescription}, // unknown, should come back as a per-property error
		},
	}}
	results, err := client.ReadPropertyMultiple(ctx, server.Addr().String(), specs)
	if err != nil {
		t.Fatalf("read-property-multiple: %v", err)
	}
	if len(results) != 1 || len(results[0].Results) != 3 {
		t.Fatalf("got %+v, want 1 object with 3 property results", results)
	}
	byProp := map[bacnet.PropertyIdentifier]bacnet.PropertyResult{}
	for _, r := range results[0].Results {
		byProp[r.Property] = r
	}
	if v := byProp[bacnet.PropObjectName]; v.Err != nil || v.Values[0].Str != "Room Temp" {
		t.Errorf("object-name result = %+v", v)
	}
	if v := byProp[bacnet.PropPresentValue]; v.Err != nil || v.Values[0].Real != 21.5 {
		t.Errorf("present-value result = %+v", v)
	}
	if v := byProp[bacnet.PropDescription]; v.Err == nil || v.Err.Code != bacnet.ErrorCodeUnknownProperty {
		t.Errorf("description result = %+v, want unknown-property error", v)
	}
}

func TestReadPropertyDeviceObjectList(t *testing.T) {
	client, server, device := newTestFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	values, err := client.ReadProperty(ctx, server.Addr().String(),
		bacnet.ObjectIdentifier{Type: bacnet.ObjectDevice, Instance: device.Instance()}, bacnet.PropObjectList, nil)
	if err != nil {
		t.Fatalf("read object-list: %v", err)
	}
	// The device object itself plus the two seeded objects.
	if len(values) != 3 {
		t.Fatalf("got %d objects, want 3", len(values))
	}
	for _, v := range values {
		if v.Kind != bacnet.KindObjectID {
			t.Errorf("object-list entry has kind %v, want object identifier", v.Kind)
		}
	}
}

func TestClientTimeoutUnreachableHost(t *testing.T) {
	client, err := bacnet.NewClient(bacnet.ClientOptions{
		LocalAddr: "127.0.0.1:0",
		Timeout:   100 * time.Millisecond,
		Retries:   0,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// 127.0.0.1:47850 has no listener, so the request should time out rather
	// than hang or panic.
	_, err = client.ReadProperty(ctx, "127.0.0.1:47850",
		bacnet.ObjectIdentifier{Type: bacnet.ObjectAnalogInput, Instance: 1}, bacnet.PropPresentValue, nil)
	if err == nil {
		t.Fatal("expected a timeout error, got nil")
	}
}
