package api

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/bacnet"
)

// rpmChunk is how many objects' metadata is requested per
// ReadPropertyMultiple while enumerating a device, keeping each reply well
// inside a single unsegmented APDU on typical devices.
const rpmChunk = 16

// idleRefreshes is how many refresh intervals a device may go unrequested
// before its cache entry is dropped (and its background refresh stops).
const idleRefreshes = 10

// variable is one BACnet object of a device, with the metadata the proxy
// needs to authorize and list it. Live values (present-value etc.) are
// deliberately not cached.
type variable struct {
	Object      bacnet.ObjectIdentifier
	Name        string
	Description string
	Units       []bacnet.Value
}

// deviceVars is a snapshot of one device's variables, in object-list order.
type deviceVars struct {
	instance uint32
	vars     []variable
	byID     map[bacnet.ObjectIdentifier]*variable
}

func (dv *deviceVars) deviceObject() bacnet.ObjectIdentifier {
	return bacnet.ObjectIdentifier{Type: bacnet.ObjectDevice, Instance: dv.instance}
}

type cacheEntry struct {
	loadMu   sync.Mutex // serializes the initial load
	data     atomic.Pointer[deviceVars]
	lastUsed atomic.Int64 // UnixNano
}

// varCache enumerates devices' variables on first use and keeps them
// fresh by re-enumerating every interval in the background. A failed
// refresh keeps serving the previous snapshot.
type varCache struct {
	client   *bacnet.Client
	interval time.Duration

	mu      sync.Mutex
	entries map[string]*cacheEntry // hostPort -> entry

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

func newVarCache(client *bacnet.Client, interval time.Duration) *varCache {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &varCache{
		client:   client,
		interval: interval,
		entries:  make(map[string]*cacheEntry),
		ctx:      ctx,
		cancel:   cancel,
		done:     make(chan struct{}),
	}
	go c.run()
	return c
}

// close stops background refreshing and waits for it to finish.
func (c *varCache) close() {
	c.cancel()
	<-c.done
}

// get returns hostPort's variables, enumerating the device first if it
// isn't cached yet.
func (c *varCache) get(hostPort string) (*deviceVars, error) {
	c.mu.Lock()
	e := c.entries[hostPort]
	if e == nil {
		e = &cacheEntry{}
		c.entries[hostPort] = e
	}
	c.mu.Unlock()
	e.lastUsed.Store(time.Now().UnixNano())

	if dv := e.data.Load(); dv != nil {
		return dv, nil
	}
	e.loadMu.Lock()
	defer e.loadMu.Unlock()
	if dv := e.data.Load(); dv != nil {
		return dv, nil
	}
	dv, err := c.load(hostPort)
	if err != nil {
		return nil, err
	}
	e.data.Store(dv)
	return dv, nil
}

func (c *varCache) run() {
	defer close(c.done)
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			c.refreshAll()
		}
	}
}

func (c *varCache) refreshAll() {
	idleBefore := time.Now().Add(-idleRefreshes * c.interval).UnixNano()
	c.mu.Lock()
	entries := make(map[string]*cacheEntry, len(c.entries))
	for hostPort, e := range c.entries {
		if e.lastUsed.Load() < idleBefore {
			delete(c.entries, hostPort)
			continue
		}
		entries[hostPort] = e
	}
	c.mu.Unlock()

	for hostPort, e := range entries {
		if e.data.Load() == nil {
			continue // never loaded successfully; the next request retries
		}
		dv, err := c.load(hostPort)
		if err != nil {
			if c.ctx.Err() != nil {
				return
			}
			slog.Warn("refreshing device variables failed; keeping previous snapshot", "device", hostPort, "err", err)
			continue
		}
		e.data.Store(dv)
	}
}

// load enumerates a device: its instance (Who-Is), its object-list, and
// each object's object-name/description/units. Objects whose name can't
// be read are left out, so name-based authorization fails closed for them.
func (c *varCache) load(hostPort string) (*deviceVars, error) {
	ctx, cancel := context.WithTimeout(c.ctx, c.interval)
	defer cancel()

	iam, err := c.client.WhoIs(ctx, hostPort)
	if err != nil {
		return nil, err
	}
	devObj := bacnet.ObjectIdentifier{Type: bacnet.ObjectDevice, Instance: iam.Device.Instance}
	list, err := c.client.ReadProperty(ctx, hostPort, devObj, bacnet.PropObjectList, nil)
	if err != nil {
		return nil, err
	}

	all := make([]variable, 0, len(list))
	for _, v := range list {
		if v.Kind == bacnet.KindObjectID {
			all = append(all, variable{Object: v.Object})
		}
	}
	for start := 0; start < len(all); start += rpmChunk {
		chunk := all[start:min(start+rpmChunk, len(all))]
		if err := c.readMetadata(ctx, hostPort, chunk); err != nil {
			return nil, err
		}
	}

	dv := &deviceVars{instance: iam.Device.Instance, byID: make(map[bacnet.ObjectIdentifier]*variable, len(all))}
	for _, v := range all {
		if v.Name == "" {
			slog.Debug("omitting object without a readable object-name", "device", hostPort, "object", v.Object.Type.String(), "instance", v.Object.Instance)
			continue
		}
		dv.vars = append(dv.vars, v)
	}
	for i := range dv.vars {
		dv.byID[dv.vars[i].Object] = &dv.vars[i]
	}
	return dv, nil
}

// readMetadata fills in chunk's metadata with one ReadPropertyMultiple,
// falling back to reading just object-name per object for devices that
// don't support ReadPropertyMultiple.
func (c *varCache) readMetadata(ctx context.Context, hostPort string, chunk []variable) error {
	specs := make([]bacnet.ReadAccessSpec, len(chunk))
	for i, v := range chunk {
		specs[i] = bacnet.ReadAccessSpec{Object: v.Object, Properties: []bacnet.PropertyReference{
			{Property: bacnet.PropObjectName},
			{Property: bacnet.PropDescription},
			{Property: bacnet.PropUnits},
		}}
	}
	results, err := c.client.ReadPropertyMultiple(ctx, hostPort, specs)
	if err == nil {
		byID := make(map[bacnet.ObjectIdentifier]*variable, len(chunk))
		for i := range chunk {
			byID[chunk[i].Object] = &chunk[i]
		}
		for _, res := range results {
			v := byID[res.Object]
			if v == nil {
				continue
			}
			for _, pr := range res.Results {
				if pr.Err != nil {
					continue
				}
				switch pr.Property {
				case bacnet.PropObjectName:
					v.Name = charString(pr.Values)
				case bacnet.PropDescription:
					v.Description = charString(pr.Values)
				case bacnet.PropUnits:
					v.Units = pr.Values
				}
			}
		}
		return nil
	}
	if ctx.Err() != nil {
		return err
	}

	for i := range chunk {
		values, err := c.client.ReadProperty(ctx, hostPort, chunk[i].Object, bacnet.PropObjectName, nil)
		if err != nil {
			if ctx.Err() != nil {
				return err
			}
			continue // leaves Name empty: the object is omitted
		}
		chunk[i].Name = charString(values)
	}
	return nil
}

func charString(values []bacnet.Value) string {
	if len(values) == 1 && values[0].Kind == bacnet.KindCharacterString {
		return values[0].Str
	}
	return ""
}
