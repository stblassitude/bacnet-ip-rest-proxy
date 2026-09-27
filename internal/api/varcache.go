package api

import (
	"context"
	"errors"
	"fmt"
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

// indexChunk is how many object-list elements are requested per
// ReadPropertyMultiple when the whole list doesn't fit in one APDU (each
// element takes about a dozen bytes of the reply).
const indexChunk = 50

// minLoadTimeout bounds how long enumerating one device may take, when
// that's longer than the refresh interval: large devices read piecewise
// can need many round trips.
const minLoadTimeout = 5 * time.Minute

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
	ctx, cancel := context.WithTimeout(c.ctx, max(c.interval, minLoadTimeout))
	defer cancel()

	iam, err := c.client.WhoIs(ctx, hostPort)
	if err != nil {
		return nil, fmt.Errorf("who-is: %w", err)
	}
	l := &loader{client: c.client, hostPort: hostPort}
	list, err := l.readObjectList(ctx, iam.Device.Instance)
	if err != nil {
		return nil, fmt.Errorf("reading object-list: %w", err)
	}

	all := make([]variable, 0, len(list))
	for _, v := range list {
		if v.Kind == bacnet.KindObjectID {
			all = append(all, variable{Object: v.Object})
		}
	}
	for start := 0; start < len(all); start += rpmChunk {
		chunk := all[start:min(start+rpmChunk, len(all))]
		if err := l.readMetadata(ctx, chunk); err != nil {
			return nil, fmt.Errorf("reading object names: %w", err)
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
	slog.Debug("enumerated device variables", "device", hostPort, "count", len(dv.vars))
	return dv, nil
}

// readObjectList reads hostPort's object-list (see loader.readObjectList).
func (c *varCache) readObjectList(ctx context.Context, hostPort string, instance uint32) ([]bacnet.Value, error) {
	return (&loader{client: c.client, hostPort: hostPort}).readObjectList(ctx, instance)
}

// loader reads one device's variables, working within the client's
// limitation to unsegmented replies (at most one 1476-byte APDU each).
type loader struct {
	client   *bacnet.Client
	hostPort string
	noRPM    bool // the device rejected ReadPropertyMultiple as unrecognized
}

// readObjectList reads the Device object's object-list whole if the reply
// fits in one APDU, and otherwise element by element: index 0 for the
// length, then batches of indexes per ReadPropertyMultiple (or one
// ReadProperty per index for devices without ReadPropertyMultiple).
func (l *loader) readObjectList(ctx context.Context, instance uint32) ([]bacnet.Value, error) {
	devObj := bacnet.ObjectIdentifier{Type: bacnet.ObjectDevice, Instance: instance}
	list, err := l.client.ReadProperty(ctx, l.hostPort, devObj, bacnet.PropObjectList, nil)
	if err == nil || !retryPiecewise(ctx, err) {
		return list, err
	}

	zero := uint32(0)
	lenValues, err := l.client.ReadProperty(ctx, l.hostPort, devObj, bacnet.PropObjectList, &zero)
	if err != nil {
		return nil, fmt.Errorf("reading its length: %w", err)
	}
	if len(lenValues) != 1 || lenValues[0].Kind != bacnet.KindUnsigned {
		return nil, fmt.Errorf("unexpected object-list length %v", lenValues)
	}
	n := uint32(lenValues[0].Unsigned)

	list = make([]bacnet.Value, 0, n)
	for start := uint32(1); start <= n; start += indexChunk {
		end := min(start+indexChunk-1, n)
		values, err := l.readIndexes(ctx, devObj, start, end)
		if err != nil {
			return nil, fmt.Errorf("reading elements %d-%d: %w", start, end, err)
		}
		list = append(list, values...)
	}
	return list, nil
}

func (l *loader) readIndexes(ctx context.Context, obj bacnet.ObjectIdentifier, start, end uint32) ([]bacnet.Value, error) {
	if !l.noRPM {
		refs := make([]bacnet.PropertyReference, 0, end-start+1)
		for i := start; i <= end; i++ {
			refs = append(refs, bacnet.PropertyReference{Property: bacnet.PropObjectList, ArrayIndex: &i})
		}
		results, err := l.client.ReadPropertyMultiple(ctx, l.hostPort, []bacnet.ReadAccessSpec{{Object: obj, Properties: refs}})
		if err == nil {
			var values []bacnet.Value
			for _, res := range results {
				for _, pr := range res.Results {
					if pr.Err != nil {
						return nil, pr.Err
					}
					values = append(values, pr.Values...)
				}
			}
			return values, nil
		}
		if !l.noteRPMFailure(ctx, err) {
			return nil, err
		}
	}
	var values []bacnet.Value
	for i := start; i <= end; i++ {
		v, err := l.client.ReadProperty(ctx, l.hostPort, obj, bacnet.PropObjectList, &i)
		if err != nil {
			return nil, err
		}
		values = append(values, v...)
	}
	return values, nil
}

// readMetadata fills in chunk's metadata with ReadPropertyMultiple, halving
// the chunk whenever the reply doesn't fit in one APDU, and falling back to
// reading just object-name per object for devices that don't support
// ReadPropertyMultiple.
func (l *loader) readMetadata(ctx context.Context, chunk []variable) error {
	if !l.noRPM {
		err := l.readMetadataRPM(ctx, chunk)
		if err == nil {
			return nil
		}
		if !l.noteRPMFailure(ctx, err) {
			return err
		}
		if !l.noRPM && len(chunk) > 1 {
			mid := len(chunk) / 2
			if err := l.readMetadata(ctx, chunk[:mid]); err != nil {
				return err
			}
			return l.readMetadata(ctx, chunk[mid:])
		}
	}
	for i := range chunk {
		values, err := l.client.ReadProperty(ctx, l.hostPort, chunk[i].Object, bacnet.PropObjectName, nil)
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

func (l *loader) readMetadataRPM(ctx context.Context, chunk []variable) error {
	specs := make([]bacnet.ReadAccessSpec, len(chunk))
	for i, v := range chunk {
		specs[i] = bacnet.ReadAccessSpec{Object: v.Object, Properties: []bacnet.PropertyReference{
			{Property: bacnet.PropObjectName},
			{Property: bacnet.PropDescription},
			{Property: bacnet.PropUnits},
		}}
	}
	results, err := l.client.ReadPropertyMultiple(ctx, l.hostPort, specs)
	if err != nil {
		return err
	}
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

// noteRPMFailure classifies a failed ReadPropertyMultiple: it records a
// device that doesn't support the service at all, and reports whether a
// smaller or per-property retry may succeed.
func (l *loader) noteRPMFailure(ctx context.Context, err error) bool {
	if rej, ok := errors.AsType[*bacnet.RejectError](err); ok && rej.Reason == bacnet.RejectReasonUnrecognizedService {
		l.noRPM = true
		return true
	}
	return retryPiecewise(ctx, err)
}

// retryPiecewise reports whether a failed read may succeed when split into
// smaller reads: the reply didn't fit in one APDU (an abort), or the device
// didn't answer at all, which some devices do for oversized replies.
func retryPiecewise(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	if _, ok := errors.AsType[*bacnet.AbortError](err); ok {
		return true
	}
	return errors.Is(err, bacnet.ErrTimeout)
}

func charString(values []bacnet.Value) string {
	if len(values) == 1 && values[0].Kind == bacnet.KindCharacterString {
		return values[0].Str
	}
	return ""
}
