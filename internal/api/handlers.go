package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/auth"
	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/authz"
	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/bacnet"
	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/config"
)

// Server holds the dependencies REST handlers need: a BACnet/IP client, the
// device alias table, the variable cache, and the authentication/authorization
// engine.
type Server struct {
	client         *bacnet.Client
	devices        map[string]string
	authenticator  *auth.Authenticator
	rules          []authz.Rule
	requestTimeout time.Duration
	trustedProxies []*net.IPNet
	// needsObjectName is set when any rule has a `variable` condition, so
	// authorizing a single-variable request needs the variable's name.
	needsObjectName bool

	cache *varCache
}

// NewServer builds a Server from a loaded configuration and a BACnet client,
// and starts refreshing the variable cache in the background; call Close to
// stop it.
func NewServer(cfg *config.Config, client *bacnet.Client) *Server {
	s := &Server{
		client:         client,
		devices:        cfg.Devices,
		authenticator:  auth.NewAuthenticator(auth.Options{Tokens: cfg.AuthTokens(), JWTSecret: cfg.Authentication.JWTSecret}),
		rules:          cfg.AuthzRules(),
		requestTimeout: cfg.Bacnet.Timeout.AsDuration(),
		trustedProxies: cfg.TrustedProxyNets(),
		cache:          newVarCache(client, cfg.Bacnet.CacheRefresh.AsDuration()),
	}
	s.needsObjectName = authz.UsesCondition(s.rules, authz.ConditionVariable)
	return s
}

// Close stops the variable cache's background refresh.
func (s *Server) Close() {
	s.cache.close()
}

func (s *Server) resolveDevice(id string) string {
	if addr, ok := s.devices[id]; ok {
		return addr
	}
	return id
}

func (s *Server) requestContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), s.requestTimeout)
}

// visibleVariables returns the variables of dv that c may see, with c's
// access to each, in object-list order.
func (s *Server) visibleVariables(c caller, dv *deviceVars) []objectSummary {
	uniform := accessNone
	if !s.needsObjectName {
		uniform = s.variableAccess(c, "")
	}
	out := make([]objectSummary, 0, len(dv.vars))
	for _, v := range dv.vars {
		a := uniform
		if s.needsObjectName {
			a = s.variableAccess(c, v.Name)
		}
		if a == accessNone {
			continue
		}
		o := objectSummary{Type: v.Object.Type.String(), Instance: v.Object.Instance, Name: v.Name, Description: v.Description, Access: a}
		if len(v.Units) > 0 {
			o.Units = jsonValues(v.Units)
		}
		out = append(out, o)
	}
	return out
}

// handleListDevices serves GET /devices: the configured alias table only,
// no BACnet traffic.
func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, "", authz.OperationListDevices); !ok {
		return
	}
	summaries := make([]deviceSummary, 0, len(s.devices))
	for id := range s.devices {
		summaries = append(summaries, deviceSummary{ID: id})
	}
	sort.Slice(summaries, func(i, j int) bool { return summaries[i].ID < summaries[j].ID })
	writeJSON(w, http.StatusOK, summaries)
}

// handleGetDevice serves GET /devices/{deviceId}: a small summary read via
// ReadPropertyMultiple against the device's own Device object, which is
// authorized like any other variable.
func (s *Server) handleGetDevice(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "deviceId")
	c, name, ok := s.authorizeVariable(w, r, deviceID, nil, authz.OperationReadPropertyMultiple)
	if !ok {
		return
	}
	hostPort := s.resolveDevice(deviceID)
	dv, err := s.cache.get(hostPort)
	if err != nil {
		writeBACnetError(w, err)
		return
	}

	ctx, cancel := s.requestContext(r)
	defer cancel()

	results, err := s.client.ReadPropertyMultiple(ctx, hostPort, []bacnet.ReadAccessSpec{{
		Object: dv.deviceObject(),
		Properties: []bacnet.PropertyReference{
			{Property: bacnet.PropObjectName},
			{Property: bacnet.PropVendorName},
			{Property: bacnet.PropModelName},
		},
	}})
	if err != nil {
		writeBACnetError(w, err)
		return
	}

	// address deliberately echoes back what the caller supplied, not the
	// resolved hostPort: an alias's target host/IP is internal network
	// topology and must not leak to a caller who only knows the alias.
	out := map[string]any{"id": deviceID, "address": deviceID, "instance": dv.instance, "access": s.variableAccess(c, name)}
	if len(results) == 1 {
		for _, pr := range results[0].Results {
			if pr.Err != nil {
				continue
			}
			out[pr.Property.String()] = jsonValues(pr.Values)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleListObjects serves GET /devices/{deviceId}/objects from the variable
// cache: only the variables the caller may read, each with its access.
func (s *Server) handleListObjects(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "deviceId")
	c := s.newCaller(r, deviceID)
	if !s.needsObjectName && s.variableAccess(c, "") == accessNone {
		// Denied for every variable alike: don't enumerate the device.
		writeDenied(w, c.bearer)
		return
	}
	dv, err := s.cache.get(s.resolveDevice(deviceID))
	if err != nil {
		if s.needsObjectName {
			slog.Warn("denying request: could not enumerate device variables for authorization", "device", deviceID, "err", err)
			writeDenied(w, c.bearer)
			return
		}
		writeBACnetError(w, err)
		return
	}
	summaries := s.visibleVariables(c, dv)
	if len(summaries) == 0 {
		// Every device has at least its Device object, so nothing visible
		// means the caller has no access to this device at all.
		writeDenied(w, c.bearer)
		return
	}
	writeJSON(w, http.StatusOK, summaries)
}

func parseObjectRef(r *http.Request) (bacnet.ObjectType, uint32, error) {
	objType, err := bacnet.ParseObjectType(chi.URLParam(r, "objectType"))
	if err != nil {
		return 0, 0, err
	}
	instance, err := strconv.ParseUint(chi.URLParam(r, "instance"), 10, 32)
	if err != nil {
		return 0, 0, err
	}
	return objType, uint32(instance), nil
}

// handleGetObject serves GET /devices/{deviceId}/objects/{type}/{instance}:
// a small summary of commonly-useful properties, silently omitting any that
// the object doesn't have.
func (s *Server) handleGetObject(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "deviceId")
	objType, instance, err := parseObjectRef(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	c, name, ok := s.authorizeVariable(w, r, deviceID, &bacnet.ObjectIdentifier{Type: objType, Instance: instance}, authz.OperationReadPropertyMultiple)
	if !ok {
		return
	}
	hostPort := s.resolveDevice(deviceID)

	ctx, cancel := s.requestContext(r)
	defer cancel()

	obj := bacnet.ObjectIdentifier{Type: objType, Instance: instance}
	results, err := s.client.ReadPropertyMultiple(ctx, hostPort, []bacnet.ReadAccessSpec{{
		Object: obj,
		Properties: []bacnet.PropertyReference{
			{Property: bacnet.PropObjectName},
			{Property: bacnet.PropPresentValue},
			{Property: bacnet.PropDescription},
			{Property: bacnet.PropUnits},
			{Property: bacnet.PropStatusFlags},
		},
	}})
	if err != nil {
		writeBACnetError(w, err)
		return
	}
	if len(results) != 1 {
		writeError(w, http.StatusBadGateway, "unexpected empty response from device")
		return
	}

	out := map[string]any{"type": objType.String(), "instance": instance}
	var firstErr *bacnet.BACnetError
	for _, pr := range results[0].Results {
		if pr.Err != nil {
			if pr.Property == bacnet.PropPresentValue || pr.Property == bacnet.PropObjectName {
				firstErr = pr.Err // the object itself likely doesn't exist
			}
			continue
		}
		out[pr.Property.String()] = jsonValues(pr.Values)
	}
	if firstErr != nil && len(out) == 2 {
		writeBACnetError(w, firstErr)
		return
	}
	out["access"] = s.variableAccess(c, name)
	writeJSON(w, http.StatusOK, out)
}

// handleGetProperty serves GET .../{property}[?index=N].
func (s *Server) handleGetProperty(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "deviceId")
	objType, instance, err := parseObjectRef(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	c, name, ok := s.authorizeVariable(w, r, deviceID, &bacnet.ObjectIdentifier{Type: objType, Instance: instance}, authz.OperationReadProperty)
	if !ok {
		return
	}
	prop, err := bacnet.ParsePropertyIdentifier(chi.URLParam(r, "property"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var arrayIndex *uint32
	if idxParam := r.URL.Query().Get("index"); idxParam != "" {
		idx, err := strconv.ParseUint(idxParam, 10, 32)
		if err != nil {
			writeError(w, http.StatusBadRequest, "index must be a non-negative integer")
			return
		}
		v := uint32(idx)
		arrayIndex = &v
	}
	hostPort := s.resolveDevice(deviceID)

	ctx, cancel := s.requestContext(r)
	defer cancel()

	if objType == bacnet.ObjectDevice && prop == bacnet.PropObjectList && s.needsObjectName {
		s.serveFilteredObjectList(w, ctx, c, hostPort, instance, arrayIndex, s.variableAccess(c, name))
		return
	}

	values, err := s.client.ReadProperty(ctx, hostPort, bacnet.ObjectIdentifier{Type: objType, Instance: instance}, prop, arrayIndex)
	if err != nil {
		writeBACnetError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, propertyValue{Value: jsonValues(values), Access: s.variableAccess(c, name)})
}

// serveFilteredObjectList serves a Device object's object-list with the
// variables c may not read removed. The list is always read in full and
// arrayIndex applied locally afterwards, so index 0 (the array length) and
// every other index refer to the filtered list and don't reveal hidden
// variables.
func (s *Server) serveFilteredObjectList(w http.ResponseWriter, ctx context.Context, c caller, hostPort string, instance uint32, arrayIndex *uint32, a access) {
	dv, err := s.cache.get(hostPort)
	if err != nil {
		writeBACnetError(w, err)
		return
	}
	values, err := s.client.ReadProperty(ctx, hostPort, bacnet.ObjectIdentifier{Type: bacnet.ObjectDevice, Instance: instance}, bacnet.PropObjectList, nil)
	if err != nil {
		writeBACnetError(w, err)
		return
	}
	visible := make([]bacnet.Value, 0, len(values))
	for _, v := range values {
		if v.Kind != bacnet.KindObjectID {
			continue
		}
		// Objects missing from the cache (e.g. created since the last
		// refresh) have no known name, so they stay hidden until then.
		if cached, ok := dv.byID[v.Object]; ok && s.variableAccess(c, cached.Name) != accessNone {
			visible = append(visible, v)
		}
	}
	switch {
	case arrayIndex == nil:
	case *arrayIndex == 0:
		visible = []bacnet.Value{bacnet.UnsignedValue(uint64(len(visible)))}
	case int(*arrayIndex) <= len(visible):
		visible = visible[*arrayIndex-1 : *arrayIndex]
	default:
		writeError(w, http.StatusNotFound, "array index out of range")
		return
	}
	writeJSON(w, http.StatusOK, propertyValue{Value: jsonValues(visible), Access: a})
}

// handleWriteProperty serves PUT .../{property}.
func (s *Server) handleWriteProperty(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "deviceId")
	objType, instance, err := parseObjectRef(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, _, ok := s.authorizeVariable(w, r, deviceID, &bacnet.ObjectIdentifier{Type: objType, Instance: instance}, authz.OperationWriteProperty); !ok {
		return
	}
	prop, err := bacnet.ParsePropertyIdentifier(chi.URLParam(r, "property"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var body writeRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	value, err := valueForWrite(objType, prop, body.Value)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	hostPort := s.resolveDevice(deviceID)
	ctx, cancel := s.requestContext(r)
	defer cancel()

	if err := s.client.WriteProperty(ctx, hostPort, bacnet.ObjectIdentifier{Type: objType, Instance: instance}, prop, value, body.Priority); err != nil {
		writeBACnetError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
