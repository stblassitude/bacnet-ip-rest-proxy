package api

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/auth"
	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/authz"
	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/bacnet"
	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/config"
)

// Server holds the dependencies REST handlers need: a BACnet/IP client, the
// device alias table, and the authentication/authorization engine.
type Server struct {
	client         *bacnet.Client
	devices        map[string]string
	authenticator  *auth.Authenticator
	rules          []authz.Rule
	requestTimeout time.Duration

	instanceCache sync.Map // hostPort string -> uint32 device instance
}

// NewServer builds a Server from a loaded configuration and a BACnet client.
func NewServer(cfg *config.Config, client *bacnet.Client) *Server {
	return &Server{
		client:         client,
		devices:        cfg.Devices,
		authenticator:  auth.NewAuthenticator(auth.Options{Tokens: cfg.AuthTokens(), JWTSecret: cfg.Authentication.JWTSecret}),
		rules:          cfg.AuthzRules(),
		requestTimeout: cfg.Bacnet.Timeout.AsDuration(),
	}
}

func (s *Server) resolveDevice(id string) string {
	if addr, ok := s.devices[id]; ok {
		return addr
	}
	return id
}

func (s *Server) deviceInstance(ctx context.Context, hostPort string) (uint32, error) {
	if v, ok := s.instanceCache.Load(hostPort); ok {
		return v.(uint32), nil
	}
	iam, err := s.client.WhoIs(ctx, hostPort)
	if err != nil {
		return 0, err
	}
	s.instanceCache.Store(hostPort, iam.Device.Instance)
	return iam.Device.Instance, nil
}

func (s *Server) requestContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), s.requestTimeout)
}

// handleListDevices serves GET /devices: the configured alias table only,
// no BACnet traffic.
func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "", authz.OperationListDevices) {
		return
	}
	summaries := make([]deviceSummary, 0, len(s.devices))
	for id, addr := range s.devices {
		summaries = append(summaries, deviceSummary{ID: id, Address: addr})
	}
	sort.Slice(summaries, func(i, j int) bool { return summaries[i].ID < summaries[j].ID })
	writeJSON(w, http.StatusOK, summaries)
}

// handleGetDevice serves GET /devices/{deviceId}: a small summary read via
// ReadPropertyMultiple against the device's own Device object.
func (s *Server) handleGetDevice(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "deviceId")
	if !s.authorize(w, r, deviceID, authz.OperationReadPropertyMultiple) {
		return
	}
	hostPort := s.resolveDevice(deviceID)

	ctx, cancel := s.requestContext(r)
	defer cancel()

	instance, err := s.deviceInstance(ctx, hostPort)
	if err != nil {
		writeBACnetError(w, err)
		return
	}
	obj := bacnet.ObjectIdentifier{Type: bacnet.ObjectDevice, Instance: instance}
	results, err := s.client.ReadPropertyMultiple(ctx, hostPort, []bacnet.ReadAccessSpec{{
		Object: obj,
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

	out := map[string]any{"id": deviceID, "address": hostPort, "instance": instance}
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

// handleListObjects serves GET /devices/{deviceId}/objects: the device's
// object-list property.
func (s *Server) handleListObjects(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "deviceId")
	if !s.authorize(w, r, deviceID, authz.OperationReadProperty) {
		return
	}
	hostPort := s.resolveDevice(deviceID)

	ctx, cancel := s.requestContext(r)
	defer cancel()

	instance, err := s.deviceInstance(ctx, hostPort)
	if err != nil {
		writeBACnetError(w, err)
		return
	}
	values, err := s.client.ReadProperty(ctx, hostPort,
		bacnet.ObjectIdentifier{Type: bacnet.ObjectDevice, Instance: instance}, bacnet.PropObjectList, nil)
	if err != nil {
		writeBACnetError(w, err)
		return
	}

	summaries := make([]objectSummary, 0, len(values))
	for _, v := range values {
		if v.Kind != bacnet.KindObjectID {
			continue
		}
		summaries = append(summaries, objectSummary{Type: v.Object.Type.String(), Instance: v.Object.Instance})
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
	if !s.authorize(w, r, deviceID, authz.OperationReadPropertyMultiple) {
		return
	}
	objType, instance, err := parseObjectRef(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
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
	writeJSON(w, http.StatusOK, out)
}

// handleGetProperty serves GET .../{property}[?index=N].
func (s *Server) handleGetProperty(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "deviceId")
	if !s.authorize(w, r, deviceID, authz.OperationReadProperty) {
		return
	}
	objType, instance, err := parseObjectRef(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
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

	values, err := s.client.ReadProperty(ctx, hostPort, bacnet.ObjectIdentifier{Type: objType, Instance: instance}, prop, arrayIndex)
	if err != nil {
		writeBACnetError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, propertyValue{Value: jsonValues(values)})
}

// handleWriteProperty serves PUT .../{property}.
func (s *Server) handleWriteProperty(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "deviceId")
	if !s.authorize(w, r, deviceID, authz.OperationWriteProperty) {
		return
	}
	objType, instance, err := parseObjectRef(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
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
