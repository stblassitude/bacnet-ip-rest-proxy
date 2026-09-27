package api_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/api"
	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/authz"
	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/bacnet"
	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/bacnetmock"
	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/config"
)

// newTestServer spins up a mock BACnet/IP device and an API server wired
// against it via the given rules, and returns an httptest.Server (the
// device is aliased "unit" for use in URLs) plus the mock device's real
// address, for tests asserting it never leaks to callers.
func newTestServer(t *testing.T, rules []authz.Rule, tokens []config.TokenConfig, jwtSecret string) (*httptest.Server, string) {
	t.Helper()
	device := bacnetmock.NewDevice(2001)
	device.AddObject(bacnet.ObjectAnalogInput, 1, map[bacnet.PropertyIdentifier]bacnet.Value{
		bacnet.PropObjectName:   bacnet.CharStringValue("Room Temp"),
		bacnet.PropPresentValue: bacnet.RealValue(21.5),
	})
	device.AddObject(bacnet.ObjectAnalogOutput, 2, map[bacnet.PropertyIdentifier]bacnet.Value{
		bacnet.PropObjectName:   bacnet.CharStringValue("Damper Cmd"),
		bacnet.PropPresentValue: bacnet.RealValue(0),
	})

	mockServer, err := bacnetmock.Listen("127.0.0.1:0", device)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = mockServer.Close() })

	client, err := bacnet.NewClient(bacnet.ClientOptions{
		LocalAddr: "127.0.0.1:0",
		Timeout:   500 * time.Millisecond,
		Retries:   1,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	cfg := &config.Config{
		Devices: map[string]string{"unit": mockServer.Addr().String()},
		Authentication: config.AuthenticationConfig{
			JWTSecret: jwtSecret,
		},
		Bacnet: config.BacnetConfig{Timeout: config.Duration(2 * time.Second)},
	}
	for _, tok := range tokens {
		cfg.Authentication.Tokens = append(cfg.Authentication.Tokens, tok)
	}
	for _, rule := range rules {
		cfg.Authorization.Rules = append(cfg.Authorization.Rules, config.RuleConfig{
			Name:       rule.Name,
			Match:      string(rule.Match),
			Permission: string(rule.Permission),
			Action:     string(rule.Action),
		})
		for _, c := range rule.Conditions {
			last := len(cfg.Authorization.Rules) - 1
			cfg.Authorization.Rules[last].Conditions = append(cfg.Authorization.Rules[last].Conditions, config.ConditionConfig{
				Type: string(c.Type), Field: c.Field, Value: c.Value,
			})
		}
	}

	apiServer := api.NewServer(cfg, client)
	t.Cleanup(apiServer.Close)
	httpServer := httptest.NewServer(api.NewRouter(apiServer))
	t.Cleanup(httpServer.Close)
	return httpServer, mockServer.Addr().String()
}

func doRequest(t *testing.T, srv *httptest.Server, method, path, bearer string, body []byte) *http.Response {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, srv.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func readonlyToken() config.TokenConfig {
	return config.TokenConfig{Name: "reader", Token: "readonly-token"}
}
func readwriteToken() config.TokenConfig {
	return config.TokenConfig{Name: "writer", Token: "readwrite-token"}
}

func standardRules() []authz.Rule {
	return []authz.Rule{
		{
			Name:       "readers",
			Conditions: []authz.Condition{{Type: authz.ConditionToken, Value: "reader"}},
			Match:      authz.MatchAll,
			Permission: authz.PermissionReadOnly,
			Action:     authz.ActionAllow,
		},
		{
			Name:       "writers",
			Conditions: []authz.Condition{{Type: authz.ConditionToken, Value: "writer"}},
			Match:      authz.MatchAll,
			Permission: authz.PermissionReadWrite,
			Action:     authz.ActionAllow,
		},
	}
}

func TestAnonymousRequestDenied(t *testing.T) {
	srv, _ := newTestServer(t, standardRules(), []config.TokenConfig{readonlyToken(), readwriteToken()}, "")
	resp := doRequest(t, srv, http.MethodGet, "/api/v1/devices", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got status %d, want 401", resp.StatusCode)
	}
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Error("expected WWW-Authenticate header on 401")
	}
}

func TestUnrecognizedBearerDenied(t *testing.T) {
	srv, _ := newTestServer(t, standardRules(), []config.TokenConfig{readonlyToken()}, "")
	resp := doRequest(t, srv, http.MethodGet, "/api/v1/devices", "garbage", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("got status %d, want 403", resp.StatusCode)
	}
}

func TestReadonlyTokenCanReadButNotWrite(t *testing.T) {
	srv, _ := newTestServer(t, standardRules(), []config.TokenConfig{readonlyToken(), readwriteToken()}, "")

	resp := doRequest(t, srv, http.MethodGet, "/api/v1/devices/unit/objects/analog-input/1/present-value", "readonly-token", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET got status %d, want 200", resp.StatusCode)
	}
	var body struct {
		Value float64 `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Value != 21.5 {
		t.Errorf("got value %v, want 21.5", body.Value)
	}

	writeBody, _ := json.Marshal(map[string]any{"value": 55})
	resp = doRequest(t, srv, http.MethodPut, "/api/v1/devices/unit/objects/analog-output/2/present-value", "readonly-token", writeBody)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("PUT with readonly token got status %d, want 403", resp.StatusCode)
	}
}

func TestReadwriteTokenCanWrite(t *testing.T) {
	srv, _ := newTestServer(t, standardRules(), []config.TokenConfig{readonlyToken(), readwriteToken()}, "")

	priority := 8
	writeBody, _ := json.Marshal(map[string]any{"value": 42.0, "priority": priority})
	resp := doRequest(t, srv, http.MethodPut, "/api/v1/devices/unit/objects/analog-output/2/present-value", "readwrite-token", writeBody)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT got status %d, want 204", resp.StatusCode)
	}

	resp = doRequest(t, srv, http.MethodGet, "/api/v1/devices/unit/objects/analog-output/2/present-value", "readwrite-token", nil)
	var body struct {
		Value float64 `json:"value"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body.Value != 42 {
		t.Fatalf("got value %v after write, want 42", body.Value)
	}
}

func TestDeviceScopedRule(t *testing.T) {
	rules := []authz.Rule{
		{
			Name: "only-unit-device",
			Conditions: []authz.Condition{
				{Type: authz.ConditionToken, Value: "reader"},
				{Type: authz.ConditionDevice, Value: "unit"},
			},
			Match:      authz.MatchAll,
			Permission: authz.PermissionReadOnly,
			Action:     authz.ActionAllow,
		},
	}
	srv, _ := newTestServer(t, rules, []config.TokenConfig{readonlyToken()}, "")

	resp := doRequest(t, srv, http.MethodGet, "/api/v1/devices/unit/objects/analog-input/1/present-value", "readonly-token", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d for allowed device, want 200", resp.StatusCode)
	}

	resp = doRequest(t, srv, http.MethodGet, "/api/v1/devices/other-device/objects/analog-input/1/present-value", "readonly-token", nil)
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got status %d for disallowed device, want 401/403", resp.StatusCode)
	}
}

func TestIPScopedRule(t *testing.T) {
	rules := []authz.Rule{
		{
			Name:       "loopback-only",
			Conditions: []authz.Condition{{Type: authz.ConditionIP, Value: "127.0.0.1"}},
			Match:      authz.MatchAll,
			Permission: authz.PermissionReadOnly,
			Action:     authz.ActionAllow,
		},
	}
	srv, _ := newTestServer(t, rules, nil, "")
	// httptest.Server listens on 127.0.0.1, so an anonymous request from the
	// test client (also 127.0.0.1) should be allowed purely by IP.
	resp := doRequest(t, srv, http.MethodGet, "/api/v1/devices/unit/objects/analog-input/1/present-value", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200 (IP-based allow)", resp.StatusCode)
	}
}

// newTestServerWithTrustedProxies is like newTestServer, but also lets a
// test configure listen.trustedProxies, for exercising
// X-Forwarded-For/X-Real-IP handling.
func newTestServerWithTrustedProxies(t *testing.T, rules []authz.Rule, trustedProxies []string) *httptest.Server {
	t.Helper()
	device := bacnetmock.NewDevice(2002)
	device.AddObject(bacnet.ObjectAnalogInput, 1, map[bacnet.PropertyIdentifier]bacnet.Value{
		bacnet.PropPresentValue: bacnet.RealValue(1),
	})
	mockServer, err := bacnetmock.Listen("127.0.0.1:0", device)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = mockServer.Close() })

	client, err := bacnet.NewClient(bacnet.ClientOptions{LocalAddr: "127.0.0.1:0", Timeout: 500 * time.Millisecond, Retries: 1})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	cfg := &config.Config{
		Listen:  config.ListenConfig{TrustedProxies: trustedProxies},
		Devices: map[string]string{"unit": mockServer.Addr().String()},
		Bacnet:  config.BacnetConfig{Timeout: config.Duration(2 * time.Second)},
	}
	for _, rule := range rules {
		rc := config.RuleConfig{Name: rule.Name, Match: string(rule.Match), Permission: string(rule.Permission), Action: string(rule.Action)}
		for _, c := range rule.Conditions {
			rc.Conditions = append(rc.Conditions, config.ConditionConfig{Type: string(c.Type), Field: c.Field, Value: c.Value})
		}
		cfg.Authorization.Rules = append(cfg.Authorization.Rules, rc)
	}

	apiServer := api.NewServer(cfg, client)
	t.Cleanup(apiServer.Close)
	httpServer := httptest.NewServer(api.NewRouter(apiServer))
	t.Cleanup(httpServer.Close)
	return httpServer
}

func TestTrustedProxyXForwardedForHonored(t *testing.T) {
	rules := []authz.Rule{{
		Name:       "spoofed-office-network",
		Conditions: []authz.Condition{{Type: authz.ConditionIP, Value: "10.0.0.0/8"}},
		Match:      authz.MatchAll,
		Permission: authz.PermissionReadOnly,
		Action:     authz.ActionAllow,
	}}
	// httptest.Server always listens on 127.0.0.1, so the real peer for
	// every request in this test is 127.0.0.1 — configuring it as trusted
	// means X-Forwarded-For is honored.
	srv := newTestServerWithTrustedProxies(t, rules, []string{"127.0.0.1/32"})

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/devices/unit/objects/analog-input/1/present-value", nil)
	req.Header.Set("X-Forwarded-For", "10.1.2.3")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200 (trusted proxy's X-Forwarded-For should be honored)", resp.StatusCode)
	}
}

func TestUntrustedPeerCannotSpoofXForwardedFor(t *testing.T) {
	rules := []authz.Rule{{
		Name:       "spoofed-office-network",
		Conditions: []authz.Condition{{Type: authz.ConditionIP, Value: "10.0.0.0/8"}},
		Match:      authz.MatchAll,
		Permission: authz.PermissionReadOnly,
		Action:     authz.ActionAllow,
	}}
	// No trusted proxies configured, so a client claiming to be in
	// 10.0.0.0/8 via X-Forwarded-For must not be believed: the real peer
	// (127.0.0.1) is what gets matched, and it doesn't satisfy the rule.
	srv := newTestServerWithTrustedProxies(t, rules, nil)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/devices/unit/objects/analog-input/1/present-value", nil)
	req.Header.Set("X-Forwarded-For", "10.1.2.3")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode == http.StatusOK {
		t.Fatal("an untrusted peer's spoofed X-Forwarded-For must not be honored")
	}
}

func TestJWTGroupRule(t *testing.T) {
	secret := "test-secret"
	rules := []authz.Rule{
		{
			Name:       "admins",
			Conditions: []authz.Condition{{Type: authz.ConditionJWT, Field: "group", Value: "admins"}},
			Match:      authz.MatchAll,
			Permission: authz.PermissionReadWrite,
			Action:     authz.ActionAllow,
		},
	}
	srv, _ := newTestServer(t, rules, nil, secret)

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"group": "admins",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	signed, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}

	resp := doRequest(t, srv, http.MethodGet, "/api/v1/devices/unit/objects/analog-input/1/present-value", signed, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}

	badTok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"group": "guests"})
	badSigned, _ := badTok.SignedString([]byte(secret))
	resp = doRequest(t, srv, http.MethodGet, "/api/v1/devices/unit/objects/analog-input/1/present-value", badSigned, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("got status %d for non-admin JWT, want 403", resp.StatusCode)
	}
}

func TestBACnetErrorMapsTo404(t *testing.T) {
	srv, _ := newTestServer(t, standardRules(), []config.TokenConfig{readonlyToken()}, "")
	resp := doRequest(t, srv, http.MethodGet, "/api/v1/devices/unit/objects/analog-input/999/present-value", "readonly-token", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("got status %d, want 404 for unknown object", resp.StatusCode)
	}
	var body struct {
		Error            string `json:"error"`
		BACnetErrorClass string `json:"bacnetErrorClass"`
		BACnetErrorCode  string `json:"bacnetErrorCode"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Error == "" || body.BACnetErrorCode == "" {
		t.Errorf("expected populated error body, got %+v", body)
	}
}

func TestListDevices(t *testing.T) {
	srv, _ := newTestServer(t, standardRules(), []config.TokenConfig{readonlyToken()}, "")
	resp := doRequest(t, srv, http.MethodGet, "/api/v1/devices", "readonly-token", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}
	var devices []struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&devices); err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].ID != "unit" {
		t.Fatalf("got %+v, want one device aliased 'unit'", devices)
	}
}

func TestListDevicesDoesNotLeakAddress(t *testing.T) {
	srv, realAddr := newTestServer(t, standardRules(), []config.TokenConfig{readonlyToken()}, "")
	resp := doRequest(t, srv, http.MethodGet, "/api/v1/devices", "readonly-token", nil)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), realAddr) {
		t.Fatalf("GET /devices leaked the alias's real address %q: %s", realAddr, body)
	}
	var devices []map[string]any
	if err := json.Unmarshal(body, &devices); err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 {
		t.Fatalf("got %d devices, want 1", len(devices))
	}
	if _, hasAddress := devices[0]["address"]; hasAddress {
		t.Fatalf("device summary must not include an address field, got %+v", devices[0])
	}
}

func TestGetDeviceEchoesRequestedIDNotRealAddress(t *testing.T) {
	srv, realAddr := newTestServer(t, standardRules(), []config.TokenConfig{readonlyToken()}, "")
	resp := doRequest(t, srv, http.MethodGet, "/api/v1/devices/unit", "readonly-token", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), realAddr) {
		t.Fatalf("GET /devices/unit leaked the alias's real address %q: %s", realAddr, body)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out["address"] != "unit" {
		t.Fatalf(`got address %q, want "unit" (the requested identifier, not the resolved address)`, out["address"])
	}
}

func TestOpenAPIAndSwaggerUIServed(t *testing.T) {
	srv, _ := newTestServer(t, nil, nil, "")

	resp := doRequest(t, srv, http.MethodGet, "/", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / got status %d, want 200", resp.StatusCode)
	}

	resp = doRequest(t, srv, http.MethodGet, "/openapi.yaml", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /openapi.yaml got status %d, want 200", resp.StatusCode)
	}

	resp = doRequest(t, srv, http.MethodGet, "/docs/index.html", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /docs/index.html got status %d, want 200", resp.StatusCode)
	}
}

// variableRules gives "reader" read access to everything, readwrite to
// "Damper*" variables, and hides "Secret*" variables from it entirely.
func variableRules() []authz.Rule {
	return []authz.Rule{
		{
			Name:       "reader may read everything",
			Conditions: []authz.Condition{{Type: authz.ConditionToken, Value: "reader"}},
			Match:      authz.MatchAll,
			Permission: authz.PermissionReadOnly,
			Action:     authz.ActionAllow,
		},
		{
			Name:       "reader may operate dampers",
			Conditions: []authz.Condition{{Type: authz.ConditionToken, Value: "reader"}, {Type: authz.ConditionVariable, Value: "Damper*"}},
			Match:      authz.MatchAll,
			Permission: authz.PermissionReadWrite,
			Action:     authz.ActionAllow,
		},
		{
			Name:       "nobody sees secrets",
			Conditions: []authz.Condition{{Type: authz.ConditionVariable, Value: "Secret*"}},
			Match:      authz.MatchAll,
			Action:     authz.ActionDenyNow,
		},
	}
}

// newVariableTestServer is newTestServer with a third, "Secret Setpoint"
// object, and returns the mock device so tests can change it.
func newVariableTestServer(t *testing.T, rules []authz.Rule, refresh time.Duration) (*httptest.Server, *bacnetmock.Device) {
	t.Helper()
	device := bacnetmock.NewDevice(2003)
	device.AddObject(bacnet.ObjectAnalogInput, 1, map[bacnet.PropertyIdentifier]bacnet.Value{
		bacnet.PropObjectName:   bacnet.CharStringValue("Room Temp"),
		bacnet.PropPresentValue: bacnet.RealValue(21.5),
	})
	device.AddObject(bacnet.ObjectAnalogOutput, 2, map[bacnet.PropertyIdentifier]bacnet.Value{
		bacnet.PropObjectName:   bacnet.CharStringValue("Damper Cmd"),
		bacnet.PropPresentValue: bacnet.RealValue(0),
	})
	device.AddObject(bacnet.ObjectAnalogValue, 3, map[bacnet.PropertyIdentifier]bacnet.Value{
		bacnet.PropObjectName:   bacnet.CharStringValue("Secret Setpoint"),
		bacnet.PropPresentValue: bacnet.RealValue(42),
	})
	mockServer, err := bacnetmock.Listen("127.0.0.1:0", device)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = mockServer.Close() })

	client, err := bacnet.NewClient(bacnet.ClientOptions{LocalAddr: "127.0.0.1:0", Timeout: 500 * time.Millisecond, Retries: 1})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	cfg := &config.Config{
		Devices:        map[string]string{"unit": mockServer.Addr().String()},
		Authentication: config.AuthenticationConfig{Tokens: []config.TokenConfig{readonlyToken()}},
		Bacnet:         config.BacnetConfig{Timeout: config.Duration(2 * time.Second), CacheRefresh: config.Duration(refresh)},
	}
	for _, rule := range rules {
		rc := config.RuleConfig{Name: rule.Name, Match: string(rule.Match), Permission: string(rule.Permission), Action: string(rule.Action)}
		for _, c := range rule.Conditions {
			rc.Conditions = append(rc.Conditions, config.ConditionConfig{Type: string(c.Type), Field: c.Field, Value: c.Value})
		}
		cfg.Authorization.Rules = append(cfg.Authorization.Rules, rc)
	}

	apiServer := api.NewServer(cfg, client)
	t.Cleanup(apiServer.Close)
	httpServer := httptest.NewServer(api.NewRouter(apiServer))
	t.Cleanup(httpServer.Close)
	return httpServer, device
}

func decodeJSON(t *testing.T, resp *http.Response, out any) {
	t.Helper()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatal(err)
	}
}

type listedObject struct {
	Type     string `json:"type"`
	Instance uint32 `json:"instance"`
	Name     string `json:"name"`
	Access   string `json:"access"`
}

func listObjects(t *testing.T, srv *httptest.Server) map[string]listedObject {
	t.Helper()
	resp := doRequest(t, srv, http.MethodGet, "/api/v1/devices/unit/objects", "readonly-token", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET objects: got status %d, want 200", resp.StatusCode)
	}
	var list []listedObject
	decodeJSON(t, resp, &list)
	byName := make(map[string]listedObject, len(list))
	for _, o := range list {
		byName[o.Name] = o
	}
	return byName
}

func TestObjectListFilteredByVariableAccess(t *testing.T) {
	srv, _ := newVariableTestServer(t, variableRules(), 0)
	objs := listObjects(t, srv)

	want := map[string]string{"mock-device": "readonly", "Room Temp": "readonly", "Damper Cmd": "readwrite"}
	if len(objs) != len(want) {
		t.Fatalf("got objects %v, want exactly %v", objs, want)
	}
	for name, access := range want {
		if objs[name].Access != access {
			t.Errorf("%q: got access %q, want %q", name, objs[name].Access, access)
		}
	}
	if o := objs["Damper Cmd"]; o.Type != "analog-output" || o.Instance != 2 {
		t.Errorf("Damper Cmd listed as %s/%d, want its real type analog-output/2", o.Type, o.Instance)
	}
}

func TestVariableAccessOnSingleObjects(t *testing.T) {
	srv, _ := newVariableTestServer(t, variableRules(), 0)

	var pv struct {
		Value  any    `json:"value"`
		Access string `json:"access"`
	}
	resp := doRequest(t, srv, http.MethodGet, "/api/v1/devices/unit/objects/analog-input/1/present-value", "readonly-token", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("read Room Temp: got status %d, want 200", resp.StatusCode)
	}
	decodeJSON(t, resp, &pv)
	if pv.Access != "readonly" {
		t.Errorf("Room Temp: got access %q, want readonly", pv.Access)
	}

	resp = doRequest(t, srv, http.MethodGet, "/api/v1/devices/unit/objects/analog-output/2", "readonly-token", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("summary of Damper Cmd: got status %d, want 200", resp.StatusCode)
	}
	var summary map[string]any
	decodeJSON(t, resp, &summary)
	if summary["access"] != "readwrite" {
		t.Errorf("Damper Cmd summary: got access %v, want readwrite", summary["access"])
	}

	resp = doRequest(t, srv, http.MethodGet, "/api/v1/devices/unit/objects/analog-value/3/present-value", "readonly-token", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("read Secret Setpoint: got status %d, want 403", resp.StatusCode)
	}

	body, _ := json.Marshal(map[string]any{"value": 50.0})
	resp = doRequest(t, srv, http.MethodPut, "/api/v1/devices/unit/objects/analog-output/2/present-value", "readonly-token", body)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("write Damper Cmd: got status %d, want 204", resp.StatusCode)
	}
	resp = doRequest(t, srv, http.MethodPut, "/api/v1/devices/unit/objects/analog-input/1/present-value", "readonly-token", body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("write Room Temp: got status %d, want 403", resp.StatusCode)
	}

	// An object the device doesn't list can't be named, so it's denied
	// rather than evaluated as if no variable condition matched.
	resp = doRequest(t, srv, http.MethodGet, "/api/v1/devices/unit/objects/analog-value/99/present-value", "readonly-token", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unknown object: got status %d, want 403", resp.StatusCode)
	}
}

func TestObjectListPropertyFiltered(t *testing.T) {
	srv, _ := newVariableTestServer(t, variableRules(), 0)

	var pv struct {
		Value []map[string]any `json:"value"`
	}
	resp := doRequest(t, srv, http.MethodGet, "/api/v1/devices/unit/objects/device/2003/object-list", "readonly-token", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("read object-list: got status %d, want 200", resp.StatusCode)
	}
	decodeJSON(t, resp, &pv)
	if len(pv.Value) != 3 {
		t.Fatalf("got %d object-list entries %v, want 3 (Secret Setpoint hidden)", len(pv.Value), pv.Value)
	}
	for _, v := range pv.Value {
		if v["type"] == "analog-value" {
			t.Errorf("hidden object leaked via object-list: %v", v)
		}
	}

	var count struct {
		Value any `json:"value"`
	}
	resp = doRequest(t, srv, http.MethodGet, "/api/v1/devices/unit/objects/device/2003/object-list?index=0", "readonly-token", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("read object-list[0]: got status %d, want 200", resp.StatusCode)
	}
	decodeJSON(t, resp, &count)
	if count.Value != 3.0 {
		t.Errorf("object-list[0]: got %v, want the filtered length 3", count.Value)
	}
}

func TestRulesWithoutVariableConditionApplyToAllVariables(t *testing.T) {
	srv, _ := newVariableTestServer(t, standardRules(), 0)
	objs := listObjects(t, srv)
	if len(objs) != 4 {
		t.Fatalf("got %d objects, want all 4", len(objs))
	}
	for name, o := range objs {
		if o.Access != "readonly" {
			t.Errorf("%q: got access %q, want readonly", name, o.Access)
		}
	}
}

func TestVariableCacheRefreshPicksUpRename(t *testing.T) {
	srv, device := newVariableTestServer(t, variableRules(), 100*time.Millisecond)
	if _, ok := listObjects(t, srv)["Room Temp"]; !ok {
		t.Fatal("Room Temp should be listed before the rename")
	}

	device.SetProperty(bacnet.ObjectAnalogInput, 1, bacnet.PropObjectName, bacnet.CharStringValue("Secret Room Temp"))
	deadline := time.Now().Add(3 * time.Second)
	for {
		objs := listObjects(t, srv)
		if _, ok := objs["Room Temp"]; !ok {
			if _, leaked := objs["Secret Room Temp"]; leaked {
				t.Fatal("renamed object should now be hidden")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cache never refreshed the renamed object")
		}
		time.Sleep(50 * time.Millisecond)
	}
	resp := doRequest(t, srv, http.MethodGet, "/api/v1/devices/unit/objects/analog-input/1/present-value", "readonly-token", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("read renamed object: got status %d, want 403", resp.StatusCode)
	}
}

// TestLargeDeviceVariableRules mirrors a Niagara station exposing hundreds
// of points: the object-list, and the metadata of a chunk of objects, don't
// fit in a single unsegmented APDU, so enumeration must read them piecewise.
func TestLargeDeviceVariableRules(t *testing.T) {
	const prefix = "Drivers.BacnetNetwork.BOILER_PLANT_CONTROL.points."
	rules := []authz.Rule{
		{
			Name:       "read-only access",
			Conditions: []authz.Condition{{Type: authz.ConditionToken, Value: "reader"}},
			Match:      authz.MatchAll,
			Permission: authz.PermissionReadOnly,
			Action:     authz.ActionAllow,
		},
		{
			Name: "read-write access",
			Conditions: []authz.Condition{
				{Type: authz.ConditionToken, Value: "reader"},
				{Type: authz.ConditionDevice, Value: "unit"},
				{Type: authz.ConditionVariable, Value: prefix + "TOWER FAN SS"},
			},
			Match:      authz.MatchAll,
			Permission: authz.PermissionReadWrite,
			Action:     authz.ActionAllow,
		},
	}
	srv, device := newVariableTestServer(t, rules, 0)
	for i := range 400 {
		device.AddObject(bacnet.ObjectAnalogValue, uint32(100+i), map[bacnet.PropertyIdentifier]bacnet.Value{
			bacnet.PropObjectName:   bacnet.CharStringValue(fmt.Sprintf("%sPOINT %03d", prefix, i)),
			bacnet.PropDescription:  bacnet.CharStringValue("a reasonably long description of this particular point"),
			bacnet.PropPresentValue: bacnet.RealValue(float32(i)),
		})
	}
	device.AddObject(bacnet.ObjectAnalogOutput, 900, map[bacnet.PropertyIdentifier]bacnet.Value{
		bacnet.PropObjectName:   bacnet.CharStringValue(prefix + "TOWER FAN SS"),
		bacnet.PropPresentValue: bacnet.RealValue(0),
	})

	objs := listObjects(t, srv)
	if len(objs) != 405 {
		t.Fatalf("got %d objects, want 405", len(objs))
	}
	if a := objs[prefix+"TOWER FAN SS"].Access; a != "readwrite" {
		t.Errorf("TOWER FAN SS: got access %q, want readwrite", a)
	}
	if a := objs[prefix+"POINT 123"].Access; a != "readonly" {
		t.Errorf("POINT 123: got access %q, want readonly", a)
	}

	resp := doRequest(t, srv, http.MethodGet, "/api/v1/devices/unit/objects/analog-value/150/present-value", "readonly-token", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("read a point: got status %d, want 200", resp.StatusCode)
	}
	body, _ := json.Marshal(map[string]any{"value": 1.0})
	resp = doRequest(t, srv, http.MethodPut, "/api/v1/devices/unit/objects/analog-output/900/present-value", "readonly-token", body)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("write TOWER FAN SS: got status %d, want 204", resp.StatusCode)
	}
	resp = doRequest(t, srv, http.MethodPut, "/api/v1/devices/unit/objects/analog-value/150/present-value", "readonly-token", body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("write a read-only point: got status %d, want 403", resp.StatusCode)
	}

	var pv struct {
		Value []any `json:"value"`
	}
	resp = doRequest(t, srv, http.MethodGet, "/api/v1/devices/unit/objects/device/2003/object-list", "readonly-token", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("read the full object-list: got status %d, want 200", resp.StatusCode)
	}
	decodeJSON(t, resp, &pv)
	if len(pv.Value) != 405 {
		t.Errorf("object-list: got %d entries, want 405", len(pv.Value))
	}
}

func TestEnumerationFailureSurfacesBACnetErrorToAuthenticatedCallers(t *testing.T) {
	srv, _ := newVariableTestServer(t, variableRules(), 0)
	// A literal address no BACnet device answers on.
	path := "/api/v1/devices/127.0.0.1:1/objects/analog-input/1/present-value"
	resp := doRequest(t, srv, http.MethodGet, path, "readonly-token", nil)
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Errorf("recognized token: got status %d, want 504", resp.StatusCode)
	}
	resp = doRequest(t, srv, http.MethodGet, path, "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous: got status %d, want 401", resp.StatusCode)
	}
}
