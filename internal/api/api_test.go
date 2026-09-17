package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
// against it via the given rules, and returns an httptest.Server plus the
// device's alias name for use in URLs.
func newTestServer(t *testing.T, rules []authz.Rule, tokens []config.TokenConfig, jwtSecret string) *httptest.Server {
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
	httpServer := httptest.NewServer(api.NewRouter(apiServer))
	t.Cleanup(httpServer.Close)
	return httpServer
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
	srv := newTestServer(t, standardRules(), []config.TokenConfig{readonlyToken(), readwriteToken()}, "")
	resp := doRequest(t, srv, http.MethodGet, "/api/v1/devices", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got status %d, want 401", resp.StatusCode)
	}
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Error("expected WWW-Authenticate header on 401")
	}
}

func TestUnrecognizedBearerDenied(t *testing.T) {
	srv := newTestServer(t, standardRules(), []config.TokenConfig{readonlyToken()}, "")
	resp := doRequest(t, srv, http.MethodGet, "/api/v1/devices", "garbage", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("got status %d, want 403", resp.StatusCode)
	}
}

func TestReadonlyTokenCanReadButNotWrite(t *testing.T) {
	srv := newTestServer(t, standardRules(), []config.TokenConfig{readonlyToken(), readwriteToken()}, "")

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
	srv := newTestServer(t, standardRules(), []config.TokenConfig{readonlyToken(), readwriteToken()}, "")

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
	srv := newTestServer(t, rules, []config.TokenConfig{readonlyToken()}, "")

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
	srv := newTestServer(t, rules, nil, "")
	// httptest.Server listens on 127.0.0.1, so an anonymous request from the
	// test client (also 127.0.0.1) should be allowed purely by IP.
	resp := doRequest(t, srv, http.MethodGet, "/api/v1/devices/unit/objects/analog-input/1/present-value", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200 (IP-based allow)", resp.StatusCode)
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
	srv := newTestServer(t, rules, nil, secret)

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
	srv := newTestServer(t, standardRules(), []config.TokenConfig{readonlyToken()}, "")
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
	srv := newTestServer(t, standardRules(), []config.TokenConfig{readonlyToken()}, "")
	resp := doRequest(t, srv, http.MethodGet, "/api/v1/devices", "readonly-token", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}
	var devices []struct {
		ID      string `json:"id"`
		Address string `json:"address"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&devices); err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].ID != "unit" {
		t.Fatalf("got %+v, want one device aliased 'unit'", devices)
	}
}

func TestOpenAPIAndSwaggerUIServed(t *testing.T) {
	srv := newTestServer(t, nil, nil, "")

	resp := doRequest(t, srv, http.MethodGet, "/openapi.yaml", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /openapi.yaml got status %d, want 200", resp.StatusCode)
	}

	resp = doRequest(t, srv, http.MethodGet, "/docs/index.html", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /docs/index.html got status %d, want 200", resp.StatusCode)
	}
}
