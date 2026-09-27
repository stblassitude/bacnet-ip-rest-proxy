package api_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/api"
	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/bacnet"
	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/bacnetmock"
	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/config"
)

func TestAuthDebugLogging(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	device := bacnetmock.NewDevice(2010)
	device.AddObject(bacnet.ObjectAnalogInput, 1, map[bacnet.PropertyIdentifier]bacnet.Value{
		bacnet.PropObjectName:   bacnet.CharStringValue("Room Temp"),
		bacnet.PropPresentValue: bacnet.RealValue(21.5),
	})
	mock, _ := bacnetmock.Listen("127.0.0.1:0", device)
	t.Cleanup(func() { mock.Close() })
	client, _ := bacnet.NewClient(bacnet.ClientOptions{LocalAddr: "127.0.0.1:0", Timeout: 500 * time.Millisecond, Retries: 1})
	t.Cleanup(func() { client.Close() })

	cfg := &config.Config{
		Devices:        map[string]string{"unit": mock.Addr().String()},
		Authentication: config.AuthenticationConfig{JWTSecret: "secret"},
		Bacnet:         config.BacnetConfig{Timeout: config.Duration(2 * time.Second)},
	}
	cfg.Authorization.Rules = []config.RuleConfig{{
		Name: "admins", Match: "all", Permission: "readonly", Action: "allow",
		Conditions: []config.ConditionConfig{{Type: "jwt", Field: "groups", Value: "admins"}},
	}}
	s := api.NewServer(cfg, client)
	t.Cleanup(s.Close)
	s.SetAuthDebug(true)
	srv := httptest.NewServer(api.NewRouter(s))
	t.Cleanup(srv.Close)

	token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "dashboards", "groups": []string{"users"}, "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte("secret"))
	path := "/api/v1/devices/unit/objects/analog-input/1/present-value"
	if resp := doRequest(t, srv, http.MethodGet, path, token, nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("got status %d, want 403", resp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	req.Header.Set("Authentication", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Authentication header: got status %d, want 401", resp.StatusCode)
	}

	out := logs.String()
	t.Log("\n" + out)
	for _, want := range []string{
		`result="JWT verified with authentication.jwtSecret"`,
		`claims="{\"exp\":`,
		`rule=admins match=all applies=false`,
		`conditions="jwt.groups=\"admins\": no match (actual [\"users\"])"`,
		`allowed=false "decided by"=<implicit-default>`,
		`hint="the token was sent in an Authentication header`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %s", want)
		}
	}
	if strings.Contains(out, token) {
		t.Error("the raw token was logged")
	}
}
