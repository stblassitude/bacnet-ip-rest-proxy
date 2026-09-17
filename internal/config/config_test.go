package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/authz"
)

const sampleYAML = `
listen:
  address: "0.0.0.0:8443"
  tls:
    enabled: true
    certFile: /etc/proxy/cert.pem
    keyFile: /etc/proxy/key.pem

bacnet:
  localPort: 47809
  timeout: 2s
  retries: 5

authentication:
  tokens:
    - name: ops
      token: opaque-ops-token
  jwtSecret: shared-secret

authorization:
  rules:
    - name: admins are allowed full access
      conditions:
        - type: jwt
          field: group
          value: admins
      match: all
      permission: readwrite
      action: allow

devices:
  default: 192.168.3.2
  integra: integra-controller.example.com
`

func writeTemp(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadValidConfig(t *testing.T) {
	cfg, err := Load(writeTemp(t, sampleYAML))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Listen.Address != "0.0.0.0:8443" {
		t.Errorf("got address %q", cfg.Listen.Address)
	}
	if cfg.Bacnet.Timeout.AsDuration().Seconds() != 2 {
		t.Errorf("got timeout %v", cfg.Bacnet.Timeout.AsDuration())
	}
	if cfg.ResolveDevice("default") != "192.168.3.2" {
		t.Errorf("got resolved device %q", cfg.ResolveDevice("default"))
	}
	if cfg.ResolveDevice("192.168.9.9") != "192.168.9.9" {
		t.Errorf("literal address should pass through unchanged, got %q", cfg.ResolveDevice("192.168.9.9"))
	}

	tokens := cfg.AuthTokens()
	if len(tokens) != 1 || tokens[0].Name != "ops" || tokens[0].Value != "opaque-ops-token" {
		t.Errorf("got tokens %+v", tokens)
	}

	rules := cfg.AuthzRules()
	if len(rules) != 1 || rules[0].Permission != authz.PermissionReadWrite || rules[0].Action != authz.ActionAllow {
		t.Errorf("got rules %+v", rules)
	}
}

func TestLoadAppliesDefaults(t *testing.T) {
	cfg, err := Load(writeTemp(t, "devices:\n  default: 10.0.0.1\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Listen.Address != ":8443" {
		t.Errorf("got default address %q", cfg.Listen.Address)
	}
	if cfg.Bacnet.Timeout.AsDuration().Seconds() != 3 {
		t.Errorf("got default timeout %v", cfg.Bacnet.Timeout.AsDuration())
	}
	if cfg.Bacnet.Retries != 3 {
		t.Errorf("got default retries %d", cfg.Bacnet.Retries)
	}
}

func TestLoadRejectsTLSMissingFiles(t *testing.T) {
	_, err := Load(writeTemp(t, "listen:\n  tls:\n    enabled: true\n"))
	if err == nil {
		t.Fatal("expected an error for enabled TLS with no cert/key files")
	}
}

func TestLoadRejectsInvalidMatchMode(t *testing.T) {
	yaml := `
authorization:
  rules:
    - name: bad
      match: sometimes
      action: allow
      permission: readonly
`
	_, err := Load(writeTemp(t, yaml))
	if err == nil {
		t.Fatal("expected an error for invalid match mode")
	}
}

func TestLoadRejectsInvalidAction(t *testing.T) {
	yaml := `
authorization:
  rules:
    - name: bad
      match: all
      action: maybe
      permission: readonly
`
	_, err := Load(writeTemp(t, yaml))
	if err == nil {
		t.Fatal("expected an error for invalid action")
	}
}

func TestLoadRejectsInvalidPermissionOnAllowRule(t *testing.T) {
	yaml := `
authorization:
  rules:
    - name: bad
      match: all
      action: allow
      permission: none
`
	_, err := Load(writeTemp(t, yaml))
	if err == nil {
		t.Fatal("expected an error for invalid permission on an allow rule")
	}
}

func TestLoadAllowsAnyPermissionOnDenyRule(t *testing.T) {
	// Permission is irrelevant for deny rules; the README's own example
	// uses "none", which isn't in {readonly, readwrite}.
	yaml := `
authorization:
  rules:
    - name: deny-guard
      match: none
      action: deny-now
      permission: none
`
	if _, err := Load(writeTemp(t, yaml)); err != nil {
		t.Fatalf("deny rule with non-standard permission should be accepted: %v", err)
	}
}

func TestLoadRejectsJWTConditionWithoutField(t *testing.T) {
	yaml := `
authorization:
  rules:
    - name: bad
      conditions:
        - type: jwt
          value: admins
      match: all
      action: allow
      permission: readonly
`
	_, err := Load(writeTemp(t, yaml))
	if err == nil {
		t.Fatal("expected an error for a jwt condition missing a field")
	}
}

func TestLoadRejectsDuplicateTokenNames(t *testing.T) {
	yaml := `
authentication:
  tokens:
    - name: ops
      token: aaa
    - name: ops
      token: bbb
`
	_, err := Load(writeTemp(t, yaml))
	if err == nil {
		t.Fatal("expected an error for duplicate token names")
	}
}
