// Package config loads and validates the proxy's YAML configuration file,
// and translates it into the types internal/auth and internal/authz expect.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/auth"
	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/authz"
)

// Duration wraps time.Duration to support YAML values like "3s" or "500ms".
type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		// A *yaml.TypeError keeps the line number in the decoder's report.
		return &yaml.TypeError{Errors: []string{fmt.Sprintf("line %d: invalid duration %q (use e.g. 3s, 500ms, 1m)", value.Line, s)}}
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) AsDuration() time.Duration { return time.Duration(d) }

// Config is the top-level shape of the proxy's YAML configuration file.
type Config struct {
	Listen         ListenConfig         `yaml:"listen"`
	Bacnet         BacnetConfig         `yaml:"bacnet"`
	Authentication AuthenticationConfig `yaml:"authentication"`
	Authorization  AuthorizationConfig  `yaml:"authorization"`
	Devices        map[string]string    `yaml:"devices"`
}

type ListenConfig struct {
	// Address is the "host:port" the HTTP(S) server listens on.
	Address string    `yaml:"address"`
	TLS     TLSConfig `yaml:"tls"`
	// TrustedProxies is a list of IPs/CIDRs allowed to supply the
	// connecting client's real IP via X-Forwarded-For/X-Real-IP. Requests
	// arriving from any other address have those headers ignored, so a
	// client can't spoof its way past an `ip` authorization condition by
	// just setting the header itself. Empty (the default) means no peer
	// is trusted and the headers are always ignored.
	TrustedProxies []string `yaml:"trustedProxies"`
}

type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"certFile"`
	KeyFile  string `yaml:"keyFile"`
}

type BacnetConfig struct {
	// LocalPort is the local UDP port the proxy binds to talk to BACnet/IP
	// devices. 0 (the default) picks an ephemeral port, which is fine since
	// this proxy only ever initiates unicast requests.
	LocalPort int      `yaml:"localPort"`
	Timeout   Duration `yaml:"timeout"`
	Retries   int      `yaml:"retries"`
	// CacheRefresh is how often each device's variables (object-list plus
	// per-object name/description/units) are re-enumerated in the
	// background. Authorization of `variable` conditions and object
	// listings are served from this cache.
	CacheRefresh Duration `yaml:"cacheRefresh"`
}

type AuthenticationConfig struct {
	Tokens []TokenConfig `yaml:"tokens"`
	// JWTSecret is the HMAC-SHA256 shared secret used to verify JWT
	// bearers. See README for why this is the chosen verification scheme.
	JWTSecret string `yaml:"jwtSecret"`
}

type TokenConfig struct {
	Name  string `yaml:"name"`
	Token string `yaml:"token"`
}

type AuthorizationConfig struct {
	Rules []RuleConfig `yaml:"rules"`
}

type RuleConfig struct {
	Name       string            `yaml:"name"`
	Conditions []ConditionConfig `yaml:"conditions"`
	Match      string            `yaml:"match"`
	Permission string            `yaml:"permission"`
	Action     string            `yaml:"action"`
}

type ConditionConfig struct {
	Type  string `yaml:"type"`
	Field string `yaml:"field"`
	Value string `yaml:"value"`
}

// Load reads and parses the YAML file at path, applies defaults, and
// validates it.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // a misspelt key is an error, not silently ignored
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("config errors:\n%w", yamlErrors(path, err))
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		// The file parsed, so this can't fail; it's only used to map each
		// error's setting path back to a line.
		var root yaml.Node
		_ = yaml.Unmarshal(data, &root)
		return nil, fmt.Errorf("config errors:\n%w", withLines(path, &root, err))
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Listen.Address == "" {
		c.Listen.Address = ":8443"
	}
	if c.Bacnet.Timeout == 0 {
		c.Bacnet.Timeout = Duration(3 * time.Second)
	}
	if c.Bacnet.Retries == 0 {
		c.Bacnet.Retries = 3
	}
	if c.Bacnet.CacheRefresh == 0 {
		c.Bacnet.CacheRefresh = Duration(60 * time.Second)
	}
}

// Validate checks the configuration for internal consistency: valid
// match/action/condition-type enum values, TLS file presence, and duplicate
// token/device names. It reports every problem found, each as a *FieldError
// naming the offending setting, combined with errors.Join.
func (c *Config) Validate() error {
	var errs []error
	if c.Listen.TLS.Enabled {
		if c.Listen.TLS.CertFile == "" {
			errs = append(errs, fieldErrorf("listen.tls.certFile", "required when listen.tls.enabled is true"))
		}
		if c.Listen.TLS.KeyFile == "" {
			errs = append(errs, fieldErrorf("listen.tls.keyFile", "required when listen.tls.enabled is true"))
		}
	}

	if c.Bacnet.CacheRefresh < 0 {
		errs = append(errs, fieldErrorf("bacnet.cacheRefresh", "must be positive"))
	}

	for i, p := range c.Listen.TrustedProxies {
		if _, err := parseIPOrCIDR(p); err != nil {
			errs = append(errs, fieldErrorf(fmt.Sprintf("listen.trustedProxies[%d]", i), "%v", err))
		}
	}

	seenTokenNames := make(map[string]bool, len(c.Authentication.Tokens))
	for i, tok := range c.Authentication.Tokens {
		path := fmt.Sprintf("authentication.tokens[%d]", i)
		if tok.Name == "" {
			errs = append(errs, fieldErrorf(path+".name", "required"))
		}
		if tok.Token == "" {
			errs = append(errs, fieldErrorf(path+".token", "required"))
		}
		if tok.Name != "" && seenTokenNames[tok.Name] {
			errs = append(errs, fieldErrorf(path+".name", "duplicate token name %q", tok.Name))
		}
		seenTokenNames[tok.Name] = true
	}

	for i, rule := range c.Authorization.Rules {
		errs = append(errs, rule.validate(fmt.Sprintf("authorization.rules[%d]", i))...)
	}
	return errors.Join(errs...)
}

func (r RuleConfig) validate(path string) []error {
	var errs []error
	switch authz.MatchMode(r.Match) {
	case authz.MatchNone, authz.MatchNotAll, authz.MatchAny, authz.MatchAll:
	default:
		errs = append(errs, fieldErrorf(path+".match", "invalid match %q (expected one of: all, any, none, not-all)", r.Match))
	}
	switch authz.Action(r.Action) {
	case authz.ActionAllowNow, authz.ActionDenyNow, authz.ActionAllow, authz.ActionDeny:
	default:
		errs = append(errs, fieldErrorf(path+".action", "invalid action %q (expected one of: allow, allow-now, deny, deny-now)", r.Action))
	}
	isAllow := r.Action == string(authz.ActionAllow) || r.Action == string(authz.ActionAllowNow)
	if isAllow {
		switch authz.Permission(r.Permission) {
		case authz.PermissionReadOnly, authz.PermissionReadWrite:
		case "":
			errs = append(errs, fieldErrorf(path+".permission", "required for an allow rule (readonly or readwrite)"))
		default:
			errs = append(errs, fieldErrorf(path+".permission", "invalid permission %q (expected readonly or readwrite)", r.Permission))
		}
	}
	for i, c := range r.Conditions {
		cpath := fmt.Sprintf("%s.conditions[%d]", path, i)
		switch authz.ConditionType(c.Type) {
		case authz.ConditionDevice, authz.ConditionIP, authz.ConditionOperation, authz.ConditionToken, authz.ConditionVariable:
		case authz.ConditionJWT:
			if c.Field == "" {
				errs = append(errs, fieldErrorf(cpath+".field", "required for a jwt condition"))
			}
		default:
			errs = append(errs, fieldErrorf(cpath+".type", "invalid condition type %q (expected one of: device, ip, jwt, operation, token, variable)", c.Type))
		}
	}
	return errs
}

// AuthTokens converts authentication.tokens into the form internal/auth
// expects.
func (c *Config) AuthTokens() []auth.Token {
	tokens := make([]auth.Token, 0, len(c.Authentication.Tokens))
	for _, t := range c.Authentication.Tokens {
		tokens = append(tokens, auth.Token{Name: t.Name, Value: t.Token})
	}
	return tokens
}

// AuthzRules converts authorization.rules into the form internal/authz
// expects. Config.Validate must have been called first.
func (c *Config) AuthzRules() []authz.Rule {
	rules := make([]authz.Rule, 0, len(c.Authorization.Rules))
	for _, r := range c.Authorization.Rules {
		conditions := make([]authz.Condition, 0, len(r.Conditions))
		for _, cond := range r.Conditions {
			conditions = append(conditions, authz.Condition{
				Type:  authz.ConditionType(cond.Type),
				Field: cond.Field,
				Value: cond.Value,
			})
		}
		rules = append(rules, authz.Rule{
			Name:       r.Name,
			Conditions: conditions,
			Match:      authz.MatchMode(r.Match),
			Permission: authz.Permission(r.Permission),
			Action:     authz.Action(r.Action),
		})
	}
	return rules
}

// ResolveDevice maps a caller-supplied device identifier (a configured
// alias, or a literal hostname/IP) to the host:port to dial.
func (c *Config) ResolveDevice(id string) string {
	if addr, ok := c.Devices[id]; ok {
		return addr
	}
	return id
}

// parseIPOrCIDR parses s as CIDR notation, or as a single IP (matched
// exactly, as a /32 or /128).
func parseIPOrCIDR(s string) (*net.IPNet, error) {
	if strings.Contains(s, "/") {
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", s, err)
		}
		return ipnet, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP %q", s)
	}
	if ip4 := ip.To4(); ip4 != nil {
		return &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}

// TrustedProxyNets parses listen.trustedProxies into matchable networks.
// Config.Validate must have been called first.
func (c *Config) TrustedProxyNets() []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(c.Listen.TrustedProxies))
	for _, p := range c.Listen.TrustedProxies {
		if ipnet, err := parseIPOrCIDR(p); err == nil {
			nets = append(nets, ipnet)
		}
	}
	return nets
}
