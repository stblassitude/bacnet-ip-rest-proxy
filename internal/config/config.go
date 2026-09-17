// Package config loads and validates the proxy's YAML configuration file,
// and translates it into the types internal/auth and internal/authz expect.
package config

import (
	"fmt"
	"os"
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
		return fmt.Errorf("invalid duration %q: %w", s, err)
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
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
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
}

// Validate checks the configuration for internal consistency: valid
// match/action/condition-type enum values, TLS file presence, and duplicate
// token/device names.
func (c *Config) Validate() error {
	if c.Listen.TLS.Enabled {
		if c.Listen.TLS.CertFile == "" || c.Listen.TLS.KeyFile == "" {
			return fmt.Errorf("listen.tls.enabled requires certFile and keyFile")
		}
	}

	seenTokenNames := make(map[string]bool, len(c.Authentication.Tokens))
	for _, tok := range c.Authentication.Tokens {
		if tok.Name == "" || tok.Token == "" {
			return fmt.Errorf("authentication.tokens: each entry needs a name and a token")
		}
		if seenTokenNames[tok.Name] {
			return fmt.Errorf("authentication.tokens: duplicate name %q", tok.Name)
		}
		seenTokenNames[tok.Name] = true
	}

	for i, rule := range c.Authorization.Rules {
		if err := rule.validate(); err != nil {
			return fmt.Errorf("authorization.rules[%d] (%s): %w", i, rule.Name, err)
		}
	}
	return nil
}

func (r RuleConfig) validate() error {
	switch authz.MatchMode(r.Match) {
	case authz.MatchNone, authz.MatchNotAll, authz.MatchAny, authz.MatchAll:
	default:
		return fmt.Errorf("invalid match %q", r.Match)
	}
	switch authz.Action(r.Action) {
	case authz.ActionAllowNow, authz.ActionDenyNow, authz.ActionAllow, authz.ActionDeny:
	default:
		return fmt.Errorf("invalid action %q", r.Action)
	}
	isAllow := r.Action == string(authz.ActionAllow) || r.Action == string(authz.ActionAllowNow)
	if isAllow {
		switch authz.Permission(r.Permission) {
		case authz.PermissionReadOnly, authz.PermissionReadWrite:
		default:
			return fmt.Errorf("invalid permission %q for an allow rule", r.Permission)
		}
	}
	for _, c := range r.Conditions {
		switch authz.ConditionType(c.Type) {
		case authz.ConditionDevice, authz.ConditionIP, authz.ConditionOperation, authz.ConditionToken:
		case authz.ConditionJWT:
			if c.Field == "" {
				return fmt.Errorf("jwt condition requires a field")
			}
		default:
			return fmt.Errorf("invalid condition type %q", c.Type)
		}
	}
	return nil
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
