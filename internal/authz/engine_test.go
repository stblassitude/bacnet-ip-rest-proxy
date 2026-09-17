package authz

import (
	"net"
	"testing"
)

func TestImplicitDefaultDeny(t *testing.T) {
	result := Evaluate(Request{Device: "default", Operation: OperationReadProperty}, nil)
	if result.Allowed {
		t.Fatalf("expected implicit deny with no rules, got %+v", result)
	}
	if result.RuleName != "<implicit-default>" {
		t.Errorf("got rule name %q", result.RuleName)
	}
}

func TestMatchModes(t *testing.T) {
	base := Request{Device: "default", Operation: OperationReadProperty, TokenName: "alice"}
	cases := []struct {
		name       string
		conditions []Condition
		mode       MatchMode
		wantMatch  bool
	}{
		{
			name:       "all-matches-when-all-conditions-match",
			conditions: []Condition{{Type: ConditionDevice, Value: "default"}, {Type: ConditionToken, Value: "alice"}},
			mode:       MatchAll,
			wantMatch:  true,
		},
		{
			name:       "all-fails-when-one-condition-fails",
			conditions: []Condition{{Type: ConditionDevice, Value: "default"}, {Type: ConditionToken, Value: "bob"}},
			mode:       MatchAll,
			wantMatch:  false,
		},
		{
			name:       "any-matches-when-one-matches",
			conditions: []Condition{{Type: ConditionDevice, Value: "other"}, {Type: ConditionToken, Value: "alice"}},
			mode:       MatchAny,
			wantMatch:  true,
		},
		{
			name:       "any-fails-when-none-match",
			conditions: []Condition{{Type: ConditionDevice, Value: "other"}, {Type: ConditionToken, Value: "bob"}},
			mode:       MatchAny,
			wantMatch:  false,
		},
		{
			name:       "none-matches-when-none-match",
			conditions: []Condition{{Type: ConditionDevice, Value: "other"}, {Type: ConditionToken, Value: "bob"}},
			mode:       MatchNone,
			wantMatch:  true,
		},
		{
			name:       "none-fails-when-one-matches",
			conditions: []Condition{{Type: ConditionDevice, Value: "default"}, {Type: ConditionToken, Value: "bob"}},
			mode:       MatchNone,
			wantMatch:  false,
		},
		{
			name:       "not-all-matches-when-one-fails",
			conditions: []Condition{{Type: ConditionDevice, Value: "default"}, {Type: ConditionToken, Value: "bob"}},
			mode:       MatchNotAll,
			wantMatch:  true,
		},
		{
			name:       "not-all-fails-when-all-match",
			conditions: []Condition{{Type: ConditionDevice, Value: "default"}, {Type: ConditionToken, Value: "alice"}},
			mode:       MatchNotAll,
			wantMatch:  false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rules := []Rule{{Name: "r", Conditions: c.conditions, Match: c.mode, Permission: PermissionReadWrite, Action: ActionAllowNow}}
			result := Evaluate(base, rules)
			if result.Allowed != c.wantMatch {
				t.Errorf("got allowed=%v, want %v", result.Allowed, c.wantMatch)
			}
		})
	}
}

func TestActionNowShortCircuits(t *testing.T) {
	rules := []Rule{
		{Name: "deny-now", Match: MatchAll, Action: ActionDenyNow, Permission: PermissionReadOnly},
		{Name: "later-allow", Match: MatchAll, Action: ActionAllowNow, Permission: PermissionReadWrite},
	}
	result := Evaluate(Request{}, rules)
	if result.Allowed {
		t.Fatalf("deny-now should have short-circuited, got %+v", result)
	}
	if result.RuleName != "deny-now" {
		t.Errorf("got rule %q, want deny-now", result.RuleName)
	}
}

func TestLastMatchingNonNowRuleWins(t *testing.T) {
	rules := []Rule{
		{Name: "allow", Match: MatchAll, Action: ActionAllow, Permission: PermissionReadWrite},
		{Name: "deny", Match: MatchAll, Action: ActionDeny, Permission: PermissionReadOnly},
	}
	result := Evaluate(Request{}, rules)
	if result.Allowed {
		t.Fatalf("the later 'deny' rule should have overridden 'allow', got %+v", result)
	}
	if result.RuleName != "deny" {
		t.Errorf("got rule %q, want deny", result.RuleName)
	}

	// Same rules, reversed: the later 'allow' should win instead.
	rules = []Rule{
		{Name: "deny", Match: MatchAll, Action: ActionDeny, Permission: PermissionReadOnly},
		{Name: "allow", Match: MatchAll, Action: ActionAllow, Permission: PermissionReadWrite},
	}
	result = Evaluate(Request{}, rules)
	if !result.Allowed || result.Permission != PermissionReadWrite {
		t.Fatalf("the later 'allow' rule should have overridden 'deny', got %+v", result)
	}
}

func TestNonMatchingRuleIsIgnored(t *testing.T) {
	rules := []Rule{
		{Name: "irrelevant", Conditions: []Condition{{Type: ConditionDevice, Value: "other-device"}}, Match: MatchAll, Action: ActionAllowNow, Permission: PermissionReadWrite},
	}
	result := Evaluate(Request{Device: "default"}, rules)
	if result.Allowed {
		t.Fatalf("non-matching rule should be ignored, fell through to implicit deny; got %+v", result)
	}
}

func TestIPConditionWildcardAndCIDR(t *testing.T) {
	req := Request{ClientIP: net.ParseIP("192.168.3.42")}
	cases := []struct {
		value string
		want  bool
	}{
		{"192.168.3.42", true},
		{"192.168.3.99", false},
		{"192.168.3.*", true},
		{"192.168.4.*", false},
		{"*", true},
		{"192.168.3.0/24", true},
		{"10.0.0.0/8", false},
	}
	for _, c := range cases {
		rule := Rule{Conditions: []Condition{{Type: ConditionIP, Value: c.value}}, Match: MatchAll, Action: ActionAllowNow, Permission: PermissionReadOnly}
		result := Evaluate(req, []Rule{rule})
		if result.Allowed != c.want {
			t.Errorf("ip condition %q: got allowed=%v, want %v", c.value, result.Allowed, c.want)
		}
	}
}

func TestIPConditionNoClientIP(t *testing.T) {
	rule := Rule{Conditions: []Condition{{Type: ConditionIP, Value: "*"}}, Match: MatchAll, Action: ActionAllowNow, Permission: PermissionReadOnly}
	result := Evaluate(Request{}, []Rule{rule})
	if result.Allowed {
		t.Fatal("an ip condition must not match when the request carries no client IP")
	}
}

func TestJWTConditionField(t *testing.T) {
	req := Request{JWTClaims: map[string]any{
		"iss":    "id.example.com",
		"group":  "admins",
		"groups": []any{"users", "admins"},
	}}
	cases := []struct {
		field string
		value string
		want  bool
	}{
		{"iss", "id.example.com", true},
		{"iss", "other.example.com", false},
		{"iss", "*.example.com", true},
		{"group", "admins", true},
		{"groups", "admins", true}, // matches within a claim array
		{"groups", "superadmins", false},
		{"missing", "*", false}, // absent claim never matches
	}
	for _, c := range cases {
		rule := Rule{Conditions: []Condition{{Type: ConditionJWT, Field: c.field, Value: c.value}}, Match: MatchAll, Action: ActionAllowNow, Permission: PermissionReadOnly}
		result := Evaluate(req, []Rule{rule})
		if result.Allowed != c.want {
			t.Errorf("jwt field %q value %q: got allowed=%v, want %v", c.field, c.value, result.Allowed, c.want)
		}
	}
}

func TestJWTConditionNoClaims(t *testing.T) {
	rule := Rule{Conditions: []Condition{{Type: ConditionJWT, Field: "iss", Value: "*"}}, Match: MatchAll, Action: ActionAllowNow, Permission: PermissionReadOnly}
	result := Evaluate(Request{}, []Rule{rule})
	if result.Allowed {
		t.Fatal("a jwt condition must not match a request with no JWT claims")
	}
}

func TestTokenConditionRequiresRecognizedToken(t *testing.T) {
	rule := Rule{Conditions: []Condition{{Type: ConditionToken, Value: "*"}}, Match: MatchAll, Action: ActionAllowNow, Permission: PermissionReadOnly}
	result := Evaluate(Request{TokenName: ""}, []Rule{rule})
	if result.Allowed {
		t.Fatal("a token condition must not match when no opaque token was recognized")
	}
	result = Evaluate(Request{TokenName: "alice"}, []Rule{rule})
	if !result.Allowed {
		t.Fatal("a token condition with value '*' should match any recognized token")
	}
}

func TestOperationCondition(t *testing.T) {
	rule := Rule{Conditions: []Condition{{Type: ConditionOperation, Value: "write-property"}}, Match: MatchAll, Action: ActionDenyNow, Permission: PermissionReadOnly}
	allow := Rule{Match: MatchAll, Action: ActionAllow, Permission: PermissionReadWrite}
	result := Evaluate(Request{Operation: OperationWriteProperty}, []Rule{allow, rule})
	if result.Allowed {
		t.Fatalf("write-property should have been denied, got %+v", result)
	}
	result = Evaluate(Request{Operation: OperationReadProperty}, []Rule{allow, rule})
	if !result.Allowed {
		t.Fatalf("read-property should remain allowed, got %+v", result)
	}
}

// TestREADMEExampleRules exercises the two rules given verbatim as an example
// in the README, reconstructed from the (corrected, missing-dash) example
// YAML. NOTE: as literally written, rule 1's second condition
// {type: operation, value: "*"} always matches (wildcard "*" matches
// everything), which makes `match: none` impossible to satisfy — so rule 1
// can never fire, and the "wrong issuer" guard it's meant to express never
// actually runs. This test documents that real (and probably unintended)
// behavior rather than the guard's evident intent; see the accompanying
// summary for a suggested fix to the example.
func TestREADMEExampleRules(t *testing.T) {
	rules := []Rule{
		{
			Name: "ensure token has been issued by our IDP",
			Conditions: []Condition{
				{Type: ConditionJWT, Field: "iss", Value: "id.example.com"},
				{Type: ConditionOperation, Value: "*"},
			},
			Match:      MatchNone,
			Permission: PermissionReadOnly,
			Action:     ActionDenyNow,
		},
		{
			Name: "admins are allowed full access",
			Conditions: []Condition{
				{Type: ConditionJWT, Field: "group", Value: "admins"},
				{Type: ConditionOperation, Value: "*"},
			},
			Match:      MatchAll,
			Permission: PermissionReadWrite,
			Action:     ActionAllow,
		},
	}

	// Rule 1 never fires (see note above), so an admin is allowed
	// regardless of issuer.
	result := Evaluate(Request{
		Operation: OperationWriteProperty,
		JWTClaims: map[string]any{"iss": "evil.example.com", "group": "admins"},
	}, rules)
	if !result.Allowed || result.Permission != PermissionReadWrite {
		t.Fatalf("admin group should get readwrite access even with a bogus issuer (rule 1 never fires), got %+v", result)
	}

	// Non-admin, any issuer: no rule grants access, implicit deny.
	result = Evaluate(Request{
		Operation: OperationReadProperty,
		JWTClaims: map[string]any{"iss": "id.example.com", "group": "guests"},
	}, rules)
	if result.Allowed {
		t.Fatalf("non-admin should fall through to implicit deny, got %+v", result)
	}

	// A corrected version of rule 1 (dropping the tautological operation
	// condition) does enforce the issuer guard as evidently intended.
	fixedRules := []Rule{
		{
			Name:       "ensure token has been issued by our IDP",
			Conditions: []Condition{{Type: ConditionJWT, Field: "iss", Value: "id.example.com"}},
			Match:      MatchNone,
			Action:     ActionDenyNow,
		},
		rules[1],
	}
	result = Evaluate(Request{
		Operation: OperationWriteProperty,
		JWTClaims: map[string]any{"iss": "evil.example.com", "group": "admins"},
	}, fixedRules)
	if result.Allowed {
		t.Fatalf("with the tautological condition removed, a bogus issuer should be denied, got %+v", result)
	}
}
