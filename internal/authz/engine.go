package authz

import (
	"encoding/json"
	"fmt"
	"net"
	"path"
	"strings"
)

// Request is the information about an incoming API call that conditions are
// evaluated against.
type Request struct {
	Device    string
	ClientIP  net.IP
	Operation Operation
	// TokenName is the configured name of the opaque bearer token that
	// matched authentication.tokens, or "" if the bearer wasn't a
	// recognized opaque token.
	TokenName string
	// JWTClaims holds the parsed claims of a validated JWT bearer, or nil
	// if the bearer wasn't a valid JWT.
	JWTClaims map[string]any
	// ObjectName is the object-name property of the BACnet object the
	// request targets, as reported by the device, or "" if the request
	// doesn't target a single object.
	ObjectName string
}

// Result is the outcome of evaluating a Request against a rule set.
type Result struct {
	Allowed    bool
	Permission Permission
	// RuleName is the name of the rule that produced this result, or
	// "<implicit-default>" if no rule matched.
	RuleName string
}

// Evaluate runs req through rules in order, per the README's algorithm:
// every matching rule overwrites a provisional (permission, action) result;
// an "-now" action stops evaluation immediately; otherwise all rules are
// checked and the last matching rule's result wins. With no matching rules
// at all, the implicit default is deny.
func Evaluate(req Request, rules []Rule) Result {
	return evaluate(req, rules, nil)
}

// RuleTrace describes how one rule fared in an evaluation, for debugging.
type RuleTrace struct {
	Rule       Rule
	Conditions []ConditionTrace
	// Applies reports whether the rule's conditions matched per its match
	// mode, so that it updated the provisional result.
	Applies bool
}

// ConditionTrace describes one condition's evaluation.
type ConditionTrace struct {
	Condition Condition
	Matched   bool
	// Actual is the request value the condition was compared with.
	Actual string
}

// Explain evaluates req exactly like Evaluate, and also returns a trace of
// every rule it looked at (rules after a decisive -now rule aren't).
func Explain(req Request, rules []Rule) (Result, []RuleTrace) {
	var trace []RuleTrace
	result := evaluate(req, rules, &trace)
	return result, trace
}

func evaluate(req Request, rules []Rule, trace *[]RuleTrace) Result {
	result := Result{Allowed: false, RuleName: "<implicit-default>"}
	for _, rule := range rules {
		applies := evaluateConditions(rule, req, trace)
		if !applies {
			continue
		}
		result = Result{
			Allowed:    rule.Action.isAllow(),
			Permission: rule.Permission,
			RuleName:   rule.Name,
		}
		if rule.Action.isNow() {
			break
		}
	}
	return result
}

func evaluateConditions(rule Rule, req Request, trace *[]RuleTrace) bool {
	conditions, mode := rule.Conditions, rule.Match
	var rt *RuleTrace
	if trace != nil {
		*trace = append(*trace, RuleTrace{Rule: rule})
		rt = &(*trace)[len(*trace)-1]
	}
	matched := 0
	for _, c := range conditions {
		m := matchCondition(c, req)
		if m {
			matched++
		}
		if rt != nil {
			rt.Conditions = append(rt.Conditions, ConditionTrace{Condition: c, Matched: m, Actual: actualValue(c, req)})
		}
	}
	applies := modeApplies(mode, matched, len(conditions))
	if rt != nil {
		rt.Applies = applies
	}
	return applies
}

func modeApplies(mode MatchMode, matched, total int) bool {
	switch mode {
	case MatchAll:
		return matched == total
	case MatchAny:
		return matched > 0
	case MatchNone:
		return matched == 0
	case MatchNotAll:
		return matched < total
	default:
		return false
	}
}

func matchCondition(c Condition, req Request) bool {
	switch c.Type {
	case ConditionDevice:
		return matchWildcard(c.Value, req.Device)
	case ConditionIP:
		if req.ClientIP == nil {
			return false
		}
		if strings.Contains(c.Value, "/") {
			_, ipnet, err := net.ParseCIDR(c.Value)
			if err != nil {
				return false
			}
			return ipnet.Contains(req.ClientIP)
		}
		return matchWildcard(c.Value, req.ClientIP.String())
	case ConditionJWT:
		if req.JWTClaims == nil {
			return false
		}
		claim, ok := req.JWTClaims[c.Field]
		if !ok {
			return false
		}
		return matchClaimValue(claim, c.Value)
	case ConditionOperation:
		return matchWildcard(c.Value, string(req.Operation))
	case ConditionToken:
		if req.TokenName == "" {
			return false
		}
		return matchWildcard(c.Value, req.TokenName)
	case ConditionVariable:
		if req.ObjectName == "" {
			return false
		}
		return matchWildcard(c.Value, req.ObjectName)
	default:
		return false
	}
}

// actualValue describes the request value condition c is compared with.
func actualValue(c Condition, req Request) string {
	switch c.Type {
	case ConditionDevice:
		if req.Device == "" {
			return "<no device>"
		}
		return req.Device
	case ConditionIP:
		if req.ClientIP == nil {
			return "<unknown>"
		}
		return req.ClientIP.String()
	case ConditionJWT:
		if req.JWTClaims == nil {
			return "<no verified JWT>"
		}
		claim, ok := req.JWTClaims[c.Field]
		if !ok {
			return fmt.Sprintf("<claim %q absent>", c.Field)
		}
		if b, err := json.Marshal(claim); err == nil {
			return string(b)
		}
		return fmt.Sprintf("%v", claim)
	case ConditionOperation:
		return string(req.Operation)
	case ConditionToken:
		if req.TokenName == "" {
			return "<no configured token>"
		}
		return req.TokenName
	case ConditionVariable:
		if req.ObjectName == "" {
			return "<not about a single variable>"
		}
		return req.ObjectName
	default:
		return "<unknown condition type>"
	}
}

// matchClaimValue compares a decoded JWT claim (string, or an array of
// strings, as is common for e.g. "groups"/"roles" claims) against pattern.
func matchClaimValue(claim any, pattern string) bool {
	switch v := claim.(type) {
	case string:
		return matchWildcard(pattern, v)
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && matchWildcard(pattern, s) {
				return true
			}
		}
		return false
	default:
		return matchWildcard(pattern, fmt.Sprintf("%v", v))
	}
}

// matchWildcard supports "*" (match everything) and glob-style patterns
// (e.g. "foo*", "*bar") via path.Match; a pattern with no wildcard
// characters requires an exact match.
func matchWildcard(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	ok, err := path.Match(pattern, value)
	return err == nil && ok
}
