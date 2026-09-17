package authz

import (
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
	result := Result{Allowed: false, RuleName: "<implicit-default>"}
	for _, rule := range rules {
		if !evaluateConditions(rule.Conditions, rule.Match, req) {
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

func evaluateConditions(conditions []Condition, mode MatchMode, req Request) bool {
	matched := 0
	for _, c := range conditions {
		if matchCondition(c, req) {
			matched++
		}
	}
	total := len(conditions)
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
	default:
		return false
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
