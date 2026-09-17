// Package authz implements the rule-based authorization engine described in
// the project README: an ordered list of rules, each with conditions, a
// match mode, a permission, and an action, evaluated against a request to
// produce a final allow/deny decision and permission level.
package authz

// Permission is the access level a matching rule grants.
type Permission string

const (
	PermissionReadOnly  Permission = "readonly"
	PermissionReadWrite Permission = "readwrite"
)

// MatchMode controls how a rule's conditions combine (README "matching").
type MatchMode string

const (
	MatchNone   MatchMode = "none"
	MatchNotAll MatchMode = "not-all"
	MatchAny    MatchMode = "any"
	MatchAll    MatchMode = "all"
)

// Action determines what a matching rule does to the provisional result
// (README "action").
type Action string

const (
	ActionAllowNow Action = "allow-now"
	ActionDenyNow  Action = "deny-now"
	ActionAllow    Action = "allow"
	ActionDeny     Action = "deny"
)

func (a Action) isAllow() bool { return a == ActionAllow || a == ActionAllowNow }
func (a Action) isNow() bool   { return a == ActionAllowNow || a == ActionDenyNow }

// ConditionType selects what field of a Request a Condition matches against.
type ConditionType string

const (
	ConditionDevice    ConditionType = "device"
	ConditionIP        ConditionType = "ip"
	ConditionJWT       ConditionType = "jwt"
	ConditionOperation ConditionType = "operation"
	ConditionToken     ConditionType = "token"
)

// Condition is a single type/value (or type/field/value, for jwt) test.
// Value supports "*" and glob-style wildcards for string types, and
// additionally CIDR notation for the ip type.
type Condition struct {
	Type  ConditionType
	Field string // only meaningful for ConditionJWT: the JWT claim name
	Value string
}

// Rule is one entry in the authorization.rules configuration list.
type Rule struct {
	Name       string
	Conditions []Condition
	Match      MatchMode
	Permission Permission
	Action     Action
}

// Operation identifies which BACnet service (or synthetic proxy operation)
// a request maps to, for matching against ConditionOperation.
type Operation string

const (
	OperationWhoIs                Operation = "who-is"
	OperationReadProperty         Operation = "read-property"
	OperationReadPropertyMultiple Operation = "read-property-multiple"
	OperationWriteProperty        Operation = "write-property"
	OperationListDevices          Operation = "list-devices"
)

// RequiredPermission returns the minimum Permission a request for op needs.
func (op Operation) RequiredPermission() Permission {
	if op == OperationWriteProperty {
		return PermissionReadWrite
	}
	return PermissionReadOnly
}
