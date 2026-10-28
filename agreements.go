// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type ConnectState string

const (
	ConnectConnected    ConnectState = "connected"
	ConnectSignContract ConnectState = "signContract"
	ConnectNotConnected ConnectState = "notConnected"
	ConnectDenied       ConnectState = "denied"
)

type AgreementState string

const (
	AgreementSigned        AgreementState = "signed"
	AgreementRejected      AgreementState = "rejected"
	AgreementStateTemplate AgreementState = "template"
)

type Grant struct {
	UUID       string `json:"uuid"`
	Name       string `json:"name"`
	Keypath    string `json:"keypath"`
	Permission string `json:"permission"`
}

func NewGrant(name, keypath, permission string) Grant {
	if name == "" {
		name = "Condition grant"
	}
	return Grant{UUID: NewUUID(), Name: name, Keypath: keypath, Permission: permission}
}

func (g Grant) MarshalJSON() ([]byte, error) {
	type grantJSON struct {
		UUID       string `json:"uuid"`
		Name       string `json:"name"`
		Keypath    string `json:"keypath"`
		Permission any    `json:"permission"`
	}
	permission := any(g.Permission)
	if group, other, ok := permissionBits(g.Permission); ok {
		permission = map[string]any{
			"group": group,
			"other": other,
		}
	}
	return json.Marshal(grantJSON{
		UUID:       g.UUID,
		Name:       g.Name,
		Keypath:    g.Keypath,
		Permission: permission,
	})
}

func (g *Grant) UnmarshalJSON(data []byte) error {
	var raw struct {
		UUID       string          `json:"uuid"`
		Name       string          `json:"name"`
		Keypath    string          `json:"keypath"`
		Permission json.RawMessage `json:"permission"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	g.UUID = raw.UUID
	if g.UUID == "" {
		g.UUID = NewUUID()
	}
	g.Name = raw.Name
	if g.Name == "" {
		g.Name = "Condition grant"
	}
	g.Keypath = raw.Keypath
	g.Permission = ""
	if len(raw.Permission) == 0 || string(raw.Permission) == "null" {
		return nil
	}
	if err := json.Unmarshal(raw.Permission, &g.Permission); err == nil {
		return nil
	}
	var permission struct {
		Group int `json:"group"`
		Other int `json:"other"`
	}
	if err := json.Unmarshal(raw.Permission, &permission); err != nil {
		return err
	}
	if !validPermissionBits(permission.Group) || !validPermissionBits(permission.Other) {
		return fmt.Errorf("permission bits must be between 0 and 15")
	}
	g.Permission = permissionString(permission.Group, permission.Other)
	return nil
}

func (g Grant) Grants(requested Grant) bool {
	if !grantKeypathMatches(g.Keypath, requested.Keypath) {
		return false
	}
	if requested.Permission == "" {
		return true
	}
	if strings.HasPrefix(requested.Permission, "action.invoke:") {
		return g.Permission == requested.Permission || g.Permission == "rw--" || g.Permission == "rw-" || g.Permission == "*"
	}
	if strings.HasPrefix(requested.Permission, "state.write") {
		return strings.Contains(g.Permission, "w") || g.Permission == "*"
	}
	if strings.HasPrefix(requested.Permission, "flow.read") || strings.HasPrefix(requested.Permission, "state.read") {
		return strings.Contains(g.Permission, "r") || g.Permission == "*"
	}
	for i, want := range requested.Permission {
		if want == '-' {
			continue
		}
		if i >= len(g.Permission) || rune(g.Permission[i]) != want {
			return false
		}
	}
	return true
}

func permissionBits(permission string) (int, int, bool) {
	trimmed := strings.TrimSpace(permission)
	switch len(trimmed) {
	case 3:
		group, ok := permissionTripletBits(trimmed)
		return group, 0, ok
	case 4:
		group, ok := permissionQuadBits(trimmed)
		return group, 0, ok
	case 6:
		group, ok := permissionTripletBits(trimmed[:3])
		if !ok {
			return 0, 0, false
		}
		other, ok := permissionTripletBits(trimmed[3:])
		return group, other, ok
	case 8:
		group, ok := permissionQuadBits(trimmed[:4])
		if !ok {
			return 0, 0, false
		}
		other, ok := permissionQuadBits(trimmed[4:])
		return group, other, ok
	default:
		return 0, 0, false
	}
}

func permissionTripletBits(permission string) (int, bool) {
	if len(permission) != 3 {
		return 0, false
	}
	bits := 0
	if permission[0] == 'r' {
		bits += 4
	} else if permission[0] != '-' {
		return 0, false
	}
	if permission[1] == 'w' {
		bits += 2
	} else if permission[1] != '-' {
		return 0, false
	}
	if permission[2] == 'x' {
		bits += 1
	} else if permission[2] != '-' {
		return 0, false
	}
	return bits, true
}

func permissionQuadBits(permission string) (int, bool) {
	if len(permission) != 4 {
		return 0, false
	}
	bits, ok := permissionTripletBits(permission[:3])
	if !ok {
		return 0, false
	}
	if permission[3] == 's' {
		bits += 8
	} else if permission[3] != '-' {
		return 0, false
	}
	return bits, true
}

func validPermissionBits(bits int) bool {
	return bits >= 0 && bits <= 15
}

func permissionString(group, other int) string {
	groupString := permissionQuadString(group)
	if other == 0 {
		return groupString
	}
	return groupString + permissionQuadString(other)
}

func permissionQuadString(bits int) string {
	var builder strings.Builder
	if bits&4 == 4 {
		builder.WriteByte('r')
	} else {
		builder.WriteByte('-')
	}
	if bits&2 == 2 {
		builder.WriteByte('w')
	} else {
		builder.WriteByte('-')
	}
	if bits&1 == 1 {
		builder.WriteByte('x')
	} else {
		builder.WriteByte('-')
	}
	if bits&8 == 8 {
		builder.WriteByte('s')
	} else {
		builder.WriteByte('-')
	}
	return builder.String()
}

func grantKeypathMatches(grant, requested string) bool {
	if grant == "*" || grant == requested {
		return true
	}
	if strings.HasSuffix(grant, ".*") {
		return strings.HasPrefix(requested, strings.TrimSuffix(grant, ".*")+".")
	}
	return strings.HasPrefix(requested, grant+".")
}

type Evidence map[string]any

// Condition is Swift's TypedCondition. Only "lookup" is evaluated here; any
// other type fails to decode, so a template or request carrying it is refused.
type Condition struct {
	Lookup *LookupCondition
}

// LookupCondition is Swift's LookupCondition: the value at Keypath, read as
// the requester, equals ExpectedValue. Keypaths start with "target." (the
// cell itself) or "identity."; $identity and $target are substituted.
type LookupCondition struct {
	UUID          string `json:"uuid"`
	Name          string `json:"name"`
	Keypath       string `json:"keypath"`
	ExpectedValue any    `json:"expectedValue"`
}

func NewLookupCondition(keypath string, expected any) Condition {
	return Condition{Lookup: &LookupCondition{UUID: strings.ToUpper(NewUUID()), Name: "Lookup condition", Keypath: keypath, ExpectedValue: expected}}
}

func (c Condition) MarshalJSON() ([]byte, error) {
	if c.Lookup == nil {
		return nil, fmt.Errorf("condition has no supported type")
	}
	return json.Marshal(map[string]any{"type": "lookup", "condition": c.Lookup})
}

func (c *Condition) UnmarshalJSON(data []byte) error {
	var raw struct {
		Type      string          `json:"type"`
		Condition json.RawMessage `json:"condition"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.Type != "lookup" {
		return fmt.Errorf("unsupported condition type %q", raw.Type)
	}
	var lookup struct {
		UUID          string          `json:"uuid"`
		Name          string          `json:"name"`
		Keypath       *string         `json:"keypath"`
		ExpectedValue json.RawMessage `json:"expectedValue"`
	}
	if err := json.Unmarshal(raw.Condition, &lookup); err != nil {
		return err
	}
	if lookup.Keypath == nil || len(lookup.ExpectedValue) == 0 {
		return fmt.Errorf("lookup condition needs keypath and expectedValue")
	}
	var expected any
	if err := json.Unmarshal(lookup.ExpectedValue, &expected); err != nil {
		return err
	}
	if lookup.Name == "" {
		lookup.Name = "Lookup condition"
	}
	c.Lookup = &LookupCondition{UUID: lookup.UUID, Name: lookup.Name, Keypath: *lookup.Keypath, ExpectedValue: expected}
	return nil
}

// policy is what two conditions share to be the same condition (Swift drops only uuid).
func (c Condition) policy() string {
	if c.Lookup == nil {
		return ""
	}
	data, _ := json.Marshal(map[string]any{"type": "lookup", "name": c.Lookup.Name, "keypath": c.Lookup.Keypath, "expectedValue": NormalizeJSON(c.Lookup.ExpectedValue)})
	return string(data)
}

// Enforcing is Swift's isAuthorizationEnforcingCondition: only lookups on the target or a resolved cell.
func (c Condition) Enforcing() bool {
	if c.Lookup == nil {
		return false
	}
	keypath := strings.TrimSpace(c.Lookup.Keypath)
	return strings.HasPrefix(keypath, "target.") || strings.HasPrefix(keypath, "resolve.")
}

// Met reads the keypath as the requester and compares it with ExpectedValue.
func (c Condition) Met(ctx context.Context, target Meddle, requester *Identity) bool {
	if c.Lookup == nil || requester == nil {
		return false
	}
	keypath := strings.ReplaceAll(c.Lookup.Keypath, "$identity", requester.UUID)
	contextKey, child, found := strings.Cut(keypath, ".")
	if !found || child == "" {
		return false
	}
	var value any
	var err error
	switch contextKey {
	case "target":
		if target == nil {
			return false
		}
		value, err = target.Get(withEvaluatingConditions(ctx), child, requester)
	default:
		return false
	}
	if err != nil {
		return false
	}
	got, _ := json.Marshal(NormalizeJSON(value))
	want, _ := json.Marshal(NormalizeJSON(c.Lookup.ExpectedValue))
	return string(got) == string(want)
}

type evaluatingConditionsKey struct{}

// While conditions are evaluated, contracts give no access, so a condition can
// never be met by the contract it decides on (as Swift).
func withEvaluatingConditions(ctx context.Context) context.Context {
	return context.WithValue(ctx, evaluatingConditionsKey{}, true)
}

func evaluatingConditions(ctx context.Context) bool {
	value, _ := ctx.Value(evaluatingConditionsKey{}).(bool)
	return value
}

func conditionsMatch(a, b []Condition) bool {
	if len(a) != len(b) {
		return false
	}
	left, right := make([]string, len(a)), make([]string, len(b))
	for i := range a {
		left[i], right[i] = a[i].policy(), b[i].policy()
		if left[i] == "" || right[i] == "" {
			return false
		}
	}
	sort.Strings(left)
	sort.Strings(right)
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

// CoversExactly is Swift's Grant.granted: the same keypath, and every requested bit held.
func (g Grant) CoversExactly(requested Grant) bool {
	if g.Keypath != requested.Keypath {
		return false
	}
	group, other, ok := permissionBits(g.Permission)
	wantGroup, wantOther, wantOK := permissionBits(requested.Permission)
	if !ok || !wantOK || wantGroup == 0 || group&wantGroup != wantGroup {
		return false
	}
	return wantOther == 0 || other&wantOther == wantOther
}

type Agreement struct {
	UUID        string         `json:"uuid"`
	Name        string         `json:"name"`
	State       AgreementState `json:"state"`
	Owner       *Identity      `json:"owner"`
	Signatories []*Identity    `json:"signatories"`
	Conditions  []Condition    `json:"conditions,omitempty"`
	Grants      []Grant        `json:"grants"`
	Duration    int            `json:"duration"`
	Timestamp   int64          `json:"timestamp,omitempty"`
}

func NewAgreement(owner *Identity) Agreement {
	if owner == nil {
		owner = NewIdentity("Cell owner", "")
	}
	return Agreement{
		UUID:        NewUUID(),
		Name:        "Contract name here",
		State:       AgreementStateTemplate,
		Owner:       owner,
		Signatories: []*Identity{owner},
		Grants: []Grant{
			NewGrant("test grant", "identity.displayName", "r--"),
			NewGrant("Feed grant", "feed", "r---"),
		},
		Duration: 60 * 60 * 24 * 365,
	}
}

func (a *Agreement) AddGrant(permission, keypath string) {
	a.Grants = append(a.Grants, NewGrant("", keypath, permission))
}

func (a Agreement) CheckGrant(requested Grant) bool {
	for _, grant := range a.Grants {
		if grant.Grants(requested) {
			return true
		}
	}
	return false
}

type ConnectContext struct {
	Requester             *Identity `json:"requester,omitempty"`
	RequestedCapabilities []string  `json:"requestedCapabilities,omitempty"`
	Purpose               string    `json:"purpose,omitempty"`
	Evidence              Evidence  `json:"evidence,omitempty"`
}

type ConnectionStatus struct {
	Label string       `json:"label"`
	State ConnectState `json:"state"`
}
