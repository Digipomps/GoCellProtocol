// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

import (
	"context"
	"encoding/json"
	"strings"
	"time"
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
	if len(trimmed) == 4 && strings.HasSuffix(trimmed, "-") {
		trimmed = trimmed[:3]
	}
	if len(trimmed) == 3 {
		group, ok := permissionTripletBits(trimmed)
		return group, 0, ok
	}
	if len(trimmed) == 6 {
		group, ok := permissionTripletBits(trimmed[:3])
		if !ok {
			return 0, 0, false
		}
		other, ok := permissionTripletBits(trimmed[3:])
		return group, other, ok
	}
	return 0, 0, false
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

func permissionString(group, other int) string {
	groupString := permissionTripletString(group)
	if other == 0 {
		return groupString
	}
	return groupString + permissionTripletString(other)
}

func permissionTripletString(bits int) string {
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

type Condition struct {
	Type             string     `json:"type"`
	Domain           string     `json:"domain,omitempty"`
	Purpose          string     `json:"purpose,omitempty"`
	RequiredEvidence []string   `json:"requiredEvidence,omitempty"`
	NotBefore        *time.Time `json:"notBefore,omitempty"`
	ExpiresAt        *time.Time `json:"expiresAt,omitempty"`
}

func (c Condition) Evaluate(ctx context.Context, requester *Identity, purpose string, evidence Evidence) bool {
	_ = ctx
	now := time.Now()
	if c.NotBefore != nil && now.Before(*c.NotBefore) {
		return false
	}
	if c.ExpiresAt != nil && now.After(*c.ExpiresAt) {
		return false
	}
	if c.Domain != "" && (requester == nil || requester.Domain != c.Domain) {
		return false
	}
	if c.Purpose != "" && c.Purpose != purpose {
		return false
	}
	for _, key := range c.RequiredEvidence {
		if evidence == nil {
			return false
		}
		if _, ok := evidence[key]; !ok {
			return false
		}
	}
	return true
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

func (a Agreement) ConditionsSatisfied(ctx context.Context, requester *Identity, purpose string, evidence Evidence) bool {
	for _, condition := range a.Conditions {
		if !condition.Evaluate(ctx, requester, purpose, evidence) {
			return false
		}
	}
	return true
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
