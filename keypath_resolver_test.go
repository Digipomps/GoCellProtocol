// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

import (
	"context"
	"testing"
)

func TestKeypathSupportsAppendIndexesAndMatchTokens(t *testing.T) {
	root := map[string]any{}
	if err := SetKeyPath(root, "people[+].name", "Ada"); err != nil {
		t.Fatal(err)
	}
	if err := SetKeyPath(root, "people[0].age", 42); err != nil {
		t.Fatal(err)
	}
	if err := SetKeyPath(root, "people[id=bob].name", "Bob"); err != nil {
		t.Fatal(err)
	}
	if err := SetKeyPath(root, "people[id=bob].age", 39); err != nil {
		t.Fatal(err)
	}
	if got, _ := GetKeyPath(root, "people[0].name"); got != "Ada" {
		t.Fatalf("people[0].name = %#v", got)
	}
	if got, _ := GetKeyPath(root, "people[id=bob].age"); got != 39 {
		t.Fatalf("people[id=bob].age = %#v", got)
	}
}

func TestResolverScopesAndRemoteRouteLayouts(t *testing.T) {
	ctx := context.Background()
	vault := NewInMemoryIdentityVault()
	alice, _ := vault.Identity(ctx, "alice", true)
	bob, _ := vault.Identity(ctx, "bob", true)
	resolver := NewCellResolver()
	factory := func(ctx context.Context, owner *Identity) (CellProtocol, error) {
		return NewGeneralCell(owner, "Cell"), nil
	}
	if err := resolver.RegisterNamedEmitCell(ctx, "Template", nil, RegisterOptions{Factory: factory, Scope: ScopeTemplate}); err != nil {
		t.Fatal(err)
	}
	if err := resolver.RegisterNamedEmitCell(ctx, "Shared", nil, RegisterOptions{Factory: factory, Scope: ScopeScaffoldUnique}); err != nil {
		t.Fatal(err)
	}
	if err := resolver.RegisterNamedEmitCell(ctx, "Personal", nil, RegisterOptions{Factory: factory, Scope: ScopeIdentityUnique}); err != nil {
		t.Fatal(err)
	}
	t1, _ := resolver.CellAtEndpoint(ctx, "cell:///Template", alice)
	t2, _ := resolver.CellAtEndpoint(ctx, "cell:///Template", alice)
	if t1 == t2 {
		t.Fatalf("template scope reused instance")
	}
	s1, _ := resolver.CellAtEndpoint(ctx, "cell:///Shared", alice)
	s2, _ := resolver.CellAtEndpoint(ctx, "cell:///Shared", bob)
	if s1 != s2 {
		t.Fatalf("scaffold scope did not reuse instance")
	}
	p1, _ := resolver.CellAtEndpoint(ctx, "cell:///Personal", alice)
	p2, _ := resolver.CellAtEndpoint(ctx, "cell:///Personal", alice)
	p3, _ := resolver.CellAtEndpoint(ctx, "cell:///Personal", bob)
	if p1 != p2 || p1 == p3 {
		t.Fatalf("identity scope mismatch")
	}

	route := RemoteCellHostRoute{WebSocketEndpoint: "bridgehead", SchemePreference: "wss", PathLayout: "publisherUUIDThenEndpoint"}
	url, err := route.BridgeURL("example.test", "ConferenceAIGatewayPreview", "bridge-uuid", false)
	if err != nil {
		t.Fatal(err)
	}
	if url != "wss://example.test/bridgehead/bridge-uuid/ConferenceAIGatewayPreview" {
		t.Fatalf("route = %s", url)
	}
	defaultRoute := RemoteCellHostRoute{WebSocketEndpoint: "bridgehead", SchemePreference: "wss"}
	url, _ = defaultRoute.BridgeURL("example.test", "LoginCell", "bridge-uuid", false)
	if url != "wss://example.test/bridgehead/LoginCell/bridge-uuid" {
		t.Fatalf("default route = %s", url)
	}
}

func TestLoadCellAppliesCellReferencesAndSetKeysAndValues(t *testing.T) {
	ctx := context.Background()
	owner, _ := NewInMemoryIdentityVault().Identity(ctx, "owner", true)
	resolver := NewCellResolver()
	source := NewGeneralCell(owner, "Source")
	target := NewGeneralCell(owner, "Target")
	if err := resolver.RegisterNamedEmitCell(ctx, "Target", target, RegisterOptions{Identity: owner}); err != nil {
		t.Fatal(err)
	}
	config := NewCellConfiguration("Loader")
	config.CellReferences = []CellReference{
		{
			Endpoint:      "cell:///Target",
			Label:         "target",
			SubscribeFeed: false,
			SetKeysAndValues: []KeyValue{
				{Key: "state.message", Value: "hello"},
			},
		},
	}
	loaded, err := resolver.LoadCell(ctx, config, source, owner)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 || loaded[0] != target {
		t.Fatalf("loaded = %#v", loaded)
	}
	got, err := target.Get(ctx, "state.message", owner)
	if err != nil {
		t.Fatal(err)
	}
	if got != "hello" {
		t.Fatalf("target state = %#v", got)
	}
	status, _ := source.AttachedStatus(ctx, "target", owner)
	if status.State != ConnectConnected {
		t.Fatalf("status = %#v", status)
	}
}
