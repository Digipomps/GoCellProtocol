// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testBridgeRoute = "/bridgehead/00000000-0000-4000-8000-000000000001/Echo"

type bridgeheadFixture struct {
	server *httptest.Server
	base   string
	closed chan string
}

func startBridgehead(t *testing.T, publicURL func(base string) string) *bridgeheadFixture {
	t.Helper()
	ctx := context.Background()
	vault := NewInMemoryIdentityVault()
	owner, err := vault.Identity(ctx, "scaffold", true)
	if err != nil {
		t.Fatal(err)
	}
	resolver := NewCellResolver()
	if err := resolver.RegisterNamedEmitCell(ctx, "Echo", NewGeneralCell(owner, "Echo"), RegisterOptions{}); err != nil {
		t.Fatal(err)
	}
	fixture := &bridgeheadFixture{closed: make(chan string, 8)}
	head := NewResolverBridgehead(resolver, owner, BridgeheadOptions{AllowInsecureLoopback: true})
	head.OnClose = func(code string) { fixture.closed <- code }
	fixture.server = httptest.NewServer(head)
	fixture.base = "ws" + strings.TrimPrefix(fixture.server.URL, "http")
	head.Options.PublicURL = publicURL(fixture.base)
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (f *bridgeheadFixture) closeCode(t *testing.T) string {
	t.Helper()
	select {
	case code := <-f.closed:
		return code
	case <-time.After(5 * time.Second):
		t.Fatal("bridgehead did not close")
		return ""
	}
}

func sameURL(base string) string { return base }

func testIdentity(t *testing.T, name string) *Identity {
	t.Helper()
	identity, err := NewInMemoryIdentityVault().Identity(context.Background(), name, true)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func authenticatedBridge(base string, identity *Identity) *CloudBridge {
	return NewCloudBridge(base+testBridgeRoute, identity, CloudBridgeOptions{
		Authenticate:           true,
		AllowInsecureWebSocket: true,
		RequestTimeout:         3 * time.Second,
	})
}

func TestGoClientIsAdmittedByGoBridgehead(t *testing.T) {
	fixture := startBridgehead(t, sameURL)
	alice := testIdentity(t, "alice")
	bridge := authenticatedBridge(fixture.base, alice)
	ctx := context.Background()
	if err := bridge.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	defer bridge.CloseConnection()
	admitted := bridge.AdmittedChannel()
	if admitted == nil || admitted.Identity.UUID != alice.UUID {
		t.Fatalf("admitted = %+v", admitted)
	}
	response, err := bridge.SendCommand(ctx, BridgeCommand{Cmd: "description"})
	if err != nil {
		t.Fatal(err)
	}
	typed, ok := response.Payload.(TypedValue)
	if !ok || typed.Kind != "description" {
		t.Fatalf("response = %+v", response)
	}
}

func rawSocket(t *testing.T, url string) *webSocketClient {
	t.Helper()
	socket, err := dialWebSocket(context.Background(), url, webSocketDialOptions{AllowInsecureWebSocket: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	return socket
}

func TestBridgeheadRefusesReadyAndCommandsBeforeAdmission(t *testing.T) {
	fixture := startBridgehead(t, sameURL)
	alice := testIdentity(t, "alice")
	frames := []BridgeCommand{
		{Cmd: "ready", CID: 0},
		{Cmd: "description", CID: 1, Identity: alice},
	}
	for _, frame := range frames {
		socket := rawSocket(t, fixture.base+testBridgeRoute)
		data, _ := json.Marshal(frame)
		if err := socket.SendText(context.Background(), data); err != nil {
			t.Fatal(err)
		}
		if _, err := socket.ReadMessage(); err == nil {
			t.Fatalf("%s: bridgehead answered before admission", frame.Cmd)
		}
		if code := fixture.closeCode(t); code != "malformed" {
			t.Fatalf("%s: closed with %q", frame.Cmd, code)
		}
	}
}

func TestBridgeheadClosesOnACommandForAnotherIdentity(t *testing.T) {
	fixture := startBridgehead(t, sameURL)
	alice := testIdentity(t, "alice")
	mallory := testIdentity(t, "mallory")
	bridge := authenticatedBridge(fixture.base, alice)
	ctx := context.Background()
	if err := bridge.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	defer bridge.CloseConnection()
	if _, err := bridge.SendCommand(ctx, BridgeCommand{Cmd: "description", Identity: mallory}); err == nil {
		t.Fatal("command for another identity was answered")
	}
	if code := fixture.closeCode(t); code != "identityMismatch" {
		t.Fatalf("closed with %q", code)
	}
}

func TestClientRefusesABridgeheadSigningForAnotherAudience(t *testing.T) {
	fixture := startBridgehead(t, func(string) string { return "wss://other.example" })
	bridge := authenticatedBridge(fixture.base, testIdentity(t, "alice"))
	if err := bridge.Ready(context.Background()); err == nil || !strings.Contains(err.Error(), "invalidProof") {
		t.Fatalf("err = %v", err)
	}
}

func TestBridgeheadWithoutPublicURLRefuses(t *testing.T) {
	fixture := startBridgehead(t, func(string) string { return "" })
	bridge := authenticatedBridge(fixture.base, testIdentity(t, "alice"))
	if err := bridge.Ready(context.Background()); err == nil {
		t.Fatal("connected without a configured public URL")
	}
	if code := fixture.closeCode(t); code != "unavailable" {
		t.Fatalf("closed with %q", code)
	}
}

func TestUnknownCellAfterAdmissionIsUnavailable(t *testing.T) {
	fixture := startBridgehead(t, sameURL)
	bridge := NewCloudBridge(fixture.base+"/bridgehead/00000000-0000-4000-8000-000000000001/Nope", testIdentity(t, "alice"),
		CloudBridgeOptions{Authenticate: true, AllowInsecureWebSocket: true, RequestTimeout: 2 * time.Second})
	ctx := context.Background()
	if err := bridge.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	defer bridge.CloseConnection()
	if code := fixture.closeCode(t); code != "unavailable" {
		t.Fatalf("closed with %q", code)
	}
}
