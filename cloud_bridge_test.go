// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCloudBridgeConnectsAndCorrelatesResponses(t *testing.T) {
	server := newTestBridgeServer(t)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	identity, _ := NewInMemoryIdentityVault().Identity(ctx, "go-client", true)
	bridge := NewCloudBridge(server.URL, identity, CloudBridgeOptions{
		AllowInsecureWebSocket: true,
		RequestTimeout:         time.Second,
	})
	defer bridge.CloseConnection()

	if err := bridge.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	value, err := bridge.Get(ctx, "state.message", identity)
	if err != nil {
		t.Fatal(err)
	}
	if value != "hello from swift-shaped staging" {
		t.Fatalf("get value = %#v", value)
	}
	result, err := bridge.Set(ctx, "state.message", "new value", identity)
	if err != nil {
		t.Fatal(err)
	}
	if result != "stored" {
		t.Fatalf("set result = %#v", result)
	}
}

func TestCloudBridgeReceivesFeedResponses(t *testing.T) {
	server := newTestBridgeServer(t)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	identity, _ := NewInMemoryIdentityVault().Identity(ctx, "go-client", true)
	bridge := NewCloudBridge(server.URL, identity, CloudBridgeOptions{
		AllowInsecureWebSocket: true,
		RequestTimeout:         time.Second,
	})
	defer bridge.CloseConnection()

	flow, err := bridge.Flow(ctx, identity)
	if err != nil {
		t.Fatal(err)
	}
	first := <-flow
	second := <-flow
	if first.Title != "Remote event 1" || second.Title != "Remote event 2" {
		t.Fatalf("unexpected flow: %#v %#v", first, second)
	}
}

func TestCloudBridgeRejectsInsecureWebSocketByDefault(t *testing.T) {
	server := newTestBridgeServer(t)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	bridge := NewCloudBridge(server.URL, nil, CloudBridgeOptions{RequestTimeout: time.Second})
	if _, err := bridge.Get(ctx, "state.message", nil); err == nil {
		t.Fatalf("expected insecure ws rejection")
	}
}

func TestCloudBridgeStagingSmoke(t *testing.T) {
	endpoint := os.Getenv("CELLPROTOCOL_STAGING_BRIDGE_URL")
	if endpoint == "" {
		t.Skip("set CELLPROTOCOL_STAGING_BRIDGE_URL to run a live Swift/Vapor bridgehead smoke test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	identity, _ := NewInMemoryIdentityVault().Identity(ctx, "go-staging-smoke", true)
	bridge := NewCloudBridge(endpoint, identity, CloudBridgeOptions{
		RequestTimeout: 10 * time.Second,
		Headers: map[string]string{
			"User-Agent": "GoCellProtocol-CloudBridge-Smoke",
		},
	})
	defer bridge.CloseConnection()
	description, err := bridge.Advertise(ctx, identity)
	if err != nil {
		t.Fatal(err)
	}
	if description.UUID == "" && description.Name == "" {
		t.Fatalf("staging description was empty: %#v", description)
	}
}

type testBridgeServer struct {
	URL      string
	listener net.Listener
	wg       sync.WaitGroup
}

func newTestBridgeServer(t *testing.T) *testBridgeServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &testBridgeServer{URL: "ws://" + listener.Addr().String() + "/bridgehead/TestCell/client", listener: listener}
	server.wg.Add(1)
	go func() {
		defer server.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			server.wg.Add(1)
			go func() {
				defer server.wg.Done()
				handleTestBridgeConnection(t, conn)
			}()
		}
	}()
	return server
}

func (s *testBridgeServer) Close() {
	_ = s.listener.Close()
	s.wg.Wait()
}

func handleTestBridgeConnection(t *testing.T, conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	request, err := http.ReadRequest(reader)
	if err != nil {
		t.Logf("read request failed: %v", err)
		return
	}
	key := request.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		t.Logf("missing websocket key")
		return
	}
	acceptBytes := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	accept := base64.StdEncoding.EncodeToString(acceptBytes[:])
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\n")
	_, _ = fmt.Fprintf(conn, "Upgrade: websocket\r\n")
	_, _ = fmt.Fprintf(conn, "Connection: Upgrade\r\n")
	_, _ = fmt.Fprintf(conn, "Sec-WebSocket-Accept: %s\r\n\r\n", accept)
	ready, _ := json.Marshal(BridgeCommand{Cmd: "ready", CID: 0})
	_ = writeWebSocketFrame(conn, webSocketOpcodeText, ready, false)

	for {
		opcode, payload, err := readWebSocketFrame(reader, defaultWebSocketMaxMessageBytes)
		if err != nil {
			return
		}
		if opcode == webSocketOpcodeClose {
			return
		}
		var command BridgeCommand
		if err := DecodeJSON(payload, &command); err != nil {
			t.Logf("decode command failed: %v", err)
			return
		}
		switch command.Command() {
		case "get":
			response := BridgeCommand{Cmd: "response", CID: command.CID, Payload: TypedValue{Kind: "string", Value: "hello from swift-shaped staging"}}
			sendTestBridgeCommand(t, conn, response)
		case "set":
			response := BridgeCommand{Cmd: "response", CID: command.CID, Payload: TypedValue{Kind: "setValueResponse", Value: SetOK("stored")}}
			sendTestBridgeCommand(t, conn, response)
		case "feed":
			first := NewFlowElement("Remote event 1", map[string]any{"n": 1})
			second := NewFlowElement("Remote event 2", map[string]any{"n": 2})
			first.Topic = "remote"
			second.Topic = "remote"
			sendTestBridgeCommand(t, conn, BridgeCommand{Cmd: "response", CID: command.CID, Payload: TypedValue{Kind: "flowElement", Value: first}})
			sendTestBridgeCommand(t, conn, BridgeCommand{Cmd: "response", CID: command.CID, Payload: TypedValue{Kind: "flowElement", Value: second}})
		default:
			if !strings.EqualFold(command.Cmd, "ready") {
				response := BridgeCommand{Cmd: "response", CID: command.CID, Payload: TypedValue{Kind: "string", Value: "unsupported command: " + command.Cmd}}
				sendTestBridgeCommand(t, conn, response)
			}
		}
	}
}

func sendTestBridgeCommand(t *testing.T, conn net.Conn, command BridgeCommand) {
	t.Helper()
	data, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeWebSocketFrame(conn, webSocketOpcodeText, data, false); err != nil {
		t.Logf("write command failed: %v", err)
	}
}
