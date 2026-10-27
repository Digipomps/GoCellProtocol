// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

// Command interop-peer is the Go peer for the cross-language interop matrix
// (haven.interop-peer.v1). The matrix runner sends one JSON object per line on
// stdin; the peer answers one line on stdout: {"ok":true,"result":...} or
// {"ok":false,"error":"..."}. PyCellProtocol's interop/matrix/README.md
// describes the protocol; the Python and Swift peers speak the same one.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	cp "github.com/Digipomps/GoCellProtocol"
)

const protocol = "haven.interop-peer.v1"

type message struct {
	Op                string `json:"op"`
	Name              string `json:"name"`
	Port              int    `json:"port"`
	Topic             string `json:"topic"`
	LandingBase       string `json:"landingBase"`
	ContactEndpointID string `json:"contactEndpointID"`
	Cell              string `json:"cell"`
	Method            string `json:"method"`
	Key               string `json:"key"`
	URL               string `json:"url"`
	Value             any    `json:"value"`
}

type peer struct {
	ctx     context.Context
	me      *cp.Identity
	sign    func([]byte) ([]byte, error)
	cells   map[string]cp.CellProtocol
	bridges map[string]*cp.CloudBridge
}

func (p *peer) handle(m message) (any, error) {
	switch m.Op {
	case "hello":
		return map[string]any{"lang": "go", "protocol": protocol}, nil
	case "init":
		name := m.Name
		if name == "" {
			name = "peer"
		}
		me, err := cp.NewInMemoryIdentityVault().Identity(p.ctx, name, true)
		if err != nil {
			return nil, err
		}
		descriptor, ok := cp.DescriptorFor(me)
		if !ok {
			return nil, errors.New("identity has no Ed25519 key")
		}
		p.me = me
		p.sign = func(b []byte) ([]byte, error) { return me.Sign(p.ctx, b) }
		p.cells = map[string]cp.CellProtocol{
			"home":      cp.NewChatCell(me, cp.ChatCellOptions{}),
			"extension": cp.NewEntityScaffoldExtensionCell(me, cp.ExtensionOptions{Descriptor: descriptor, Sign: p.sign, DisplayName: name}),
		}
		return map[string]any{"identity": me, "descriptor": descriptor}, nil
	case "invitation":
		descriptor, _ := cp.DescriptorFor(p.me)
		p.cells["invitation"] = cp.NewInvitationCell(p.me, cp.InvitationOptions{
			Descriptor: descriptor, Sign: p.sign, DisplayName: p.me.DisplayName,
			LandingBase: m.LandingBase, ContactEndpointID: m.ContactEndpointID,
		})
		return map[string]any{"cell": "invitation"}, nil
	case "serve":
		return p.serve(m)
	case "call":
		cell := p.cells[m.Cell]
		if cell == nil {
			return nil, fmt.Errorf("no cell %s", m.Cell)
		}
		if m.Method == "get" {
			return cell.Get(p.ctx, m.Key, p.me)
		}
		return cell.Set(p.ctx, m.Key, m.Value, p.me)
	case "remote":
		bridge := p.bridges[m.URL]
		if bridge == nil {
			bridge = cp.NewCloudBridge(m.URL, p.me, cp.CloudBridgeOptions{Authenticate: true, AllowInsecureWebSocket: true, RequestTimeout: 10 * time.Second})
			if err := bridge.Ready(p.ctx); err != nil {
				return nil, err
			}
			p.bridges[m.URL] = bridge
		}
		var result any
		var err error
		if m.Method == "get" {
			result, err = bridge.Get(p.ctx, m.Key, p.me)
		} else {
			result, err = bridge.Set(p.ctx, m.Key, m.Value, p.me)
		}
		if err != nil {
			return nil, err
		}
		// Bridge answers carry refusals as {state: error}.
		switch r := result.(type) {
		case map[string]any:
			if r["state"] == "error" {
				return nil, fmt.Errorf("%v", r["value"])
			}
		case cp.SetValueResponse:
			if r.State == "error" {
				return nil, fmt.Errorf("%v", r.Value)
			}
		case *cp.SetValueResponse:
			if r != nil && r.State == "error" {
				return nil, fmt.Errorf("%v", r.Value)
			}
		}
		return result, nil
	}
	return nil, fmt.Errorf("unknown op %s", m.Op)
}

func (p *peer) serve(m message) (any, error) {
	topic := m.Topic
	if topic == "" {
		topic = "chat"
	}
	chat := cp.NewChatCell(p.me, cp.ChatCellOptions{Topic: topic})
	p.cells["chat"] = chat
	resolver := cp.NewCellResolver()
	if err := resolver.RegisterNamedEmitCell(p.ctx, "Chat", chat, cp.RegisterOptions{}); err != nil {
		return nil, err
	}
	scaffold, err := cp.NewInMemoryIdentityVault().Identity(p.ctx, "scaffold", true)
	if err != nil {
		return nil, err
	}
	origin := fmt.Sprintf("127.0.0.1:%d", m.Port)
	mux := http.NewServeMux()
	mux.Handle("/bridgehead/", cp.NewResolverBridgehead(resolver, scaffold, cp.BridgeheadOptions{PublicURL: "ws://" + origin, AllowInsecureLoopback: true}))
	landing := cp.NewInviteLanding(nil)
	landing.RateLimit = false
	mux.Handle("/i/", landing)
	listener, err := net.Listen("tcp", origin)
	if err != nil {
		return nil, err
	}
	go func() { _ = (&http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}).Serve(listener) }()
	return map[string]any{
		"landingBase": "http://" + origin,
		"chatURL":     "ws://" + origin + "/bridgehead/" + chat.CellUUID() + "/Chat",
	}, nil
}

func main() {
	p := &peer{ctx: context.Background(), cells: map[string]cp.CellProtocol{}, bridges: map[string]*cp.CloudBridge{}}
	out := json.NewEncoder(os.Stdout)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1<<20), 1<<26)
	for scanner.Scan() {
		if len(scanner.Bytes()) == 0 {
			continue
		}
		var m message
		var result any
		err := json.Unmarshal(scanner.Bytes(), &m)
		if err == nil {
			result, err = p.handle(m)
		}
		if err != nil {
			_ = out.Encode(map[string]any{"ok": false, "error": err.Error()})
			continue
		}
		if encodeErr := out.Encode(map[string]any{"ok": true, "result": result}); encodeErr != nil {
			_ = out.Encode(map[string]any{"ok": false, "error": "encode: " + encodeErr.Error()})
		}
	}
}
