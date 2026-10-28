// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Digipomps/GoCellProtocol/interop"
)

// BridgeheadOptions configures the inbound /bridgehead/:pubId/:bridgeId route.
type BridgeheadOptions struct {
	// PublicURL is this node's own origin, for example wss://node.example.
	// The signed audience is PublicURL + request path, never the Host or
	// Forwarded headers. Without it every connection is refused.
	PublicURL string
	// AllowInsecureLoopback permits ws:// for a loopback PublicURL (tests, local dev).
	AllowInsecureLoopback bool
	// ChannelDomain is the signed domain; empty means "bridge".
	ChannelDomain string
	// Recheck runs after the signature verifies, for revocation or policy.
	Recheck func(interop.PublicIdentity) error
	// MaxMessageBytes bounds every frame after admission.
	MaxMessageBytes int64
	// Clock fixes time in tests.
	Clock interop.ChannelClock
}

// BridgeheadOpen returns the endpoint for an admitted connection. It runs
// only after admission and gets the proven principal, never wire metadata.
// pubID and bridgeID are the two path segments.
type BridgeheadOpen func(ctx context.Context, admitted *interop.AdmittedChannel, pubID, bridgeID string) (*BridgeEndpoint, error)

// Bridgehead serves Cells over org.haven.bridge-channel.v1, the way a Swift
// bridgehead does: no "ready" frame, no command before admission, and every
// later command must carry the admitted public key. Admission proves control
// of a key and grants no Cell permission; the Cell's own authorization still
// decides what that key may read or write.
type Bridgehead struct {
	Options BridgeheadOptions
	Open    BridgeheadOpen
	// OnClose, if set, receives the failure code a connection ended with ("" for a clean close).
	OnClose func(code string)
}

// NewResolverBridgehead serves named Cells from a resolver. The Cell name is
// the segment that is not a UUID, so both Swift's /bridgehead/:pubId/:name and
// the older /bridgehead/:name/:requester work.
func NewResolverBridgehead(resolver *CellResolver, owner *Identity, options BridgeheadOptions) *Bridgehead {
	return &Bridgehead{
		Options: options,
		Open: func(ctx context.Context, _ *interop.AdmittedChannel, pubID, bridgeID string) (*BridgeEndpoint, error) {
			name := pubID
			if looksLikeUUID(pubID) {
				name = bridgeID
			}
			cell, err := resolver.CellAtEndpoint(ctx, "cell:///"+name, owner)
			if err != nil {
				return nil, err
			}
			return NewBridgeEndpoint(cell, owner), nil
		},
	}
}

func looksLikeUUID(value string) bool {
	return len(value) >= 32 && (strings.Count(value, "-") == 0 || strings.Count(value, "-") == 4)
}

func (h *Bridgehead) finish(code string) {
	if h.OnClose != nil {
		h.OnClose(code)
	}
}

func (h *Bridgehead) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	segments := strings.Split(strings.TrimPrefix(r.URL.EscapedPath(), "/"), "/")
	if len(segments) != 3 || segments[0] != "bridgehead" || segments[1] == "" || segments[2] == "" {
		http.NotFound(w, r)
		return
	}
	domain := h.Options.ChannelDomain
	if domain == "" {
		domain = "bridge"
	}
	endpoint, err := interop.ChannelEndpointFromURL(
		strings.TrimRight(h.Options.PublicURL, "/")+r.URL.EscapedPath(), domain, h.Options.AllowInsecureLoopback)
	if h.Options.PublicURL == "" || err != nil || r.URL.RawQuery != "" {
		http.Error(w, "bridge unavailable", http.StatusForbidden)
		h.finish("unavailable")
		return
	}
	socket, err := acceptWebSocket(w, r, interop.ChannelMaximumEnvelope)
	if err != nil {
		h.finish("malformed")
		return
	}
	code := h.serve(r.Context(), socket, endpoint, segments[1], segments[2])
	if code == "" {
		_ = socket.Close()
	} else {
		_ = socket.closeWithCode(1008)
	}
	h.finish(code)
}

func (h *Bridgehead) serve(ctx context.Context, socket *webSocketClient, endpoint interop.ChannelEndpoint, pubID, bridgeID string) string {
	server := interop.NewChannelServer(endpoint, h.Options.Clock)
	server.Recheck = h.Options.Recheck
	_ = socket.conn.SetReadDeadline(time.Now().Add(interop.ChannelPreAuthDeadline))
	for server.State != "authenticated" {
		frame, err := socket.ReadMessage()
		if err != nil {
			return "expired"
		}
		reply, err := server.Receive(frame)
		if err != nil {
			return interop.VerdictOf(err)
		}
		if err := socket.SendText(ctx, reply); err != nil {
			return "closed"
		}
	}
	_ = socket.conn.SetReadDeadline(time.Time{})
	admitted := server.Admitted
	now := h.Options.Clock.Wall
	if now == nil {
		now = time.Now
	}

	bridge, err := h.Open(ctx, admitted, pubID, bridgeID)
	if err != nil || bridge == nil {
		// Same answer for "no such Cell" and "not allowed".
		return "unavailable"
	}
	if h.Options.MaxMessageBytes > 0 {
		socket.maxBytes = h.Options.MaxMessageBytes
	} else {
		socket.maxBytes = defaultWebSocketMaxMessageBytes
	}
	for {
		frame, err := socket.ReadMessage()
		if err != nil {
			return "" // peer went away
		}
		var command BridgeCommand
		if err := DecodeJSON(frame, &command); err != nil {
			return "malformed"
		}
		if interop.IsChannelAuthCommand(command.Cmd) || command.Command() == "ready" {
			return "unexpectedMessage"
		}
		presented, err := channelPublicIdentity(command.Identity)
		if err != nil {
			return interop.VerdictOf(err)
		}
		if err := admitted.CheckIdentity(presented, command.Command() != "response", now()); err != nil {
			return interop.VerdictOf(err)
		}
		for _, response := range bridge.Handle(ctx, command) {
			if err := admitted.Check(now()); err != nil {
				return interop.VerdictOf(err)
			}
			data, err := json.Marshal(response)
			if err != nil {
				return "malformed"
			}
			if err := socket.SendText(ctx, data); err != nil {
				return ""
			}
		}
	}
}

// channelPublicIdentity is the minimal public principal of a wire identity,
// or nil when it carries none.
func channelPublicIdentity(identity *Identity) (*interop.PublicIdentity, error) {
	if identity == nil || identity.PublicSecureKey == "" {
		return nil, nil
	}
	key, err := base64.StdEncoding.DecodeString(identity.PublicSecureKey)
	if err != nil {
		return nil, errors.New("identityMismatch")
	}
	public := interop.NewEd25519PublicIdentity(identity.UUID, key)
	return &public, nil
}
