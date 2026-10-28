// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package interop

// org.haven.bridge-channel.v1 against the Swift vectors. The vectors fix every
// random input (nonces, session ID, generation), so a Go server and client
// driven with the same inputs must emit the very same envelopes, and a Go
// client signature equals the Swift one (Ed25519 is deterministic).

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type channelVector struct {
	fixtureCase
	transcript ChannelTranscript
}

func loadChannelVectors(t *testing.T) (map[string]channelVector, map[string]ed25519.PrivateKey) {
	t.Helper()
	dir := filepath.Join("testdata", "v1")
	manifest, _ := loadFixtures(t)
	keys := map[string]ed25519.PrivateKey{}
	for _, party := range manifest.Parties {
		seed, err := hex.DecodeString(party.SeedHex)
		if err != nil {
			t.Fatal(err)
		}
		keys[party.Name] = ed25519.NewKeyFromSeed(seed)
	}
	vectors := map[string]channelVector{}
	for _, entry := range manifest.Cases {
		data, err := os.ReadFile(filepath.Join(dir, entry.File))
		if err != nil {
			t.Fatal(err)
		}
		var c fixtureCase
		if err := json.Unmarshal(data, &c); err != nil {
			t.Fatal(err)
		}
		if c.Type != channelAuthFixtureType {
			continue
		}
		transcript, err := DecodeChannelTranscript(b64(t, c.EncodedBase64))
		if err != nil {
			t.Fatalf("%s: %v", c.ID, err)
		}
		vectors[c.ID] = channelVector{fixtureCase: c, transcript: transcript}
	}
	if len(vectors) != 3 {
		t.Fatalf("want 3 channel vectors, got %d", len(vectors))
	}
	return vectors, keys
}

type testClock struct {
	wall time.Time
	mono time.Duration
}

func (c *testClock) channelClock(tr ChannelTranscript, ids ...string) ChannelClock {
	next := 0
	return ChannelClock{
		Wall:      func() time.Time { return c.wall },
		Monotonic: func() time.Duration { return c.mono },
		Random: func(n int) []byte {
			if n == 32 {
				return tr.ServerNonce
			}
			return make([]byte, n)
		},
		NewUUID: func() string {
			id := ids[next%len(ids)]
			next++
			return id
		},
	}
}

func clockAt(tr ChannelTranscript) *testClock {
	return &testClock{wall: time.UnixMilli(tr.IssuedAtMilliseconds), mono: time.Hour}
}

func serverFor(clock *testClock, tr ChannelTranscript) *ChannelServer {
	return NewChannelServer(tr.Endpoint, clock.channelClock(tr, tr.Generation, tr.SessionID))
}

func clientFor(t *testing.T, clock *testClock, tr ChannelTranscript) *ChannelClient {
	t.Helper()
	cc := clock.channelClock(tr)
	cc.Random = func(int) []byte { return tr.ClientNonce }
	client, err := NewChannelClient(tr.Identity, tr.Endpoint, cc)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func mustOf(t *testing.T) func([]byte, error) []byte {
	return func(data []byte, err error) []byte {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	if got := VerdictOf(err); got != code {
		t.Fatalf("want %s, got %s", code, got)
	}
}

func TestChannelVectorsMatchSwift(t *testing.T) {
	vectors, _ := loadChannelVectors(t)
	for id, v := range vectors {
		tr := v.transcript
		if got := mustOf(t)(tr.Encoded()); !bytes.Equal(got, b64(t, v.EncodedBase64)) {
			t.Fatalf("%s: transcript bytes differ", id)
		}
		if tr.Digest() != v.Related["transcriptDigestHex"] {
			t.Fatalf("%s: digest", id)
		}
		if tr.Endpoint.Audience() != v.Related["endpointAudience"] {
			t.Fatalf("%s: audience", id)
		}
		if got := mustOf(t)(ChannelSigningData(tr)); !bytes.Equal(got, b64(t, v.CanonicalBase64)) {
			t.Fatalf("%s: signing data\n got %s\nwant %s", id, got, b64(t, v.CanonicalBase64))
		}
		checks := map[string][]byte{
			"helloEnvelopeBase64":     mustOf(t)(ChannelHelloEnvelope(tr.Identity, tr.ClientNonce)),
			"challengeEnvelopeBase64": mustOf(t)(ChannelChallengeEnvelope(tr)),
			"proofEnvelopeBase64":     mustOf(t)(ChannelProofEnvelope(tr.SessionID, tr.Generation, b64(t, v.SignatureBase64))),
			"acceptedEnvelopeBase64":  mustOf(t)(ChannelAcceptedEnvelope(tr)),
		}
		for key, got := range checks {
			if !bytes.Equal(got, b64(t, v.Related[key])) {
				t.Fatalf("%s: %s differs\n got %s\nwant %s", id, key, got, b64(t, v.Related[key]))
			}
		}
		endpoint, err := ChannelEndpointFromURL(tr.Endpoint.Audience(), tr.Endpoint.Domain, false)
		if err != nil || endpoint != tr.Endpoint {
			t.Fatalf("%s: endpoint from URL: %v", id, err)
		}
		valid := VerifySignature(b64(t, v.SignatureBase64), b64(t, v.CanonicalBase64), tr.Identity.Descriptor())
		if valid != v.Expect.SignatureValid {
			t.Fatalf("%s: signature valid = %v", id, valid)
		}
	}
}

func TestGoServerAndClientReproduceTheSwiftHandshake(t *testing.T) {
	vectors, keys := loadChannelVectors(t)
	for _, id := range []string{"bridge.channel-auth.valid", "bridge.channel-auth.whole-second"} {
		v := vectors[id]
		tr := v.transcript
		clock := clockAt(tr)
		server := serverFor(clock, tr)
		client := clientFor(t, clock, tr)

		hello := mustOf(t)(client.Hello())
		if !bytes.Equal(hello, b64(t, v.Related["helloEnvelopeBase64"])) {
			t.Fatalf("%s: hello", id)
		}
		challenge := mustOf(t)(server.Receive(hello))
		if !bytes.Equal(challenge, b64(t, v.Related["challengeEnvelopeBase64"])) {
			t.Fatalf("%s: challenge", id)
		}
		offered := mustOf(t)(client.BeginChallenge(challenge))
		proof := mustOf(t)(client.FinishChallenge(ed25519.Sign(keys["bob"], offered)))
		if !bytes.Equal(proof, b64(t, v.Related["proofEnvelopeBase64"])) {
			t.Fatalf("%s: proof (Go signature differs from Swift)", id)
		}
		accepted := mustOf(t)(server.Receive(proof))
		if !bytes.Equal(accepted, b64(t, v.Related["acceptedEnvelopeBase64"])) {
			t.Fatalf("%s: accepted", id)
		}
		if err := client.Accept(accepted); err != nil {
			t.Fatal(err)
		}
		if server.State != "authenticated" || client.State != "authenticated" {
			t.Fatalf("%s: states %s/%s", id, server.State, client.State)
		}
		if !server.Admitted.Identity.Equal(tr.Identity) || server.Admitted.TranscriptDigest != tr.Digest() {
			t.Fatalf("%s: admitted", id)
		}
		id := tr.Identity
		if err := server.Admitted.CheckIdentity(&id, true, clock.wall); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSwiftClientMessagesAreAcceptedByGoServer(t *testing.T) {
	vectors, _ := loadChannelVectors(t)
	v := vectors["bridge.channel-auth.valid"]
	clock := clockAt(v.transcript)
	server := serverFor(clock, v.transcript)
	if got := mustOf(t)(server.Receive(b64(t, v.Related["helloEnvelopeBase64"]))); !bytes.Equal(got, b64(t, v.Related["challengeEnvelopeBase64"])) {
		t.Fatal("challenge")
	}
	clock.wall = clock.wall.Add(time.Second)
	if got := mustOf(t)(server.Receive(b64(t, v.Related["proofEnvelopeBase64"]))); !bytes.Equal(got, b64(t, v.Related["acceptedEnvelopeBase64"])) {
		t.Fatal("accepted")
	}
}

func TestProofFromAnotherKeyIsRefusedAndTerminal(t *testing.T) {
	vectors, _ := loadChannelVectors(t)
	v := vectors["bridge.channel-auth.wrong-key"]
	server := serverFor(clockAt(v.transcript), v.transcript)
	mustOf(t)(server.Receive(b64(t, v.Related["helloEnvelopeBase64"])))
	_, err := server.Receive(b64(t, v.Related["proofEnvelopeBase64"]))
	wantCode(t, err, "invalidProof")
	if server.State != "closed" || server.Admitted != nil {
		t.Fatal("not terminal")
	}
	_, err = server.Receive(b64(t, v.Related["helloEnvelopeBase64"]))
	wantCode(t, err, "unexpectedMessage")
}

func TestReplayedProofCannotOpenASecondChannel(t *testing.T) {
	vectors, _ := loadChannelVectors(t)
	v := vectors["bridge.channel-auth.valid"]
	clock := clockAt(v.transcript)
	server := serverFor(clock, v.transcript)
	mustOf(t)(server.Receive(b64(t, v.Related["helloEnvelopeBase64"])))
	mustOf(t)(server.Receive(b64(t, v.Related["proofEnvelopeBase64"])))
	_, err := server.Receive(b64(t, v.Related["proofEnvelopeBase64"]))
	wantCode(t, err, "unexpectedMessage")
	// A fresh connection draws a new generation, so the old proof is stale.
	cc := clock.channelClock(v.transcript, "11111111-1111-4111-8111-111111111111", v.transcript.SessionID)
	other := NewChannelServer(v.transcript.Endpoint, cc)
	mustOf(t)(other.Receive(b64(t, v.Related["helloEnvelopeBase64"])))
	_, err = other.Receive(b64(t, v.Related["proofEnvelopeBase64"]))
	wantCode(t, err, "staleGeneration")
}

func TestLateProofAndPreAuthDeadline(t *testing.T) {
	vectors, _ := loadChannelVectors(t)
	v := vectors["bridge.channel-auth.valid"]
	clock := clockAt(v.transcript)
	server := serverFor(clock, v.transcript)
	mustOf(t)(server.Receive(b64(t, v.Related["helloEnvelopeBase64"])))
	clock.wall = clock.wall.Add(30 * time.Second)
	_, err := server.Receive(b64(t, v.Related["proofEnvelopeBase64"]))
	wantCode(t, err, "expired")

	clock = clockAt(v.transcript)
	server = serverFor(clock, v.transcript)
	clock.mono += ChannelPreAuthDeadline
	_, err = server.Receive(b64(t, v.Related["helloEnvelopeBase64"]))
	wantCode(t, err, "expired")
}

func TestClientRefusesAChallengeForAnotherEndpoint(t *testing.T) {
	vectors, _ := loadChannelVectors(t)
	v := vectors["bridge.channel-auth.valid"]
	clock := clockAt(v.transcript)
	elsewhere, err := ChannelEndpointFromURL("wss://evil.example/bridgehead/x/y", "bridge", false)
	if err != nil {
		t.Fatal(err)
	}
	server := NewChannelServer(elsewhere, clock.channelClock(v.transcript, v.transcript.Generation, v.transcript.SessionID))
	client := clientFor(t, clock, v.transcript)
	challenge := mustOf(t)(server.Receive(mustOf(t)(client.Hello())))
	_, err = client.BeginChallenge(challenge)
	wantCode(t, err, "invalidProof")
}

func TestClientRefusesAChallengeWhoseSigningDataLies(t *testing.T) {
	vectors, _ := loadChannelVectors(t)
	v := vectors["bridge.channel-auth.valid"]
	clock := clockAt(v.transcript)
	client := clientFor(t, clock, v.transcript)
	mustOf(t)(client.Hello())
	body, err := challengeBody(v.transcript)
	if err != nil {
		t.Fatal(err)
	}
	body["signingData"] = encodeB64([]byte(`{"action":"anything"}`))
	_, err = client.BeginChallenge(mustOf(t)(ChannelEnvelope("channelAuthChallenge", body)))
	wantCode(t, err, "invalidProof")
}

func TestMalformedEnvelopesAreRefused(t *testing.T) {
	vectors, _ := loadChannelVectors(t)
	v := vectors["bridge.channel-auth.valid"]
	hello := b64(t, v.Related["helloEnvelopeBase64"])
	bad := [][]byte{
		[]byte(`{"cmd":"channelAuthHello","cid":0,"&string":"{}"}`), // key order
		append([]byte(" "), hello...),                               // whitespace
		bytes.Replace(hello, []byte(`"cid":0`), []byte(`"cid":1`), 1),
		bytes.Replace(hello, []byte(`channelAuthHello`), []byte(`description`), 1),
		bytes.Repeat([]byte("a"), ChannelMaximumEnvelope+1),
	}
	for i, data := range bad {
		server := serverFor(clockAt(v.transcript), v.transcript)
		if _, err := server.Receive(data); VerdictOf(err) != "malformed" {
			t.Fatalf("case %d: want malformed, got %v", i, err)
		}
	}
}

func TestChannelEndpointURLRules(t *testing.T) {
	good := map[string]ChannelEndpoint{
		"wss://node.example/bridgehead/a/b":      {"wss://node.example", "/bridgehead/a/b", "bridge"},
		"wss://node.example:8443/bridgehead/a/b": {"wss://node.example:8443", "/bridgehead/a/b", "bridge"},
	}
	for raw, want := range good {
		got, err := ChannelEndpointFromURL(raw, "bridge", false)
		if err != nil || got != want {
			t.Fatalf("%s: %v %v", raw, got, err)
		}
	}
	if _, err := ChannelEndpointFromURL("ws://127.0.0.1:9000/bridgehead/a/b", "bridge", true); err != nil {
		t.Fatal(err)
	}
	refused := map[string]string{
		"ws://127.0.0.1:9000/bridgehead/a/b":  "insecureEndpoint",
		"ws://node.example/bridgehead/a/b":    "insecureEndpoint",
		"wss://node.example:443/bridgehead/a": "malformed",
		"wss://Node.example/bridgehead/a":     "malformed",
		"WSS://node.example/bridgehead/a":     "malformed",
		"wss://u:p@node.example/bridgehead/a": "malformed",
		"wss://node.example/bridgehead/a?x=1": "malformed",
		"wss://node.example/bridgehead/a#x":   "malformed",
		"wss://node.example/bridgehead/../a":  "malformed",
		"wss://node.example/bridgehead//a":    "malformed",
		"wss://node.example/bridge%20head/a":  "malformed",
		"wss://node.example./bridgehead/a":    "malformed",
		"wss://node.example":                  "malformed",
	}
	for raw, code := range refused {
		_, err := ChannelEndpointFromURL(raw, "bridge", false)
		if VerdictOf(err) != code {
			t.Fatalf("%s: want %s, got %v", raw, code, err)
		}
	}
}

func TestAdmittedChannelBindsIdentity(t *testing.T) {
	vectors, keys := loadChannelVectors(t)
	v := vectors["bridge.channel-auth.valid"]
	clock := clockAt(v.transcript)
	server := serverFor(clock, v.transcript)
	mustOf(t)(server.Receive(b64(t, v.Related["helloEnvelopeBase64"])))
	mustOf(t)(server.Receive(b64(t, v.Related["proofEnvelopeBase64"])))
	admitted := server.Admitted
	mallory := NewEd25519PublicIdentity(v.transcript.Identity.UUID, keys["mallory"].Public().(ed25519.PublicKey))
	wantCode(t, admitted.CheckIdentity(&mallory, true, clock.wall), "identityMismatch")
	wantCode(t, admitted.CheckIdentity(nil, true, clock.wall), "identityMismatch")
	if err := admitted.CheckIdentity(nil, false, clock.wall); err != nil {
		t.Fatal(err)
	}
	wantCode(t, admitted.Check(clock.wall.Add(ChannelLifetime)), "expired")
}
