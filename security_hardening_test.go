// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBridgeAgreementAdmissionDelegatesAndFailsClosed(t *testing.T) {
	ctx := context.Background()
	vault := NewInMemoryIdentityVault()
	owner, _ := vault.Identity(ctx, "owner", true)
	guest, _ := vault.Identity(ctx, "guest", true)
	cell := NewGeneralCell(owner, "Secure")
	endpoint := NewBridgeEndpoint(cell, owner)
	agreement := NewAgreement(owner)
	agreement.Grants = []Grant{NewGrant("", "private", "rw--")}

	responses := endpoint.Handle(ctx, BridgeCommand{
		Cmd:      "agreement",
		CID:      1,
		Identity: guest,
		Payload:  TypedValue{Kind: "agreementPayload", Value: agreement},
	})
	if len(responses) != 1 {
		t.Fatalf("agreement response count = %d", len(responses))
	}
	typed := responses[0].Payload.(TypedValue)
	if typed.Kind != "agreementState" || typed.Value != string(AgreementRejected) {
		t.Fatalf("agreement response = %#v", typed)
	}
	if _, err := cell.Set(ctx, "private.secret", "denied", guest); err == nil {
		t.Fatalf("rejected bridge agreement installed an arbitrary grant")
	}

	missingIdentity := endpoint.Handle(ctx, BridgeCommand{
		Cmd:     "agreement",
		CID:     2,
		Payload: TypedValue{Kind: "agreementPayload", Value: agreement},
	})[0].Payload.(TypedValue)
	if missingIdentity.Kind != "agreementState" || missingIdentity.Value != string(AgreementRejected) {
		t.Fatalf("missing-identity agreement response = %#v", missingIdentity)
	}
}

func TestResolverConcurrentIdentityAndScaffoldScopesAreUnique(t *testing.T) {
	ctx := context.Background()
	vault := NewInMemoryIdentityVault()
	alice, _ := vault.Identity(ctx, "alice", true)
	bob, _ := vault.Identity(ctx, "bob", true)

	for _, testCase := range []struct {
		name  string
		scope CellUsageScope
	}{
		{name: "scaffold", scope: ScopeScaffoldUnique},
		{name: "identity", scope: ScopeIdentityUnique},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			resolver := NewCellResolver()
			var factoryCalls atomic.Int32
			factory := func(ctx context.Context, owner *Identity) (CellProtocol, error) {
				factoryCalls.Add(1)
				return NewGeneralCell(owner, "Concurrent"), nil
			}
			if err := resolver.RegisterNamedEmitCell(ctx, "Concurrent", nil, RegisterOptions{
				Factory: factory,
				Scope:   testCase.scope,
			}); err != nil {
				t.Fatal(err)
			}

			const requests = 64
			start := make(chan struct{})
			results := make(chan struct {
				requester string
				uuid      string
				err       error
			}, requests)
			var workers sync.WaitGroup
			for index := 0; index < requests; index++ {
				requester := alice
				if testCase.scope == ScopeIdentityUnique && index%2 == 1 {
					requester = bob
				}
				workers.Add(1)
				go func(requester *Identity) {
					defer workers.Done()
					<-start
					cell, err := resolver.CellAtEndpoint(ctx, "cell:///Concurrent", requester)
					uuid := ""
					if cell != nil {
						uuid = cell.CellUUID()
					}
					results <- struct {
						requester string
						uuid      string
						err       error
					}{requester: requester.UUID, uuid: uuid, err: err}
				}(requester)
			}
			close(start)
			workers.Wait()
			close(results)

			uuidsByRequester := map[string]map[string]struct{}{}
			for result := range results {
				if result.err != nil {
					t.Fatalf("resolve failed: %v", result.err)
				}
				if result.uuid == "" {
					t.Fatalf("resolved cell has no UUID")
				}
				if uuidsByRequester[result.requester] == nil {
					uuidsByRequester[result.requester] = map[string]struct{}{}
				}
				uuidsByRequester[result.requester][result.uuid] = struct{}{}
			}

			if testCase.scope == ScopeScaffoldUnique {
				all := map[string]struct{}{}
				for _, uuids := range uuidsByRequester {
					for uuid := range uuids {
						all[uuid] = struct{}{}
					}
				}
				if len(all) != 1 || factoryCalls.Load() != 1 {
					t.Fatalf("scaffold scope instances=%d factoryCalls=%d", len(all), factoryCalls.Load())
				}
				return
			}

			if len(uuidsByRequester[alice.UUID]) != 1 || len(uuidsByRequester[bob.UUID]) != 1 {
				t.Fatalf("identity scope instances = %#v", uuidsByRequester)
			}
			var aliceUUID, bobUUID string
			for uuid := range uuidsByRequester[alice.UUID] {
				aliceUUID = uuid
			}
			for uuid := range uuidsByRequester[bob.UUID] {
				bobUUID = uuid
			}
			if aliceUUID == bobUUID || factoryCalls.Load() != 2 {
				t.Fatalf("identity scope alice=%s bob=%s factoryCalls=%d", aliceUUID, bobUUID, factoryCalls.Load())
			}
		})
	}
}

func TestBridgeEndpointSignsOnlyCanonicalNonReplayChallenge(t *testing.T) {
	ctx := context.Background()
	owner, _ := NewInMemoryIdentityVault().Identity(ctx, "owner", true)
	attacker, _ := NewInMemoryIdentityVault().Identity(ctx, "attacker", true)
	endpoint := NewBridgeEndpoint(NewGeneralCell(owner, "Signer"), owner)
	wireIdentity := cloneWireIdentity(t, owner)

	denied := endpoint.Handle(ctx, BridgeCommand{
		Cmd:      "sign",
		CID:      1,
		Identity: wireIdentity,
		Payload:  TypedValue{Kind: "signData", Value: []byte("arbitrary bytes")},
	})[0].Payload.(TypedValue)
	if denied.Kind != "setValueResponse" || !strings.Contains(denied.Value.(SetValueResponse).Value.(string), "signing denied") {
		t.Fatalf("arbitrary sign response = %#v", denied)
	}

	now := time.Now()
	challengeData := makeSigningChallenge(t, owner, now, 0x41)
	wrongIdentity := endpoint.Handle(ctx, BridgeCommand{
		Cmd:      "sign",
		CID:      2,
		Identity: cloneWireIdentity(t, attacker),
		Payload:  TypedValue{Kind: "signData", Value: challengeData},
	})[0].Payload.(TypedValue)
	if wrongIdentity.Kind != "setValueResponse" || !strings.Contains(wrongIdentity.Value.(SetValueResponse).Value.(string), "signing denied") {
		t.Fatalf("wrong-identity sign response = %#v", wrongIdentity)
	}

	signed := endpoint.Handle(ctx, BridgeCommand{
		Cmd:      "sign",
		CID:      3,
		Identity: wireIdentity,
		Payload:  TypedValue{Kind: "signData", Value: challengeData},
	})[0].Payload.(TypedValue)
	if signed.Kind != "signature" {
		t.Fatalf("canonical sign response = %#v", signed)
	}
	verified, err := owner.Verify(ctx, signed.Value.([]byte), challengeData)
	if err != nil || !verified {
		t.Fatalf("canonical challenge signature verified=%v err=%v", verified, err)
	}

	replay := endpoint.Handle(ctx, BridgeCommand{
		Cmd:      "sign",
		CID:      4,
		Identity: wireIdentity,
		Payload:  TypedValue{Kind: "signData", Value: challengeData},
	})[0].Payload.(TypedValue)
	if replay.Kind != "setValueResponse" || !strings.Contains(replay.Value.(SetValueResponse).Value.(string), "replay") {
		t.Fatalf("replayed sign response = %#v", replay)
	}
}

func TestIdentitySigningChallengeValidationRejectsInvalidCanonicalFields(t *testing.T) {
	ctx := context.Background()
	identity, _ := NewInMemoryIdentityVault().Identity(ctx, "challenge", true)
	now := time.Now()
	baseData := makeSigningChallenge(t, identity, now, 0x43)

	tests := []struct {
		name   string
		mutate func(*identitySigningChallenge)
	}{
		{name: "type", mutate: func(value *identitySigningChallenge) { value.Type = "wrong" }},
		{name: "version", mutate: func(value *identitySigningChallenge) { value.Version++ }},
		{name: "purpose", mutate: func(value *identitySigningChallenge) { value.Purpose = "arbitrary-signing" }},
		{name: "identity", mutate: func(value *identitySigningChallenge) { value.IdentityUUID = "forged" }},
		{name: "fingerprint", mutate: func(value *identitySigningChallenge) { value.PublicKeyFingerprint = "EdDSA:Curve25519:forged" }},
		{name: "nonce", mutate: func(value *identitySigningChallenge) {
			value.Nonce = make([]byte, identitySigningChallengeMinimumNonce-1)
		}},
		{name: "scope", mutate: func(value *identitySigningChallenge) { value.Domain = "" }},
		{name: "scope-size", mutate: func(value *identitySigningChallenge) {
			value.Audience = strings.Repeat("a", identitySigningChallengeMaximumScope+1)
		}},
		{name: "validity", mutate: func(value *identitySigningChallenge) {
			value.ExpiresAt = value.IssuedAt + identitySigningChallengeValiditySeconds + 1
		}},
		{name: "future", mutate: func(value *identitySigningChallenge) {
			value.IssuedAt = float64(now.Unix()) + identitySigningChallengeClockSkewSeconds + 1
			value.ExpiresAt = value.IssuedAt + identitySigningChallengeValiditySeconds
		}},
		{name: "expired", mutate: func(value *identitySigningChallenge) {
			value.IssuedAt = float64(now.Unix()) - identitySigningChallengeValiditySeconds
			value.ExpiresAt = float64(now.Unix()) - 1
		}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			var challenge identitySigningChallenge
			if err := json.Unmarshal(baseData, &challenge); err != nil {
				t.Fatal(err)
			}
			testCase.mutate(&challenge)
			data, err := json.Marshal(challenge)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := validateIdentitySigningChallenge(data, identity, now); err == nil {
				t.Fatalf("invalid %s challenge was accepted", testCase.name)
			}
		})
	}

	oversized := append(append([]byte(nil), baseData...), make([]byte, identitySigningChallengeMaximumBytes)...)
	if _, err := validateIdentitySigningChallenge(oversized, identity, now); err == nil {
		t.Fatalf("oversized challenge was accepted")
	}
}

func TestCloudBridgeSignsOnlyCanonicalNonReplayChallenge(t *testing.T) {
	ctx := context.Background()
	identity, _ := NewInMemoryIdentityVault().Identity(ctx, "client", true)
	bridge := NewCloudBridge("wss://unused.invalid", identity, DefaultCloudBridgeOptions())
	wireIdentity := cloneWireIdentity(t, identity)
	now := time.Now()
	preReadyChallenge := makeSigningChallenge(t, identity, now, 0x44)
	preReady := captureCloudBridgeSignResponse(t, bridge, BridgeCommand{
		Cmd:      "sign",
		CID:      1,
		Identity: wireIdentity,
		Payload:  TypedValue{Kind: "signData", Value: preReadyChallenge},
	})
	if typed := preReady.Payload.(TypedValue); typed.Kind != "string" || !strings.Contains(typed.Value.(string), "not ready") {
		t.Fatalf("pre-ready cloud sign response = %#v", preReady.Payload)
	}
	bridge.markReady()

	denied := captureCloudBridgeSignResponse(t, bridge, BridgeCommand{
		Cmd:      "sign",
		CID:      2,
		Identity: wireIdentity,
		Payload:  TypedValue{Kind: "signData", Value: []byte("arbitrary bytes")},
	})
	if typed := denied.Payload.(TypedValue); typed.Kind != "string" || !strings.Contains(typed.Value.(string), "signing denied") {
		t.Fatalf("arbitrary cloud sign response = %#v", denied.Payload)
	}

	challengeData := makeSigningChallenge(t, identity, now, 0x42)
	signed := captureCloudBridgeSignResponse(t, bridge, BridgeCommand{
		Cmd:      "sign",
		CID:      3,
		Identity: wireIdentity,
		Payload:  TypedValue{Kind: "signData", Value: challengeData},
	})
	typedSignature := signed.Payload.(TypedValue)
	if typedSignature.Kind != "signature" {
		t.Fatalf("canonical cloud sign response = %#v", typedSignature)
	}
	verified, err := identity.Verify(ctx, typedSignature.Value.([]byte), challengeData)
	if err != nil || !verified {
		t.Fatalf("cloud signature verified=%v err=%v", verified, err)
	}

	replay := captureCloudBridgeSignResponse(t, bridge, BridgeCommand{
		Cmd:      "sign",
		CID:      4,
		Identity: wireIdentity,
		Payload:  TypedValue{Kind: "signData", Value: challengeData},
	})
	if typed := replay.Payload.(TypedValue); typed.Kind != "string" || !strings.Contains(typed.Value.(string), "replay") {
		t.Fatalf("replayed cloud sign response = %#v", replay.Payload)
	}

	bridge.mu.Lock()
	bridge.sessionReady = false
	bridge.mu.Unlock()
	freshAfterReconnect := makeSigningChallenge(t, identity, time.Now(), 0x45)
	staleReady := captureCloudBridgeSignResponse(t, bridge, BridgeCommand{
		Cmd:      "sign",
		CID:      5,
		Identity: wireIdentity,
		Payload:  TypedValue{Kind: "signData", Value: freshAfterReconnect},
	})
	if typed := staleReady.Payload.(TypedValue); typed.Kind != "string" || !strings.Contains(typed.Value.(string), "not ready") {
		t.Fatalf("stale-ready cloud sign response = %#v", staleReady.Payload)
	}
}

func makeSigningChallenge(t *testing.T, identity *Identity, now time.Time, nonceByte byte) []byte {
	t.Helper()
	fingerprint, err := signingPublicKeyFingerprint(identity)
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := float64(now.UnixNano())/float64(time.Second) - 1
	challenge := identitySigningChallenge{
		Type:                 identitySigningChallengeType,
		Version:              identitySigningChallengeVersion,
		Purpose:              identitySigningChallengePurpose,
		IdentityUUID:         identity.UUID,
		PublicKeyFingerprint: fingerprint,
		Domain:               "test.local",
		Resource:             "cell:///Signer",
		Action:               "checkIdentityOrigin",
		Audience:             "GoCellProtocolTests",
		Nonce:                []byte(strings.Repeat(string([]byte{nonceByte}), identitySigningChallengeMinimumNonce)),
		IssuedAt:             issuedAt,
		ExpiresAt:            issuedAt + identitySigningChallengeValiditySeconds,
	}
	data, err := json.Marshal(challenge)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func cloneWireIdentity(t *testing.T, identity *Identity) *Identity {
	t.Helper()
	data, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	var clone Identity
	if err := DecodeJSON(data, &clone); err != nil {
		t.Fatal(err)
	}
	return &clone
}

func captureCloudBridgeSignResponse(t *testing.T, bridge *CloudBridge, command BridgeCommand) BridgeCommand {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	bridge.mu.Lock()
	bridge.socket = &webSocketClient{
		conn:     client,
		reader:   bufio.NewReader(client),
		maxBytes: defaultWebSocketMaxMessageBytes,
	}
	bridge.connected = true
	bridge.mu.Unlock()
	done := make(chan struct{})
	go func() {
		bridge.handleSignCommand(command)
		close(done)
	}()
	opcode, payload, err := readWebSocketFrame(bufio.NewReader(server), defaultWebSocketMaxMessageBytes)
	if err != nil {
		t.Fatal(err)
	}
	if opcode != webSocketOpcodeText {
		t.Fatalf("sign response opcode = %d", opcode)
	}
	var response BridgeCommand
	if err := DecodeJSON(payload, &response); err != nil {
		t.Fatal(err)
	}
	<-done
	bridge.mu.Lock()
	bridge.socket = nil
	bridge.mu.Unlock()
	return response
}
