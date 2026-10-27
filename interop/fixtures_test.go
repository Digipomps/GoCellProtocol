// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package interop

// test.interop.fixtures (Go): GoCellProtocol reproduces Swift byte for byte.
// For every case in testdata/v1 (copied from CellProtocol fixtures/interop/v1)
// decode the wire JSON, re-encode it, and compare canonical bytes, signature
// verdict and verifier verdict with what Swift produced.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

type fixtureCase struct {
	ID                   string            `json:"id"`
	Flow                 string            `json:"flow"`
	Type                 string            `json:"type"`
	EncodedBase64        string            `json:"encodedBase64"`
	CanonicalBase64      string            `json:"canonicalBase64"`
	SignatureBase64      string            `json:"signatureBase64"`
	Signer               json.RawMessage   `json:"signer"`
	ExcludedTopLevelKeys []string          `json:"excludedTopLevelKeys"`
	Related              map[string]string `json:"related"`
	Expect               struct {
		SignatureValid bool   `json:"signatureValid"`
		Verdict        string `json:"verdict"`
	} `json:"expect"`
}

type fixtureManifest struct {
	VerifyAtEpoch int64 `json:"verifyAtEpoch"`
	Parties       []struct {
		Name       string          `json:"name"`
		SeedHex    string          `json:"seedHex"`
		Descriptor json.RawMessage `json:"descriptor"`
	} `json:"parties"`
	Cases []struct {
		ID   string `json:"id"`
		File string `json:"file"`
		Flow string `json:"flow"`
	} `json:"cases"`
}

func loadFixtures(t *testing.T) (fixtureManifest, map[string]fixtureCase) {
	t.Helper()
	dir := filepath.Join("testdata", "v1")
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest fixtureManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	cases := map[string]fixtureCase{}
	for _, entry := range manifest.Cases {
		data, err := os.ReadFile(filepath.Join(dir, entry.File))
		if err != nil {
			t.Fatal(err)
		}
		var c fixtureCase
		if err := json.Unmarshal(data, &c); err != nil {
			t.Fatal(err)
		}
		cases[c.ID] = c
	}
	return manifest, cases
}

func b64(t *testing.T, text string) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func decodeCase(t *testing.T, c fixtureCase) Model {
	t.Helper()
	model, err := NewModel(c.Type)
	if err != nil {
		t.Fatal(err)
	}
	if err := Decode(b64(t, c.EncodedBase64), model); err != nil {
		t.Fatalf("%s: %v", c.ID, err)
	}
	return model
}

func signerOf(t *testing.T, c fixtureCase) IdentityPublicKeyDescriptor {
	t.Helper()
	var descriptor IdentityPublicKeyDescriptor
	if err := Decode(c.Signer, &descriptor); err != nil {
		t.Fatal(err)
	}
	return descriptor
}

func sortedIDs(cases map[string]fixtureCase) []string {
	ids := make([]string, 0, len(cases))
	for id := range cases {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func TestFixturesCoverAllFlows(t *testing.T) {
	manifest, cases := loadFixtures(t)
	flows := map[string]bool{}
	for _, entry := range manifest.Cases {
		flows[entry.Flow] = true
	}
	for _, flow := range []string{"extend", "invite", "chat", "bridge"} {
		if !flows[flow] {
			t.Errorf("no %s cases", flow)
		}
	}
	if len(cases) < 28 {
		t.Errorf("only %d cases", len(cases))
	}
}

func TestFixturesWireJSONRoundTrip(t *testing.T) {
	_, cases := loadFixtures(t)
	for _, id := range sortedIDs(cases) {
		c := cases[id]
		got, err := EncodedJSON(decodeCase(t, c))
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if want := b64(t, c.EncodedBase64); !bytes.Equal(got, want) {
			t.Errorf("%s: wire JSON differs\n got %s\nwant %s", id, got, want)
		}
	}
}

func TestFixturesCanonicalBytesMatchSwift(t *testing.T) {
	_, cases := loadFixtures(t)
	for _, id := range sortedIDs(cases) {
		c := cases[id]
		got, err := SignedBytes(decodeCase(t, c))
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if want := b64(t, c.CanonicalBase64); !bytes.Equal(got, want) {
			t.Errorf("%s: canonical bytes differ\n got %s\nwant %s", id, got, want)
		}
	}
}

func TestFixturesSignatureVerdict(t *testing.T) {
	_, cases := loadFixtures(t)
	for _, id := range sortedIDs(cases) {
		c := cases[id]
		var signature []byte
		if c.SignatureBase64 != "" {
			signature = b64(t, c.SignatureBase64)
		}
		if got := VerifySignature(signature, b64(t, c.CanonicalBase64), signerOf(t, c)); got != c.Expect.SignatureValid {
			t.Errorf("%s: signature valid = %v, Swift says %v", id, got, c.Expect.SignatureValid)
		}
	}
}

func TestFixturesVerifierVerdictMatchesSwift(t *testing.T) {
	manifest, cases := loadFixtures(t)
	now := time.Unix(manifest.VerifyAtEpoch, 0).UTC()
	related := func(c fixtureCase, name string) Model { return decodeCase(t, cases[c.Related[name]]) }
	for _, id := range sortedIDs(cases) {
		c := cases[id]
		model := decodeCase(t, c)
		var got string
		switch m := model.(type) {
		case *IdentityEnrollmentRequest, *IdentityEnrollmentApproval, *IdentityLinkRevocation:
			// v1 records the envelope signature only for the extend flow.
			payload, _ := SignedBytes(model)
			var signature []byte
			switch e := m.(type) {
			case *IdentityEnrollmentRequest:
				signature = e.Proof.Signature
			case *IdentityEnrollmentApproval:
				signature = e.Proof.Signature
			case *IdentityLinkRevocation:
				signature = e.Proof.Signature
			}
			got = "bad_signature"
			if VerifySignature(signature, payload, signerOf(t, c)) {
				got = "valid"
			}
		case *HavenInviteTicket:
			got = VerifyTicket(m, now, TicketOptions{})
		case *HavenInvitePublication:
			_, err := VerifyPublication(m, now)
			got = VerdictOf(err)
		case *HavenInviteReply:
			got = VerdictOf(VerifyReply(m, related(c, "ticket").(*HavenInviteTicket), now))
		case *HavenInviteRevocationNotice:
			got = VerdictOf(VerifyRevocationNotice(m, related(c, "ticket").(*HavenInviteTicket)))
		case *HavenInviteContactRequest:
			got = VerdictOf(VerifyContactRequest(m, related(c, "ticket").(*HavenInviteTicket), now))
		case *ChatInvitationArtifact:
			got = VerdictOf(VerifyChatInvitation(m, now, ChatOptions{}))
		case *ChatInvitationAcceptance:
			got = VerdictOf(VerifyChatAcceptance(m, related(c, "invitation").(*ChatInvitationArtifact), now, nil))
		case *IdentitySigningChallenge:
			_, err := ValidateSigningChallenge(b64(t, c.CanonicalBase64), signerOf(t, c), now)
			got = VerdictOf(err)
		default:
			t.Fatalf("%s: no verifier for %T", id, model)
		}
		if got != c.Expect.Verdict {
			t.Errorf("%s: verdict %q, Swift says %q", id, got, c.Expect.Verdict)
		}
	}
}

func TestFixturesDerivedValues(t *testing.T) {
	_, cases := loadFixtures(t)
	request := decodeCase(t, cases["extend.request.valid"]).(*IdentityEnrollmentRequest)
	hash, err := RequestHash(request)
	if err != nil || !bytes.Equal(hash, b64(t, cases["extend.request.valid"].Related["requestHashBase64"])) {
		t.Errorf("request hash differs: %v", err)
	}
	artifact := decodeCase(t, cases["chat.invitation.valid"]).(*ChatInvitationArtifact)
	invitationHash, err := InvitationHash(artifact)
	if err != nil || !bytes.Equal(invitationHash, b64(t, cases["chat.invitation.valid"].Related["invitationHashBase64"])) {
		t.Errorf("invitation hash differs: %v", err)
	}
	ticket := decodeCase(t, cases["invite.ticket.valid"]).(*HavenInviteTicket)
	token, err := ticket.Token()
	if err != nil || token != cases["invite.ticket.valid"].Related["ticketToken"] {
		t.Errorf("ticket token differs: %v", err)
	}
	if _, err := TicketFromToken(token); err != nil {
		t.Errorf("token does not decode: %v", err)
	}
}

func TestGoSignedTicketEqualsSwiftSignature(t *testing.T) {
	manifest, cases := loadFixtures(t)
	var seed []byte
	for _, party := range manifest.Parties {
		if party.Name == "alice" {
			seed, _ = hex.DecodeString(party.SeedHex)
		}
	}
	key := ed25519.NewKeyFromSeed(seed)
	swift := decodeCase(t, cases["invite.ticket.valid"]).(*HavenInviteTicket)
	mine := *swift
	mine.Proof = nil
	if err := Sign(&mine, key, swift.Issuer.UUID); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mine.Proof.Signature, swift.Proof.Signature) {
		t.Error("Ed25519 is deterministic: Go and Swift signatures over the same bytes should be equal")
	}
	now := time.Unix(manifest.VerifyAtEpoch, 0)
	if got := VerifyTicket(&mine, now, TicketOptions{}); got != "valid" {
		t.Errorf("Go-signed ticket: %s", got)
	}
}

func TestFoundationKeyOrder(t *testing.T) {
	got := SortedKeys([]string{"requestID", "requestedScopes", "requestedDomains"}, FoundationOrder)
	want := []string{"requestedDomains", "requestedScopes", "requestID"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("foundation order %v, want %v", got, want)
		}
	}
	got = SortedKeys([]string{"k10", "k9", "K1"}, FoundationOrder)
	want = []string{"K1", "k9", "k10"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("numeric order %v, want %v", got, want)
		}
	}
	if encoder := SortedKeys([]string{"requestedDomains", "requestID"}, EncoderOrder); encoder[0] != "requestID" {
		t.Fatalf("encoder order %v", encoder)
	}
}

func TestCanonicalEscaping(t *testing.T) {
	got, err := CanonicalJSON(map[string]any{"a": "x/y \"q\" \\ \n\t\u0001 æ 🙂 <&>"}, FoundationOrder)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":"x\/y \"q\" \\ \n\t\u0001 æ 🙂 <&>"}`
	if string(got) != want {
		t.Errorf("got %s want %s", got, want)
	}
}
