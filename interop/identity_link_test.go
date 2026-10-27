// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package interop

// test.interop.extend (Go): entity extension completion against the Swift
// fixtures, plus a credential and presentation built in Go from the same
// inputs, which must carry the same signatures.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type linkFixtures struct {
	cases       map[string]fixtureCase
	keys        map[string]ed25519.PrivateKey
	descriptors map[string]IdentityPublicKeyDescriptor
	verifyAt    time.Time
}

func loadLinkFixtures(t *testing.T) linkFixtures {
	t.Helper()
	manifest, _ := loadFixtures(t)
	out := linkFixtures{cases: map[string]fixtureCase{}, keys: map[string]ed25519.PrivateKey{},
		descriptors: map[string]IdentityPublicKeyDescriptor{}, verifyAt: time.Unix(manifest.VerifyAtEpoch, 0)}
	for _, party := range manifest.Parties {
		seed, _ := hex.DecodeString(party.SeedHex)
		out.keys[party.Name] = ed25519.NewKeyFromSeed(seed)
		var descriptor IdentityPublicKeyDescriptor
		if err := Decode(party.Descriptor, &descriptor); err != nil {
			t.Fatal(err)
		}
		out.descriptors[party.Name] = descriptor
	}
	for _, entry := range manifest.Cases {
		data, err := os.ReadFile(filepath.Join("testdata", "v1", entry.File))
		if err != nil {
			t.Fatal(err)
		}
		var c fixtureCase
		if err := json.Unmarshal(data, &c); err != nil {
			t.Fatal(err)
		}
		switch c.Type {
		case "VCClaim", "VCPresentation", "IdentityLinkCompletionEnvelope":
			out.cases[c.ID] = c
		}
	}
	if len(out.cases) != 11 {
		t.Fatalf("want 11 VC chain cases, got %d", len(out.cases))
	}
	return out
}

func decodeLinkModel(t *testing.T, c fixtureCase) Model {
	t.Helper()
	var model Model
	switch c.Type {
	case "VCClaim":
		model = &VCClaim{}
	case "VCPresentation":
		model = &VCPresentation{}
	case "IdentityLinkCompletionEnvelope":
		model = &IdentityLinkCompletionEnvelope{}
	}
	if err := Decode(b64(t, c.EncodedBase64), model); err != nil {
		t.Fatalf("%s: %v", c.ID, err)
	}
	return model
}

func signerFunc(key ed25519.PrivateKey) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) { return ed25519.Sign(key, data), nil }
}

func TestLinkFixturesWireAndSignedBytesMatchSwift(t *testing.T) {
	f := loadLinkFixtures(t)
	for id, c := range f.cases {
		model := decodeLinkModel(t, c)
		encoded, err := EncodedJSON(model)
		if err != nil || !bytes.Equal(encoded, b64(t, c.EncodedBase64)) {
			t.Fatalf("%s: wire JSON differs (%v)\n got %s", id, err, encoded)
		}
		signed, err := SignedBytes(model)
		if err != nil || !bytes.Equal(signed, b64(t, c.CanonicalBase64)) {
			t.Fatalf("%s: signed bytes differ (%v)\n got %s\nwant %s", id, err, signed, b64(t, c.CanonicalBase64))
		}
		if got := VerifySignature(b64(t, c.SignatureBase64), signed, signerOf(t, c)); got != c.Expect.SignatureValid {
			t.Fatalf("%s: signature valid = %v", id, got)
		}
	}
}

func TestLinkFixturesVerdictsMatchSwift(t *testing.T) {
	f := loadLinkFixtures(t)
	var challenge []byte
	{
		valid := decodeLinkModel(t, f.cases["extend.completion.valid"]).(*IdentityLinkCompletionEnvelope)
		challenge = valid.ExpectedPresentationChallenge
	}
	for id, c := range f.cases {
		verdict := ""
		switch model := decodeLinkModel(t, c).(type) {
		case *VCClaim:
			verdict = map[bool]string{true: "valid", false: "invalid"}[model.Verify(f.descriptors["alice"])]
		case *VCPresentation:
			verdict = map[bool]string{true: "valid", false: "invalid"}[model.VerifyHolderProof(challenge, "staging.haven.digipomps.org")]
		case *IdentityLinkCompletionEnvelope:
			result, err := VerifyCompletion(model, f.verifyAt, nil, nil)
			verdict = VerdictOf(err)
			if err == nil {
				record, _ := EncodedJSON(&result.Record)
				if !bytes.Equal(record, b64(t, c.Related["recordBase64"])) {
					t.Fatalf("%s: record differs\n got %s", id, record)
				}
			}
		}
		if verdict != c.Expect.Verdict {
			t.Fatalf("%s: verdict %s, Swift says %s", id, verdict, c.Expect.Verdict)
		}
	}
}

func TestDIDKeyMatchesSwift(t *testing.T) {
	f := loadLinkFixtures(t)
	related := f.cases["extend.credential.valid"].Related
	for name, key := range map[string]string{"alice": "issuerDID", "bob": "holderDID"} {
		did, err := DIDKey(f.descriptors[name])
		if err != nil || did != related[key] {
			t.Fatalf("%s: %s vs %s", name, did, related[key])
		}
	}
	curve, key, err := PublicKeyFromDIDKey(related["holderDID"])
	if err != nil || curve != "Curve25519" || !bytes.Equal(key, f.descriptors["bob"].PublicKey) {
		t.Fatalf("decode: %v", err)
	}
	for _, data := range [][]byte{{}, {0}, {0, 0, 1}, append([]byte{0xed, 0x01}, make([]byte, 32)...)} {
		back, err := Base58Decode(Base58Encode(data))
		if err != nil || !bytes.Equal(back, data) {
			t.Fatalf("base58 round trip %x -> %x", data, back)
		}
	}
}

func TestReplayedApprovalIsRefused(t *testing.T) {
	f := loadLinkFixtures(t)
	envelope := decodeLinkModel(t, f.cases["extend.completion.valid"]).(*IdentityLinkCompletionEnvelope)
	_, err := VerifyCompletion(envelope, f.verifyAt, map[string]bool{envelope.Approval.JTI: true}, nil)
	if VerdictOf(err) != "replayDetected" {
		t.Fatalf("err = %v", err)
	}
}

func lastSegment(id string) string { return id[strings.LastIndex(id, "/")+1:] }

func TestGoBuiltCredentialAndPresentationEqualSwift(t *testing.T) {
	f := loadLinkFixtures(t)
	valid := decodeLinkModel(t, f.cases["extend.completion.valid"]).(*IdentityLinkCompletionEnvelope)
	swiftClaim := valid.SameEntityCredential
	subject := map[string]any{}
	for key, value := range swiftClaim.CredentialSubject.(map[string]any) {
		if key != "id" {
			subject[key] = value
		}
	}
	issued, _ := ParseISO8601(swiftClaim.IssuanceDate)
	claim, err := IssueVCClaim(CredentialTypeSameEntity, f.descriptors["alice"], valid.Request.NewIdentity, subject,
		signerFunc(f.keys["alice"]), lastSegment(swiftClaim.ID), issued)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := EncodedJSON(claim)
	want, _ := EncodedJSON(&swiftClaim)
	if !bytes.Equal(got, want) {
		t.Fatalf("credential differs\n got %s\nwant %s", got, want)
	}
	swiftPresentation := valid.Presentation
	created, _ := ParseISO8601(swiftPresentation.Proof.Created)
	presentation, err := BindAndSignPresentation([]VCClaim{*claim}, f.descriptors["bob"], signerFunc(f.keys["bob"]),
		swiftPresentation.Challenge, *swiftPresentation.Domain, lastSegment(swiftPresentation.ID), created)
	if err != nil {
		t.Fatal(err)
	}
	got, _ = EncodedJSON(presentation)
	want, _ = EncodedJSON(&swiftPresentation)
	if !bytes.Equal(got, want) {
		t.Fatalf("presentation differs\n got %s\nwant %s", got, want)
	}
}

func TestGoApproverAndNewKeyCompleteALink(t *testing.T) {
	f := loadLinkFixtures(t)
	valid := decodeLinkModel(t, f.cases["extend.completion.valid"]).(*IdentityLinkCompletionEnvelope)
	request := valid.Request
	now := f.verifyAt.Add(-30 * time.Second)
	pkg, err := ApproveEnrollment(&IdentityLinkApprovalEnvelope{Request: request, IssuerType: "existingDevice",
		FreshAuthRequired: true, ApprovedScopes: []string{"chat.read"}},
		f.descriptors["alice"], signerFunc(f.keys["alice"]), now, "APR-GO-0001", "C1A10000-0000-4000-8000-0000000000F2")
	if err != nil {
		t.Fatal(err)
	}
	challenge := bytes.Repeat([]byte{7}, 32)
	presentation, err := BindAndSignPresentation([]VCClaim{pkg.SameEntityCredential}, request.NewIdentity, signerFunc(f.keys["bob"]),
		challenge, "node.example", "9E5E0000-0000-4000-8000-0000000000F2", now)
	if err != nil {
		t.Fatal(err)
	}
	envelope := &IdentityLinkCompletionEnvelope{
		Request: request, Approval: pkg.Approval, SameEntityCredential: pkg.SameEntityCredential, Presentation: *presentation,
		IssuerIdentity: pkg.IssuerIdentity, ExpectedAudience: request.Audience, ExpectedOrigin: request.Origin,
		ExpectedPresentationChallenge: challenge, ExpectedPresentationDomain: "node.example",
	}
	data, err := EncodedJSON(envelope)
	if err != nil {
		t.Fatal(err)
	}
	var back IdentityLinkCompletionEnvelope
	if err := Decode(data, &back); err != nil {
		t.Fatal(err)
	}
	result, err := VerifyCompletion(&back, f.verifyAt, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Record.ApprovedScopes) != 1 || result.Record.ApprovedScopes[0] != "chat.read" {
		t.Fatalf("record = %+v", result.Record)
	}
	_ = base64.StdEncoding
}
