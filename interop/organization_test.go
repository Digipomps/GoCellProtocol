// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package interop

// test.ge.interop (Go): an organization owned by a group, against Swift.
// Every org.* case in testdata/v1 (copied from CellProtocol) is decoded,
// re-encoded, and checked for signed bytes, signature and verdict. The shared
// access table org.access-matrix.json is the Go column of the condition
// matrix, and the native tests repeat the Swift test.ge.* scenarios.

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

type orgFixtures struct {
	cases       map[string]fixtureCase
	keys        map[string]ed25519.PrivateKey
	descriptors map[string]IdentityPublicKeyDescriptor
	verifyAt    time.Time
}

func loadOrgFixtures(t *testing.T) orgFixtures {
	t.Helper()
	manifest, _ := loadFixtures(t)
	out := orgFixtures{cases: map[string]fixtureCase{}, keys: map[string]ed25519.PrivateKey{},
		descriptors: map[string]IdentityPublicKeyDescriptor{}, verifyAt: time.Unix(manifest.VerifyAtEpoch, 0).UTC()}
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
		if entry.Flow != "org" {
			continue
		}
		data, err := os.ReadFile(filepath.Join("testdata", "v1", entry.File))
		if err != nil {
			t.Fatal(err)
		}
		var c fixtureCase
		if err := json.Unmarshal(data, &c); err != nil {
			t.Fatal(err)
		}
		out.cases[c.ID] = c
	}
	if len(out.cases) != 23 {
		t.Fatalf("want 23 org cases, got %d", len(out.cases))
	}
	return out
}

func (f orgFixtures) decode(t *testing.T, id string) Model {
	t.Helper()
	c, ok := f.cases[id]
	if !ok {
		t.Fatalf("no case %s", id)
	}
	model, err := NewOrganizationModel(c.Type)
	if err != nil {
		t.Fatal(err)
	}
	if err := Decode(b64(t, c.EncodedBase64), model); err != nil {
		t.Fatalf("%s: %v", id, err)
	}
	return model
}

func (f orgFixtures) signer(name string) func([]byte) ([]byte, error) {
	key := f.keys[name]
	return func(data []byte) ([]byte, error) { return ed25519.Sign(key, data), nil }
}

func TestOrganizationFixturesBytesAndSignatures(t *testing.T) {
	f := loadOrgFixtures(t)
	for _, id := range sortedIDs(f.cases) {
		c := f.cases[id]
		model := f.decode(t, id)
		encoded, err := EncodedJSON(model)
		if err != nil || !bytes.Equal(encoded, b64(t, c.EncodedBase64)) {
			t.Errorf("%s: wire JSON differs (%v)\n got %s", id, err, encoded)
		}
		signed, err := SignedBytes(model)
		if err != nil || !bytes.Equal(signed, b64(t, c.CanonicalBase64)) {
			t.Errorf("%s: signed bytes differ (%v)\n got %s", id, err, signed)
		}
		if len(c.Signer) > 0 {
			var signature []byte
			if c.SignatureBase64 != "" {
				signature = b64(t, c.SignatureBase64)
			}
			if got := VerifySignature(signature, signed, signerOf(t, c)); got != c.Expect.SignatureValid {
				t.Errorf("%s: signature valid = %v, Swift says %v", id, got, c.Expect.SignatureValid)
			}
		}
	}
}

func TestOrganizationFixturesVerdictMatchesSwift(t *testing.T) {
	f := loadOrgFixtures(t)
	policyOf := func(c fixtureCase) *GovernancePolicy { return f.decode(t, c.Related["policy"]).(*GovernancePolicy) }
	for _, id := range sortedIDs(f.cases) {
		c := f.cases[id]
		var got string
		switch m := f.decode(t, id).(type) {
		case *GovernancePolicy, *OrganizationActionProposal:
			got = "valid"
		case *OrganizationGenesisSeal:
			got = VerdictOf(m.Verify(policyOf(c)))
		case *OrganizationApproval:
			got = map[bool]string{true: "valid", false: "bad_signature"}[m.SignatureIsValid()]
		case *ApprovalBundle:
			got = BundleVerdict(policyOf(c), m, f.verifyAt)
		case *VCClaim:
			got = map[bool]string{true: "valid", false: "invalid"}[VerifyRoleCredential(m)]
		case *OrganizationRoleStatusList:
			got = map[bool]string{true: "valid", false: "bad_signature"}[m.SignatureIsValid()]
		default:
			t.Fatalf("%s: no verifier for %T", id, m)
		}
		if got != c.Expect.Verdict {
			t.Errorf("%s: verdict %q, Swift says %q", id, got, c.Expect.Verdict)
		}
	}
}

func TestOrganizationDerivedHashesAndSummaries(t *testing.T) {
	f := loadOrgFixtures(t)
	for _, id := range []string{"org.policy.v1", "org.policy.v2", "org.policy.all-two"} {
		hash, err := f.decode(t, id).(*GovernancePolicy).PolicyHash()
		if err != nil || !bytes.Equal(hash, b64(t, f.cases[id].Related["policyHashBase64"])) {
			t.Errorf("%s: policy hash differs", id)
		}
	}
	seal := f.decode(t, "org.genesis.valid").(*OrganizationGenesisSeal)
	if hash, _ := seal.SealHash(); !bytes.Equal(hash, b64(t, f.cases["org.genesis.valid"].Related["sealHashBase64"])) {
		t.Error("seal hash differs")
	}
	proposal := f.decode(t, "org.proposal.role-issue").(*OrganizationActionProposal)
	if hash, _ := proposal.ProposalHash(); !bytes.Equal(hash, b64(t, f.cases["org.proposal.role-issue"].Related["proposalHashBase64"])) {
		t.Error("proposal hash differs")
	}
	role := f.cases["org.role.valid"]
	credential := f.decode(t, "org.role.valid").(*VCClaim)
	if hash, _ := RolePayloadHash(credential); !bytes.Equal(hash, b64(t, role.Related["payloadHashBase64"])) || !bytes.Equal(hash, proposal.PayloadHash) {
		t.Error("role payload hash differs")
	}
	if summary := RoleSummary(credential, seal.DisplayName); summary != role.Related["summary"] || summary != proposal.PayloadSummary {
		t.Errorf("role summary %q, Swift says %q", summary, role.Related["summary"])
	}
	v1 := f.decode(t, "org.policy.v1").(*GovernancePolicy)
	v2 := f.decode(t, "org.policy.v2").(*GovernancePolicy)
	amend := f.decode(t, "org.bundle.amend-v2.alice").(*ApprovalBundle)
	if summary := AmendmentSummary(v1, v2); summary != amend.Proposal.PayloadSummary {
		t.Errorf("amendment summary %q, Swift says %q", summary, amend.Proposal.PayloadSummary)
	}
}

func TestOrganizationGoBuildsTheSameAsSwift(t *testing.T) {
	f := loadOrgFixtures(t)
	v1, err := OwnerGroupPolicy("entity:interop-gruppe", 1, nil, []IdentityPublicKeyDescriptor{f.descriptors["alice"]},
		RolesOneGovernanceAll, "2026-10-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	expectEncoded(t, "org.policy.v1", v1, f)
	hash, _ := v1.PolicyHash()
	seal := &OrganizationGenesisSeal{Version: 1, Kind: "organization", AnchorID: "entity:interop-gruppe",
		DisplayName: "Interop-gruppa (test)", InitialPolicyHash: hash, CustodianKey: f.descriptors["custodian"],
		Founders: []IdentityPublicKeyDescriptor{f.descriptors["alice"]}, SealedAt: "2026-10-27T11:58:00Z"}
	if err := seal.Sign(f.descriptors["alice"], f.signer("alice"), "2026-10-27T11:58:00Z"); err != nil {
		t.Fatal(err)
	}
	expectEncoded(t, "org.genesis.valid", seal, f)
	if err := seal.Verify(v1); err != nil {
		t.Fatal(err)
	}
	cohort := "MasterHAVEN26"
	issuedAt, _ := ParseISO8601("2026-10-27T11:59:45Z")
	credential, err := UnsignedRoleCredential("entity:interop-gruppe", "InteropGruppeRoleCredential", f.descriptors["custodian"],
		f.descriptors["bob"], "researcher", &cohort, "2027-06-30", hash, issuedAt, "0201E000-0000-4000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := credential.UnsignedBytes()
	credential.Proof.SignatureData, _ = f.signer("custodian")(data)
	expectEncoded(t, "org.role.valid", credential, f)
	issuerDID, _ := DIDKey(f.descriptors["custodian"])
	status := NewStatusList("entity:interop-gruppe", issuerDID, 2, "2026-10-27T11:59:50Z", []string{credential.ID, credential.ID})
	payload, _ := SignedBytes(status)
	status.Signature, _ = f.signer("custodian")(payload)
	expectEncoded(t, "org.status.v2", status, f)
}

func expectEncoded(t *testing.T, id string, model any, f orgFixtures) {
	t.Helper()
	got, err := EncodedJSON(model)
	if err != nil || !bytes.Equal(got, b64(t, f.cases[id].EncodedBase64)) {
		t.Errorf("%s: Go output differs from Swift (%v)\n got %s", id, err, got)
	}
}

// ---- Native scenarios (test.ge.*), same as the Swift suites ---------------------------

const (
	geAnchor  = "entity:interop-gruppe"
	geCreated = "2026-10-27T11:59:00Z"
	geExpires = "2026-10-27T12:09:00Z"
	geApprove = "2026-10-27T11:59:30Z"
)

func (f orgFixtures) policy(t *testing.T, names []string, agreement OwnershipAgreement, version int64, previous *GovernancePolicy) *GovernancePolicy {
	t.Helper()
	var owners []IdentityPublicKeyDescriptor
	for _, name := range names {
		owners = append(owners, f.descriptors[name])
	}
	var previousHash []byte
	if previous != nil {
		previousHash, _ = previous.PolicyHash()
	}
	policy, err := OwnerGroupPolicy(geAnchor, version, previousHash, owners, agreement, "2026-10-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func (f orgFixtures) proposal(policy *GovernancePolicy, action, proposer, label string) *OrganizationActionProposal {
	hash, _ := policy.PolicyHash()
	return &OrganizationActionProposal{Version: 1, ProposalID: "prop-" + label, OrganizationAnchorID: geAnchor, PolicyHash: hash,
		ActionClass: action, PayloadHash: bytes.Repeat([]byte{1}, 32), PayloadSummary: "test", Audience: geAnchor,
		CreatedAt: geCreated, ExpiresAt: geExpires, Nonce: []byte(label), Proposer: f.descriptors[proposer]}
}

func (f orgFixtures) bundle(t *testing.T, proposal *OrganizationActionProposal, names ...string) *ApprovalBundle {
	t.Helper()
	bundle := &ApprovalBundle{Proposal: *proposal}
	for _, name := range names {
		approval, err := SignApproval(proposal, f.descriptors[name], f.signer(name), geApprove)
		if err != nil {
			t.Fatal(err)
		}
		bundle.Approvals = append(bundle.Approvals, *approval)
	}
	return bundle
}

func (f orgFixtures) amend(t *testing.T, current, next *GovernancePolicy, label string, names ...string) *ApprovalBundle {
	t.Helper()
	proposal, err := AmendmentProposal(current, next, geAnchor, "amend-"+label, f.descriptors["alice"], geCreated, geExpires, []byte(label))
	if err != nil {
		t.Fatal(err)
	}
	return f.bundle(t, proposal, names...)
}

func TestGEOwnerChangeIsANewVersionNeedingAllOwners(t *testing.T) {
	f := loadOrgFixtures(t)
	v1 := f.policy(t, []string{"alice"}, RolesOneGovernanceAll, 1, nil)
	v2 := f.policy(t, []string{"alice", "bob"}, RolesOneGovernanceAll, 2, v1)
	if err := VerifyAmendment(v1, v2, f.amend(t, v1, v2, "v2", "alice"), geAnchor); err != nil {
		t.Fatalf("alice alone may add bob under v1: %v", err)
	}
	v3 := f.policy(t, []string{"alice", "bob", "mallory"}, RolesOneGovernanceAll, 3, v2)
	if err := VerifyAmendment(v2, v3, f.amend(t, v2, v3, "v3", "alice"), geAnchor); err == nil || err.Error() != "approvalsRefused: clauseNotSatisfied" {
		t.Fatalf("alice alone under v2: %v", err)
	}
	if err := VerifyAmendment(v2, v3, f.amend(t, v2, v3, "v3b", "alice", "bob"), geAnchor); err != nil {
		t.Fatalf("both owners: %v", err)
	}
	skipped := f.policy(t, []string{"alice", "bob"}, RolesOneGovernanceAll, 3, v1)
	if got := VerdictOf(VerifyAmendment(v1, skipped, f.amend(t, v1, skipped, "skip", "alice"), geAnchor)); got != "versionNotNext" {
		t.Fatalf("skipped version: %s", got)
	}
	roleBundle := f.bundle(t, f.proposal(v1, ActionRoleIssue, "alice", "role"), "alice")
	if got := VerdictOf(VerifyAmendment(v1, v2, roleBundle, geAnchor)); got != "proposalIsNotAnAmendment" {
		t.Fatalf("role bundle as amendment: %s", got)
	}
	outsider := f.bundle(t, f.proposal(v1, ActionRoleIssue, "mallory", "outsider"), "mallory")
	if got := BundleVerdict(v1, outsider, f.verifyAt); got != "approverNotMember" {
		t.Fatalf("outsider: %s", got)
	}
}

func TestGEAgreementTemplates(t *testing.T) {
	f := loadOrgFixtures(t)
	cases := []struct {
		agreement OwnershipAgreement
		owners    []string
		approvers []string
		action    string
		want      string
	}{
		{RolesOneGovernanceAll, []string{"alice", "bob"}, []string{"alice"}, ActionRoleIssue, "met:roller:0"},
		{RolesOneGovernanceAll, []string{"alice", "bob"}, []string{"alice"}, ActionPolicyAmend, "clauseNotSatisfied"},
		{AllTwo, []string{"alice", "bob"}, []string{"alice"}, ActionRoleIssue, "clauseNotSatisfied"},
		{AllTwo, []string{"alice", "bob"}, []string{"alice", "bob"}, ActionPolicyAmend, "met:styring:0"},
		{OneAlone, []string{"alice", "bob"}, []string{"bob"}, ActionPolicyAmend, "met:styring:0"},
		{TwoOfThree, []string{"alice", "bob", "mallory"}, []string{"alice"}, ActionRoleRevoke, "clauseNotSatisfied"},
		{TwoOfThree, []string{"alice", "bob", "mallory"}, []string{"bob", "mallory"}, ActionRoleRevoke, "met:roller:0"},
		{TwoOfThree, []string{"alice", "bob", "mallory"}, []string{"alice", "mallory"}, ActionPolicyAmend, "met:styring:0"},
	}
	for _, c := range cases {
		policy := f.policy(t, c.owners, c.agreement, 1, nil)
		bundle := f.bundle(t, f.proposal(policy, c.action, "alice", c.action), c.approvers...)
		if got := BundleVerdict(policy, bundle, f.verifyAt); got != c.want {
			t.Errorf("%s %v %s: %s, want %s", c.agreement.TemplateID, c.approvers, c.action, got, c.want)
		}
	}
	if _, err := OwnerGroupPolicy(geAnchor, 1, nil, []IdentityPublicKeyDescriptor{f.descriptors["alice"]}, AllTwo, "2026-10-01T00:00:00Z"); VerdictOf(err) != "quorumCannotBeMet" {
		t.Errorf("impossible quorum: %v", err)
	}
}

func TestGEGenesisFoundersMustBeTheOwners(t *testing.T) {
	f := loadOrgFixtures(t)
	v1 := f.policy(t, []string{"alice", "bob"}, RolesOneGovernanceAll, 1, nil)
	hash, _ := v1.PolicyHash()
	seal := &OrganizationGenesisSeal{Version: 1, Kind: "organization", AnchorID: geAnchor, DisplayName: "G", InitialPolicyHash: hash,
		CustodianKey: f.descriptors["custodian"], Founders: []IdentityPublicKeyDescriptor{f.descriptors["alice"]}, SealedAt: geCreated}
	_ = seal.Sign(f.descriptors["alice"], f.signer("alice"), geCreated)
	steps := []string{VerdictOf(seal.Verify(v1))}
	seal.Founders = append(seal.Founders, f.descriptors["bob"])
	steps = append(steps, VerdictOf(seal.Verify(v1)))
	_ = seal.Sign(f.descriptors["alice"], f.signer("alice"), geCreated)
	steps = append(steps, VerdictOf(seal.Verify(v1)))
	_ = seal.Sign(f.descriptors["bob"], f.signer("bob"), geCreated)
	steps = append(steps, VerdictOf(seal.Verify(v1)))
	want := []string{"ownerNotFounder", "founderSignatureInvalid", "founderSignatureMissing", "valid"}
	for i := range want {
		if steps[i] != want[i] {
			t.Errorf("step %d: %s, want %s", i, steps[i], want[i])
		}
	}
}

func TestGEStatusMirrorRefusesOlderAndForgedLists(t *testing.T) {
	f := loadOrgFixtures(t)
	registry := NewCredentialStatusRegistry()
	if err := registry.Accept(f.decode(t, "org.status.v2").(*OrganizationRoleStatusList), f.verifyAt); err != nil {
		t.Fatal(err)
	}
	if got := VerdictOf(registry.Accept(f.decode(t, "org.status.v1").(*OrganizationRoleStatusList), f.verifyAt)); got != "sequenceNotNewer" {
		t.Errorf("older list: %s", got)
	}
	if got := VerdictOf(registry.Accept(f.decode(t, "org.status.wrong-key").(*OrganizationRoleStatusList), f.verifyAt)); got != "signatureInvalid" {
		t.Errorf("forged list: %s", got)
	}
	dedup := NewStatusList(geAnchor, "did:key:z", 3, geCreated, []string{"b", "a", "b"})
	if dedup.Summary("G", []string{"b", "a"}) != "G trekker tilbake 2 rolle(r): a, b. Statusliste nr. 3." || len(dedup.RevokedCredentialIDs) != 2 {
		t.Errorf("status list not deduplicated and sorted like Swift: %v", dedup.RevokedCredentialIDs)
	}
}

// ---- test.ge.condition-interop: the shared access table (Go column) ----------------------

type accessMatrix struct {
	ContextID    string `json:"contextId"`
	MaxMirrorAge int64  `json:"maximumMirrorAgeSeconds"`
	Scenarios    []struct {
		ID            string `json:"id"`
		Credential    string `json:"credential"`
		IssuerTrusted bool   `json:"issuerTrusted"`
		Status        string `json:"status"`
		ExpectedRole  string `json:"expectedRole"`
		Decision      string `json:"decision"`
		Reason        string `json:"reason"`
	} `json:"scenarios"`
}

func TestAccessMatrixMatchesSharedTable(t *testing.T) {
	f := loadOrgFixtures(t)
	raw, err := os.ReadFile(filepath.Join("testdata", "v1", "org.access-matrix.json"))
	if err != nil {
		t.Fatal(err)
	}
	var matrix accessMatrix
	if err := json.Unmarshal(raw, &matrix); err != nil {
		t.Fatal(err)
	}
	if len(matrix.Scenarios) != 7 {
		t.Fatalf("want 7 scenarios, got %d", len(matrix.Scenarios))
	}
	issuer := f.cases["org.role.valid"].Related["issuerDID"]
	bob, _ := DIDKey(f.descriptors["bob"])
	for _, scenario := range matrix.Scenarios {
		credentialCase := "org.role.valid"
		if scenario.Credential == "tampered" {
			credentialCase = "org.role.tampered"
		}
		credential := f.decode(t, credentialCase).(*VCClaim)
		now := f.verifyAt
		if scenario.Credential == "expired" {
			// Check after the signed validUntil (2027-06-30) instead of issuing a new credential.
			now, _ = ParseISO8601("2027-07-01T00:00:00Z")
		}
		mirroredAt := now
		if scenario.Status == "stale" {
			mirroredAt = now.Add(-time.Duration(matrix.MaxMirrorAge+1) * time.Second)
		}
		registry := NewCredentialStatusRegistry()
		if err := registry.Accept(f.decode(t, "org.status.v1").(*OrganizationRoleStatusList), mirroredAt); err != nil {
			t.Fatal(err)
		}
		if scenario.Status == "revoked" {
			if err := registry.Accept(f.decode(t, "org.status.v2").(*OrganizationRoleStatusList), mirroredAt); err != nil {
				t.Fatal(err)
			}
		}
		trusted := map[string][]string{}
		if scenario.IssuerTrusted {
			trusted[issuer] = []string{matrix.ContextID}
		}
		result := RoleAccess(credential, RoleAccessRequest{TrustedIssuers: trusted, ContextID: matrix.ContextID,
			RequesterDID: bob, RequiredType: "InteropGruppeRoleCredential", ExpectedRole: scenario.ExpectedRole,
			Registry: registry, Now: now, RequireRevocationCheck: true})
		decision := "unresolved"
		if result.Decision == "trusted" {
			decision = "met"
		}
		if decision != scenario.Decision || !contains(result.Reasons, scenario.Reason) {
			t.Errorf("%s: %s %v, want %s with %s", scenario.ID, decision, result.Reasons, scenario.Decision, scenario.Reason)
		}
	}
}
