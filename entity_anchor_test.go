package cellprotocol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/Digipomps/GoCellProtocol/interop"
)

var anchorChallenge = bytes.Repeat([]byte{7}, 32)

const anchorDomain = "node.example"

func anchorFixture(t *testing.T) (extensionFixtures, *interop.IdentityEnrollmentRequest, time.Time) {
	t.Helper()
	f := loadExtensionFixtures(t)
	_, wire := extensionCase(t, "extend.request.valid")
	var request interop.IdentityEnrollmentRequest
	if err := fromStored(wire, &request); err != nil {
		t.Fatal(err)
	}
	return f, &request, f.verifyAt.Add(-30 * time.Second)
}

func newAnchor(t *testing.T, now time.Time) (*Identity, *EntityAnchorCell) {
	t.Helper()
	owner, err := NewInMemoryIdentityVault().Identity(context.Background(), "owner", true)
	if err != nil {
		t.Fatal(err)
	}
	anchor := NewEntityAnchorCell(owner)
	anchor.Clock = func() time.Time { return now }
	return owner, anchor
}

func setMap(t *testing.T, anchor *EntityAnchorCell, keypath string, value any, requester *Identity) map[string]any {
	t.Helper()
	result, err := anchor.Set(context.Background(), keypath, value, requester)
	if err != nil {
		t.Fatalf("%s: %v", keypath, err)
	}
	return result.(map[string]any)
}

// completion is what Bob, the new key, sends back after presenting the credential.
func completion(t *testing.T, f extensionFixtures, packageValue any, request *interop.IdentityEnrollmentRequest, now time.Time) any {
	t.Helper()
	var pkg interop.IdentityLinkApprovalPackage
	if err := fromStored(packageValue, &pkg); err != nil {
		t.Fatal(err)
	}
	bob := f.keys["bob"]
	presentation, err := interop.BindAndSignPresentation([]interop.VCClaim{pkg.SameEntityCredential}, request.NewIdentity,
		func(m []byte) ([]byte, error) { return ed25519.Sign(bob, m), nil },
		anchorChallenge, anchorDomain, "9E5E0000-0000-4000-8000-0000000000A1", now)
	if err != nil {
		t.Fatal(err)
	}
	envelope := &interop.IdentityLinkCompletionEnvelope{
		Request: *request, Approval: pkg.Approval, SameEntityCredential: pkg.SameEntityCredential, Presentation: *presentation,
		IssuerIdentity: pkg.IssuerIdentity, ExpectedAudience: request.Audience, ExpectedOrigin: request.Origin,
		ExpectedPresentationChallenge: anchorChallenge, ExpectedPresentationDomain: anchorDomain,
	}
	value, err := toStored(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func approvalEnvelope(t *testing.T, request *interop.IdentityEnrollmentRequest, scopes []string) any {
	t.Helper()
	value, err := toStored(&interop.IdentityLinkApprovalEnvelope{Request: *request, IssuerType: "existingDevice", FreshAuthRequired: true, ApprovedScopes: scopes})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestEntityAnchorGenesisSealsToTheOwnerOnce(t *testing.T) {
	_, _, now := anchorFixture(t)
	owner, anchor := newAnchor(t, now)
	sealed := setMap(t, anchor, "identityLinks.genesis", map[string]any{"trigger": "onboarding"}, owner)
	if sealed["status"] != "sealed" {
		t.Fatalf("sealed = %#v", sealed)
	}
	var seal interop.EntityGenesisSeal
	var record interop.IdentityLinkRecord
	if fromStored(sealed["seal"], &seal) != nil || fromStored(sealed["record"], &record) != nil {
		t.Fatal("seal or record does not decode")
	}
	if err := interop.VerifyGenesis(&seal, &record); err != nil {
		t.Fatal(err)
	}
	if seal.Trigger != "onboarding" || record.ApprovedScopes[0] != "same_entity" {
		t.Fatalf("seal = %#v record = %#v", seal, record)
	}
	for keypath, want := range map[string]string{
		"identityLinks.genesis":              "alreadySealed",
		"identityLinks.genesis.trigger":      "genesisKeypathIsImmutable",
		interop.RecordKeypath(record.LinkID): "genesisKeypathIsImmutable",
		"identityLinks.revoke":               "cannotRevokeGenesisLink",
	} {
		value := any("directEdit")
		if keypath == "identityLinks.revoke" {
			value = record.LinkID
		}
		if got := setMap(t, anchor, keypath, value, owner); got["code"] != want {
			t.Fatalf("%s = %#v, want %s", keypath, got, want)
		}
	}
}

func TestEntityAnchorFirstPersistSealsAndStrangersCannot(t *testing.T) {
	_, _, now := anchorFixture(t)
	owner, anchor := newAnchor(t, now)
	stranger, _ := NewInMemoryIdentityVault().Identity(context.Background(), "stranger", true)
	envelope := map[string]any{"schema": "test", "mutations": []any{map[string]any{"keypath": "person.displayName", "value": "Ada"}}}
	if _, err := anchor.Set(context.Background(), "entity.batchPersist", envelope, stranger); err == nil {
		t.Fatal("a stranger persisted entity data")
	}
	if persisted := setMap(t, anchor, "entity.batchPersist", envelope, owner); persisted["status"] != "persisted" {
		t.Fatalf("persisted = %#v", persisted)
	}
	state, _ := anchor.Get(context.Background(), "identityLinks.state", owner)
	genesis := state.(map[string]any)["genesis"].(map[string]any)
	if state.(map[string]any)["sealed"] != true || genesis["trigger"] != "firstPersist" {
		t.Fatalf("state = %#v", state)
	}
}

func TestEntityAnchorApproveCompleteReplayAndRevoke(t *testing.T) {
	f, request, now := anchorFixture(t)
	owner, anchor := newAnchor(t, now)
	approved := setMap(t, anchor, "identityLinks.approveEnrollment", approvalEnvelope(t, request, []string{"chat.read"}), owner)
	if approved["status"] != "approved" {
		t.Fatalf("approved = %#v", approved)
	}
	var pkg interop.IdentityLinkApprovalPackage
	if err := fromStored(approved["approvalPackage"], &pkg); err != nil {
		t.Fatal(err)
	}
	ownerDescriptor, _ := DescriptorFor(owner)
	if err := interop.VerifyEnrollmentApproval(&pkg.Approval, ownerDescriptor, request); err != nil {
		t.Fatal(err)
	}
	done := completion(t, f, approved["approvalPackage"], request, now)
	completed := setMap(t, anchor, "identityLinks.completeEnrollment", done, owner)
	if completed["status"] != "completed" {
		t.Fatalf("completed = %#v", completed)
	}
	var record interop.IdentityLinkRecord
	if err := fromStored(completed["record"], &record); err != nil {
		t.Fatal(err)
	}
	if !record.LinkedIdentity.SameKey(f.descriptors["bob"]) || record.ApprovedScopes[0] != "chat.read" {
		t.Fatalf("record = %#v", record)
	}
	if replay := setMap(t, anchor, "identityLinks.completeEnrollment", done, owner); replay["code"] != "replayDetected" {
		t.Fatalf("replay = %#v", replay)
	}
	revoked := setMap(t, anchor, "identityLinks.revoke", map[string]any{"linkID": record.LinkID}, owner)
	if revoked["status"] != "revoked" || revoked["record"].(map[string]any)["revokedAt"] == nil {
		t.Fatalf("revoked = %#v", revoked)
	}
}

func TestEntityAnchorRefusesATamperedOrMalformedChain(t *testing.T) {
	f, request, now := anchorFixture(t)
	owner, anchor := newAnchor(t, now)
	approved := setMap(t, anchor, "identityLinks.approveEnrollment", approvalEnvelope(t, request, nil), owner)
	done := completion(t, f, approved["approvalPackage"], request, now).(map[string]any)
	approval := done["approval"].(map[string]any)
	approval["approvedScopes"] = append(approval["approvedScopes"].([]any), "admin")
	if got := setMap(t, anchor, "identityLinks.completeEnrollment", done, owner); got["status"] != "error" {
		t.Fatalf("escalated = %#v", got)
	}
	if got := setMap(t, anchor, "identityLinks.completeEnrollment", map[string]any{"linkID": "x"}, owner); got["code"] != "bad_payload" {
		t.Fatalf("malformed = %#v", got)
	}
	if got := setMap(t, anchor, "identityLinks.approveEnrollment", map[string]any{"approvalID": "a"}, owner); got["code"] != "bad_payload" {
		t.Fatalf("malformed approval = %#v", got)
	}
}
