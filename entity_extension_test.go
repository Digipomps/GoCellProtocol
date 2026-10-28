package cellprotocol

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Digipomps/GoCellProtocol/interop"
)

const extensionAudience = "https://staging.haven.digipomps.org"

type extensionFixtures struct {
	verifyAt    time.Time
	keys        map[string]ed25519.PrivateKey
	descriptors map[string]interop.IdentityPublicKeyDescriptor
}

func loadExtensionFixtures(t *testing.T) extensionFixtures {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("interop", "testdata", "v1", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		VerifyAtEpoch int64 `json:"verifyAtEpoch"`
		Parties       []struct {
			Name       string         `json:"name"`
			SeedHex    string         `json:"seedHex"`
			Descriptor map[string]any `json:"descriptor"`
		} `json:"parties"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	out := extensionFixtures{verifyAt: time.Unix(manifest.VerifyAtEpoch, 0).UTC(), keys: map[string]ed25519.PrivateKey{}, descriptors: map[string]interop.IdentityPublicKeyDescriptor{}}
	for _, party := range manifest.Parties {
		seed, _ := hex.DecodeString(party.SeedHex)
		out.keys[party.Name] = ed25519.NewKeyFromSeed(seed)
		var descriptor interop.IdentityPublicKeyDescriptor
		if err := interop.FromWire(party.Descriptor, &descriptor); err != nil {
			t.Fatal(err)
		}
		out.descriptors[party.Name] = descriptor
	}
	return out
}

func extensionCase(t *testing.T, name string) (map[string]any, map[string]any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("interop", "testdata", "v1", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	encoded, _ := base64.StdEncoding.DecodeString(c["encodedBase64"].(string))
	value, err := interop.DecodeJSON(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return c, value.(map[string]any)
}

func newExtensionCell(f extensionFixtures, party string, now time.Time, owner ...*Identity) *EntityScaffoldExtensionCell {
	key := f.keys[party]
	counter := 0
	var o *Identity
	if len(owner) > 0 {
		o = owner[0]
	}
	return NewEntityScaffoldExtensionCell(o, ExtensionOptions{
		Descriptor:  f.descriptors[party],
		Sign:        func(m []byte) ([]byte, error) { return ed25519.Sign(key, m), nil },
		DisplayName: party,
		Clock:       func() time.Time { return now },
		NewUUID: func() string {
			counter++
			return fmt.Sprintf("00000000-0000-4000-8000-%012d", counter)
		},
	})
}

func TestExtensionRequestHashAndHumanCodeMatchSwift(t *testing.T) {
	c, wire := extensionCase(t, "extend.request.valid")
	var request interop.IdentityEnrollmentRequest
	if err := interop.FromWire(wire, &request); err != nil {
		t.Fatal(err)
	}
	related := c["related"].(map[string]any)
	hash, err := BindingRequestHash(&request)
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.StdEncoding.EncodeToString(hash); got != related["bindingRequestHashBase64"] {
		t.Fatalf("binding hash = %s, Swift %s", got, related["bindingRequestHashBase64"])
	}
	if got := HumanCode(request.RequestID + request.Audience); got != related["humanCode"] {
		t.Fatalf("human code = %s, Swift %s", got, related["humanCode"])
	}
}

func TestExtensionReviewsASwiftRequest(t *testing.T) {
	f := loadExtensionFixtures(t)
	approver := newExtensionCell(f, "alice", f.verifyAt)
	_, valid := extensionCase(t, "extend.request.valid")
	review := approver.reviewRequest(map[string]any{"request": valid})
	if review["status"] != "reviewable" || review["signatureValid"] != true {
		t.Fatalf("review = %#v", review)
	}
	_, tampered := extensionCase(t, "extend.request.tampered")
	if review := approver.reviewRequest(tampered); review["status"] != "rejected" || review["signatureValid"] != false {
		t.Fatalf("tampered review = %#v", review)
	}
}

func TestExtensionAskApproveAcceptBetweenTwoGoPlaces(t *testing.T) {
	ctx := context.Background()
	f := loadExtensionFixtures(t)
	owner, _ := NewInMemoryIdentityVault().Identity(ctx, "owner", true)
	newPlace := newExtensionCell(f, "bob", f.verifyAt, owner)
	approver := newExtensionCell(f, "alice", f.verifyAt, owner)

	askedAny, err := newPlace.Set(ctx, "extension.beginRequest", map[string]any{"audience": extensionAudience, "requestedScopes": []any{"entity.read", "agreement.sign", "admin"}}, owner)
	if err != nil {
		t.Fatal(err)
	}
	asked := askedAny.(map[string]any)
	reviewAny, _ := approver.Set(ctx, "extension.reviewRequest", asked["payload"], owner)
	review := reviewAny.(map[string]any)
	if review["status"] != "reviewable" || review["humanCode"] != asked["humanCode"] {
		t.Fatalf("review = %#v", review)
	}
	approvedAny, _ := approver.Set(ctx, "extension.approveRequest", map[string]any{"payload": asked["payload"], "approvedScopes": []any{"entity.read"}}, owner)
	approved := approvedAny.(map[string]any)
	if fmt.Sprint(approved["refusedScopes"]) != "[admin agreement.sign]" {
		t.Fatalf("refused = %v", approved["refusedScopes"])
	}
	data, _ := DataFromBase64URL(approved["payload"].(string))
	var approval interop.IdentityEnrollmentApproval
	if err := interop.Decode(data, &approval); err != nil {
		t.Fatal(err)
	}
	if err := interop.VerifyEnrollmentApproval(&approval, f.descriptors["alice"], nil); err != nil {
		t.Fatal(err)
	}
	acceptedAny, _ := newPlace.Set(ctx, "extension.acceptApproval", map[string]any{"payload": approved["payload"], "issuerIdentity": approved["issuerIdentity"]}, owner)
	accepted := acceptedAny.(map[string]any)
	if accepted["status"] != "ok" || accepted["signatureVerified"] != true {
		t.Fatalf("accepted = %#v", accepted)
	}
	stateAny, _ := newPlace.Get(ctx, "extension.state", owner)
	if state := stateAny.(map[string]any); state["activeLinkCount"] != 1 {
		t.Fatalf("state = %#v", state)
	}
	revokedAny, _ := approver.Set(ctx, "extension.revokeLink", map[string]any{"linkID": approved["linkID"]}, owner)
	var revocation interop.IdentityLinkRevocation
	if !decodeObject(revokedAny.(map[string]any)["revocation"].(map[string]any), &revocation) {
		t.Fatal("revocation does not decode")
	}
	if err := interop.VerifyLinkRevocation(&revocation, f.descriptors["alice"]); err != nil {
		t.Fatal(err)
	}
}

func TestExtensionAcceptRefusesForeignTamperedAndExpired(t *testing.T) {
	f := loadExtensionFixtures(t)
	newPlace := newExtensionCell(f, "bob", f.verifyAt)
	approver := newExtensionCell(f, "alice", f.verifyAt)
	other := newExtensionCell(f, "bob", f.verifyAt)
	asked := newPlace.beginRequest(map[string]any{"audience": extensionAudience})
	approved := approver.approveRequest(asked["payload"])

	other.beginRequest(map[string]any{"audience": extensionAudience + "/other"})
	if got := other.acceptApproval(approved["payload"]); got["code"] != "request_hash_mismatch" {
		t.Fatalf("foreign = %#v", got)
	}

	data, _ := DataFromBase64URL(approved["payload"].(string))
	var wire map[string]any
	_ = json.Unmarshal(data, &wire)
	wire["approvedScopes"] = append(wire["approvedScopes"].([]any), "agreement.sign")
	if got := newPlace.acceptApproval(map[string]any{"approval": wire, "issuerIdentity": approved["issuerIdentity"]}); got["code"] != "bad_signature" {
		t.Fatalf("tampered = %#v", got)
	}
	if got := newPlace.acceptApproval(approved["payload"]); got["status"] != "ok" || got["signatureVerified"] != false {
		t.Fatalf("plain = %#v", got)
	}

	late := newExtensionCell(f, "bob", f.verifyAt)
	lateAsked := late.beginRequest(map[string]any{"audience": extensionAudience})
	lateApproved := approver.approveRequest(map[string]any{"payload": lateAsked["payload"], "ttlMinutes": 2})
	late.opts.Clock = func() time.Time { return f.verifyAt.Add(time.Hour) }
	if got := late.acceptApproval(lateApproved["payload"]); got["code"] != "expired" {
		t.Fatalf("expired = %#v", got)
	}
}

func TestExtensionRefusesWithoutAudienceOrScopes(t *testing.T) {
	f := loadExtensionFixtures(t)
	if got := newExtensionCell(f, "bob", f.verifyAt).beginRequest(map[string]any{}); got["code"] != "missing_audience" {
		t.Fatalf("got %#v", got)
	}
	asked := newExtensionCell(f, "bob", f.verifyAt).beginRequest(map[string]any{"audience": extensionAudience, "requestedScopes": []any{"admin"}})
	if got := newExtensionCell(f, "alice", f.verifyAt).approveRequest(asked["payload"]); got["code"] != "no_scopes" {
		t.Fatalf("got %#v", got)
	}
}
