package cellprotocol

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Digipomps/GoCellProtocol/interop"
)

const inviteTestBase = "https://landing.test"

func inviteWire(t *testing.T, name string) []byte {
	t.Helper()
	_, wire := extensionCase(t, name)
	data, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func decodeBody(t *testing.T, response InviteResponse) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(response.Body, &out); err != nil {
		t.Fatalf("body %q: %v", response.Body, err)
	}
	return out
}

// inProcess calls the landing by route, as HTTP would, through JSON.
func inProcess(landing *InviteLanding) InviteTransport {
	return func(ctx context.Context, method, target string, body any) (int, any) {
		parsed, _ := url.Parse(target)
		path := strings.TrimPrefix(parsed.Path, "/i/")
		data, _ := json.Marshal(body)
		var response InviteResponse
		switch {
		case method == "POST" && path == "api/publish":
			response = landing.Publish(data)
		case method == "POST" && path == "api/revoke":
			response = landing.Revoke(data)
		case method == "POST" && path == "api/status":
			response = landing.Status(data)
		case method == "POST" && path == "api/requests":
			response = landing.Collect(data)
		case method == "POST" && strings.HasSuffix(path, "/reply"):
			response = landing.Reply(strings.TrimSuffix(path, "/reply"), data, true, "test")
		case method == "GET":
			response = landing.Landing(path, "test", true)
		default:
			return 404, nil
		}
		var out any
		_ = json.Unmarshal(response.Body, &out)
		return response.Status, out
	}
}

func newInvitationCell(f extensionFixtures, party string, now *time.Time, landing *InviteLanding, endpoint string) *InvitationCell {
	key := f.keys[party]
	counter := 0
	return NewInvitationCell(testOwner(party), InvitationOptions{
		Descriptor:        f.descriptors[party],
		Sign:              func(m []byte) ([]byte, error) { return ed25519.Sign(key, m), nil },
		DisplayName:       strings.ToUpper(party[:1]) + party[1:],
		LandingBase:       inviteTestBase,
		ContactEndpointID: endpoint,
		Transport:         inProcess(landing),
		Clock:             func() time.Time { return *now },
		NewUUID: func() string {
			counter++
			return fmt.Sprintf("00000000-0000-4000-8000-%012d", counter)
		},
	})
}

var testOwners = map[string]*Identity{}

func testOwner(name string) *Identity {
	if owner, ok := testOwners[name]; ok {
		return owner
	}
	owner, err := NewInMemoryIdentityVault().Identity(context.Background(), name, true)
	if err != nil {
		panic(err)
	}
	testOwners[name] = owner
	return owner
}

func set(t *testing.T, cell *InvitationCell, keypath string, value any) map[string]any {
	t.Helper()
	out, err := cell.Set(context.Background(), keypath, value, cell.owner)
	if err != nil {
		t.Fatal(err)
	}
	return out.(map[string]any)
}

func TestLandingAcceptsSwiftPublicationAndRefusesSwappedCode(t *testing.T) {
	f := loadExtensionFixtures(t)
	landing := NewInviteLanding(func() time.Time { return f.verifyAt })
	swapped := landing.Publish(inviteWire(t, "invite.publication.code-swapped"))
	if body := decodeBody(t, swapped); swapped.Status != 403 || body["code"] != "ticket_mismatch" {
		t.Fatalf("swapped: %d %v", swapped.Status, body)
	}
	if r := landing.Publish(inviteWire(t, "invite.publication.valid")); r.Status != 200 {
		t.Fatalf("publish: %d %s", r.Status, r.Body)
	}
	if body := decodeBody(t, landing.Publish(inviteWire(t, "invite.publication.valid"))); body["message"] != "Allerede registrert." {
		t.Fatalf("republish: %v", body)
	}
	_, publication := extensionCase(t, "invite.publication.valid")
	for _, record := range landing.tickets {
		if record.statusKeyDigest != interop.StatusKeyDigest(publication["statusKey"].(string)) {
			t.Fatal("status key not stored as digest")
		}
	}
}

func TestLandingStoresSwiftContactRequestAndDeletesOnCollect(t *testing.T) {
	f := loadExtensionFixtures(t)
	landing := NewInviteLanding(func() time.Time { return f.verifyAt })
	landing.Publish(inviteWire(t, "invite.publication.valid"))
	if r := landing.Reply("ABC234", inviteWire(t, "invite.contact-request.valid"), true, "x"); r.Status != 200 {
		t.Fatalf("reply: %d %s", r.Status, r.Body)
	}
	_, publication := extensionCase(t, "invite.publication.valid")
	query, _ := json.Marshal(map[string]any{"ticketID": publication["ticketID"], "statusKey": publication["statusKey"]})
	status := decodeBody(t, landing.Status(query))
	if status["contactRequestCount"].(float64) != 1 || status["openCount"].(float64) != 0 {
		t.Fatalf("status: %v", status)
	}
	if _, has := status["firstOpenedAt"]; has {
		t.Fatal("status leaks firstOpenedAt")
	}
	wrong, _ := json.Marshal(map[string]any{"ticketID": publication["ticketID"], "statusKey": "wrong"})
	if r := landing.Status(wrong); r.Status != 404 {
		t.Fatalf("wrong key: %d", r.Status)
	}
	collected := decodeBody(t, landing.Collect(query))["requests"].([]any)
	if len(collected) != 1 {
		t.Fatalf("collected %d", len(collected))
	}
	var request interop.HavenInviteContactRequest
	if !decodeObject(collected[0].(map[string]any), &request) {
		t.Fatal("decode collected")
	}
	ticket, _ := interop.DecodeTicketToken(publication["ticketToken"].(string))
	if err := interop.VerifyContactRequest(&request, ticket, f.verifyAt); err != nil {
		t.Fatal(err)
	}
	if again := decodeBody(t, landing.Collect(query))["requests"].([]any); len(again) != 0 {
		t.Fatal("collect did not delete")
	}
}

func TestLandingRevocationChecksIssuer(t *testing.T) {
	f := loadExtensionFixtures(t)
	landing := NewInviteLanding(func() time.Time { return f.verifyAt })
	landing.Publish(inviteWire(t, "invite.publication.valid"))
	if r := landing.Revoke(inviteWire(t, "invite.revocation.forged")); r.Status != 403 {
		t.Fatalf("forged: %d", r.Status)
	}
	if r := landing.Revoke(inviteWire(t, "invite.revocation.valid")); r.Status != 200 {
		t.Fatalf("revoke: %d %s", r.Status, r.Body)
	}
	if r := landing.Landing("ABC234", "x", true); r.Status != 410 {
		t.Fatalf("landing after revoke: %d", r.Status)
	}
	if body := decodeBody(t, landing.Reply("ABC234", inviteWire(t, "invite.contact-request.valid"), true, "x")); body["code"] != "not_active" {
		t.Fatalf("reply after revoke: %v", body)
	}
}

func TestLinkHelpersMatchPythonAndSwift(t *testing.T) {
	f := loadExtensionFixtures(t)
	_, publication := extensionCase(t, "invite.publication.valid")
	ticket, err := interop.DecodeTicketToken(publication["ticketToken"].(string))
	if err != nil {
		t.Fatal(err)
	}
	token, _ := ticket.Token()
	for _, link := range []string{"haven://invite/" + token, "https://x.test/i/" + token, "https://gw.test/r?t=" + token} {
		if got, err := interop.TokenFromLink(link); err != nil || got != token {
			t.Fatalf("%s -> %v", link, err)
		}
	}
	if got, _ := interop.TokenFromLink("https://x.test/i/ABC234"); got != "ABC234" {
		t.Fatal(got)
	}
	payload := interop.InviteVerdictPayload(interop.VerifyInvite(ticket, f.verifyAt, interop.TicketOptions{}), ticket)
	if payload["code"] != "valid" || payload["reason"] != "Gyldig invitasjon fra Alice." || payload["audienceMatches"] != nil {
		t.Fatalf("payload %v", payload)
	}
	email, _ := interop.NormalizeEmail("Ola <Ola@Example.COM>")
	if interop.DisclosureToken("email", email) != interop.SHA256HexString("haven.endpoint.v1|email|ola@example.com")[:16] {
		t.Fatal("disclosure token")
	}
	if interop.InviteHumanCode("x") != HumanCode("x") {
		t.Fatal("human code differs between packages")
	}
}

func TestInviteReplyPullAcceptBetweenTwoGoCells(t *testing.T) {
	f := loadExtensionFixtures(t)
	now := f.verifyAt
	landing := NewInviteLanding(func() time.Time { return now })
	alice := newInvitationCell(f, "alice", &now, landing, "ep-alice")
	bob := newInvitationCell(f, "bob", &now, landing, "")

	prepared := set(t, alice, "invite.prepare", map[string]any{"recipient": "bob@example.org", "recipientDisplayName": "Bob Testesen"})
	if prepared["status"] != "ok" || prepared["published"] != true {
		t.Fatalf("prepare: %v", prepared)
	}
	if prepared["link"] != inviteTestBase+"/i/"+prepared["humanCode"].(string) {
		t.Fatalf("link %v", prepared["link"])
	}
	if checked := set(t, bob, "invite.verify", map[string]any{"link": prepared["selfContainedLink"]}); checked["code"] != "valid" {
		t.Fatalf("verify: %v", checked)
	}
	if answered := set(t, bob, "invite.respond", map[string]any{"link": prepared["link"], "message": "Hei Alice!"}); answered["status"] != "ok" {
		t.Fatalf("respond: %v", answered)
	}
	status := set(t, alice, "invite.refreshStatus", map[string]any{})
	if row := status["outbox"].([]any)[0].(map[string]any); row["state"] != "joined" || row["contactRequestCount"] != 1 {
		t.Fatalf("status: %v", row)
	}
	pulled := set(t, alice, "invite.pullContactRequests", map[string]any{})
	if pulled["receivedCount"] != 1 {
		t.Fatalf("pull: %v", pulled)
	}
	inbox := pulled["inbox"].([]any)[0].(map[string]any)
	accepted := set(t, alice, "invite.acceptContactRequest", map[string]any{"requestID": inbox["requestID"]})
	if accepted["sender"].(map[string]any)["uuid"] != f.descriptors["bob"].UUID {
		t.Fatalf("accept: %v", accepted)
	}
}

func TestRevokeStopsLinkAndReply(t *testing.T) {
	f := loadExtensionFixtures(t)
	now := f.verifyAt
	landing := NewInviteLanding(func() time.Time { return now })
	alice := newInvitationCell(f, "alice", &now, landing, "ep-alice")
	bob := newInvitationCell(f, "bob", &now, landing, "")
	prepared := set(t, alice, "invite.prepare", map[string]any{"recipient": "bob@example.org"})
	if revoked := set(t, alice, "invite.revoke", map[string]any{"ticketID": prepared["ticketID"]}); !strings.Contains(revoked["message"].(string), "slutter å virke") {
		t.Fatalf("revoke: %v", revoked)
	}
	if refused := set(t, bob, "invite.respond", map[string]any{"link": prepared["selfContainedLink"]}); refused["code"] != "not_active" {
		t.Fatalf("respond after revoke: %v", refused)
	}
	if verdict := set(t, alice, "invite.verify", map[string]any{"link": prepared["selfContainedLink"]}); verdict["code"] != "revoked" {
		t.Fatalf("verify: %v", verdict)
	}
}

func TestInboxCapAndNoReplyChannel(t *testing.T) {
	f := loadExtensionFixtures(t)
	now := f.verifyAt
	landing := NewInviteLanding(func() time.Time { return now })
	landing.RateLimit = false
	alice := newInvitationCell(f, "alice", &now, landing, "ep-alice")
	set(t, alice, "invite.configure", map[string]any{"maxContactRequests": 1})
	prepared := set(t, alice, "invite.prepare", map[string]any{"recipient": "bob@example.org"})
	first := set(t, newInvitationCell(f, "bob", &now, landing, ""), "invite.respond", map[string]any{"link": prepared["link"]})
	second := set(t, newInvitationCell(f, "mallory", &now, landing, ""), "invite.respond", map[string]any{"link": prepared["link"]})
	if first["status"] != "ok" || second["code"] != "inbox_full" {
		t.Fatalf("cap: %v / %v", first, second)
	}
	quiet := newInvitationCell(f, "alice", &now, landing, "")
	noReply := set(t, quiet, "invite.prepare", map[string]any{"recipient": "carol@example.org"})
	if caps := noReply["capabilities"].([]any); len(caps) != 1 {
		t.Fatalf("caps %v", caps)
	}
	if r := set(t, newInvitationCell(f, "bob", &now, landing, ""), "invite.respond", map[string]any{"link": noReply["link"]}); r["code"] != "no_reply_channel" {
		t.Fatalf("no reply: %v", r)
	}
}

func TestInviteLandingOverHTTP(t *testing.T) {
	f := loadExtensionFixtures(t)
	now := time.Now()
	server := httptest.NewServer(NewInviteLanding(nil))
	defer server.Close()
	key := f.keys["alice"]
	alice := NewInvitationCell(testOwner("alice"), InvitationOptions{Descriptor: f.descriptors["alice"], Sign: func(m []byte) ([]byte, error) { return ed25519.Sign(key, m), nil }, LandingBase: server.URL, ContactEndpointID: "ep-alice"})
	bobKey := f.keys["bob"]
	bob := NewInvitationCell(testOwner("bob"), InvitationOptions{Descriptor: f.descriptors["bob"], Sign: func(m []byte) ([]byte, error) { return ed25519.Sign(bobKey, m), nil }})
	_ = now
	prepared := set(t, alice, "invite.prepare", map[string]any{"recipient": "bob@example.org"})
	if prepared["published"] != true {
		t.Fatalf("prepare: %v", prepared)
	}
	if r := set(t, bob, "invite.respond", map[string]any{"link": prepared["link"]}); r["status"] != "ok" {
		t.Fatalf("respond: %v", r)
	}
	if pulled := set(t, alice, "invite.pullContactRequests", nil); pulled["receivedCount"] != 1 {
		t.Fatalf("pull: %v", pulled)
	}
}
