// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Digipomps/GoCellProtocol/interop"
)

func newChatIdentity(t *testing.T, name string) *Identity {
	t.Helper()
	identity, err := NewInMemoryIdentityVault().Identity(context.Background(), name, true)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

// publicChatIdentity is what arrives over the authenticated bridge: the key, no vault.
func publicChatIdentity(t *testing.T, identity *Identity) *Identity {
	t.Helper()
	data, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	var out Identity
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return &out
}

func identityWire(t *testing.T, identity *Identity) map[string]any {
	t.Helper()
	data, _ := json.Marshal(identity)
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func chatSet(t *testing.T, cell *ChatCell, keypath string, value any, requester *Identity) any {
	t.Helper()
	out, err := cell.Set(context.Background(), keypath, value, requester)
	if err != nil {
		t.Fatalf("%s: %v", keypath, err)
	}
	return out
}

func chatGet(t *testing.T, cell *ChatCell, keypath string, requester *Identity) any {
	t.Helper()
	out, err := cell.Get(context.Background(), keypath, requester)
	if err != nil {
		t.Fatalf("%s: %v", keypath, err)
	}
	return out
}

func denied(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected denial", what)
	}
}

type chatFixture struct {
	alice, bob, mallory *Identity
	chat                *ChatCell
	artifact            any
	acceptance          any
}

func invitedChat(t *testing.T, conditions ...string) chatFixture {
	t.Helper()
	if len(conditions) == 0 {
		conditions = []string{"invitationAccepted"}
	}
	f := chatFixture{alice: newChatIdentity(t, "Alice"), bob: newChatIdentity(t, "Bob"), mallory: newChatIdentity(t, "Mallory")}
	f.chat = NewChatCell(f.alice, ChatCellOptions{})
	chatSet(t, f.chat, "audience.admissionConditions", stringsToAny(conditions), f.alice)
	bobHome := NewChatCell(f.bob, ChatCellOptions{})
	chatSet(t, f.chat, "audience.inviteIdentities", []any{identityWire(t, f.bob)}, f.alice)
	artifacts, ok := chatSet(t, f.chat, "audience.generateInvitationArtifacts", true, f.alice).([]any)
	if !ok || len(artifacts) != 1 {
		t.Fatalf("artifacts %#v", artifacts)
	}
	f.artifact = artifacts[0]
	f.acceptance = chatSet(t, bobHome, "audience.generateInvitationAcceptance", f.artifact, f.bob)
	if s, isErr := f.acceptance.(string); isErr {
		t.Fatalf("acceptance: %s", s)
	}
	return f
}

// chatRequest is what a guest sends: the advertised template, as it arrives
// over the wire, with only the grants it wants (all when keys is empty).
func chatRequest(t *testing.T, chat *ChatCell, requester *Identity, keys ...string) Agreement {
	t.Helper()
	advertised, err := chat.Advertise(context.Background(), requester)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(advertised.ContractTemplate)
	if err != nil {
		t.Fatal(err)
	}
	var request Agreement
	if err := json.Unmarshal(data, &request); err != nil {
		t.Fatal(err)
	}
	if len(keys) > 0 {
		wanted := map[string]bool{}
		for _, key := range keys {
			wanted[key] = true
		}
		kept := []Grant{}
		for _, grant := range request.Grants {
			if wanted[grant.Keypath] {
				kept = append(kept, grant)
			}
		}
		request.Grants = kept
	}
	return request
}

func agree(t *testing.T, chat *ChatCell, request Agreement, requester, authority *Identity) AgreementState {
	t.Helper()
	state, err := chat.AddAgreementAuthorizedBy(context.Background(), request, requester, authority)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func TestChatArtifactAndAcceptanceVerifyAsSwiftDoes(t *testing.T) {
	f := invitedChat(t)
	artifact := chatArtifactFrom(f.artifact)
	acceptance := chatAcceptanceFrom(f.acceptance)
	if artifact == nil || acceptance == nil {
		t.Fatal("artifact or acceptance did not decode")
	}
	chatUUID := f.chat.uuid
	if err := interop.VerifyChatInvitation(artifact, time.Now(), interop.ChatOptions{ExpectedChatCellUUID: &chatUUID, ExpectedInviterUUID: &f.alice.UUID}); err != nil {
		t.Fatal(err)
	}
	if err := interop.VerifyChatAcceptance(acceptance, artifact, time.Now(), &chatUUID); err != nil {
		t.Fatal(err)
	}
	if len(artifact.Nonce) != 64 {
		t.Fatalf("nonce %d bytes", len(artifact.Nonce))
	}
}

func TestChatInviteeJoinsSendsAndReadsAfterAccepting(t *testing.T) {
	f := invitedChat(t)
	ctx := context.Background()
	remoteBob := publicChatIdentity(t, f.bob)
	_, err := f.chat.Get(ctx, "messages", remoteBob)
	denied(t, err, "messages before accepting")
	// No proof yet: the Agreement's condition does not hold.
	if agree(t, f.chat, chatRequest(t, f.chat, remoteBob), remoteBob, nil) != AgreementRejected {
		t.Fatal("signed without proof")
	}
	if chatGet(t, f.chat, "audience.admission.invitationAccepted", remoteBob) != false {
		t.Fatal("condition held before proof")
	}

	proof := map[string]any{"artifact": f.artifact, "acceptance": f.acceptance}
	accepted := chatSet(t, f.chat, "audience.acceptInvitationArtifact", proof, remoteBob).(map[string]any)
	if accepted["status"] != "accepted" || accepted["idempotent"] != false {
		t.Fatalf("accepted %#v", accepted)
	}
	again := chatSet(t, f.chat, "audience.acceptInvitationArtifact", proof, remoteBob).(map[string]any)
	if again["idempotent"] != true {
		t.Fatalf("again %#v", again)
	}
	// The proof alone opens nothing; the contract does.
	_, err = f.chat.Get(ctx, "messages", remoteBob)
	denied(t, err, "messages with proof but no contract")
	if chatGet(t, f.chat, "audience.admission.invitationAccepted", remoteBob) != true {
		t.Fatal("condition did not hold after proof")
	}
	if agree(t, f.chat, chatRequest(t, f.chat, remoteBob, "messages", "sendMessage"), remoteBob, nil) != AgreementSigned {
		t.Fatal("not signed after proof")
	}

	sent := chatSet(t, f.chat, "sendMessage", "Hei Alice", remoteBob).(map[string]any)
	if sent["status"] != "sent" || sent["message"].(map[string]any)["ownerUUID"] != f.bob.UUID {
		t.Fatalf("sent %#v", sent)
	}
	chatSet(t, f.chat, "sendMessage", map[string]any{"content": "# Hei", "contentType": "markdown"}, f.alice)
	messages := chatGet(t, f.chat, "messages", remoteBob).([]any)
	if len(messages) != 2 || messages[0].(map[string]any)["content"] != "Hei Alice" || messages[1].(map[string]any)["isMarkdown"] != true {
		t.Fatalf("messages %#v", messages)
	}

	_, err = f.chat.Set(ctx, "sendMessage", "hei", publicChatIdentity(t, f.mallory))
	denied(t, err, "stranger")
	impostor := publicChatIdentity(t, f.mallory)
	impostor.UUID = f.bob.UUID
	_, err = f.chat.Get(ctx, "messages", impostor)
	denied(t, err, "impostor")
	_, err = f.chat.Set(ctx, "audience.generateInvitationArtifacts", true, remoteBob)
	denied(t, err, "member on owner key")
	_, err = f.chat.Set(ctx, "audience.admissionConditions", []any{}, remoteBob)
	denied(t, err, "member sets conditions")
	if agree(t, f.chat, chatRequest(t, f.chat, publicChatIdentity(t, f.mallory)), publicChatIdentity(t, f.mallory), nil) != AgreementRejected {
		t.Fatal("stranger signed")
	}

	chatSet(t, f.chat, "audience.revokeInvites", []any{f.bob.UUID}, f.alice)
	_, err = f.chat.Get(ctx, "messages", remoteBob)
	denied(t, err, "after revoke")
}

func TestChatRefusesTamperedForeignAndSupersededProofs(t *testing.T) {
	f := invitedChat(t)
	remoteBob := publicChatIdentity(t, f.bob)
	tampered := map[string]any{}
	for k, v := range f.artifact.(map[string]any) {
		tampered[k] = v
	}
	tampered["topic"] = "annet"
	if got := chatSet(t, f.chat, "audience.acceptInvitationArtifact", map[string]any{"artifact": tampered, "acceptance": f.acceptance}, remoteBob); got != "error: invalidArtifactProof" {
		t.Fatalf("tampered %#v", got)
	}

	other := NewChatCell(f.alice, ChatCellOptions{})
	chatSet(t, other, "audience.inviteIdentities", []any{identityWire(t, f.bob)}, f.alice)
	if got := chatSet(t, other, "audience.acceptInvitationArtifact", map[string]any{"artifact": f.artifact, "acceptance": f.acceptance}, remoteBob); got != "error: chatCellMismatch" {
		t.Fatalf("foreign %#v", got)
	}

	malloryHome := NewChatCell(f.mallory, ChatCellOptions{})
	if got := chatSet(t, malloryHome, "audience.generateInvitationAcceptance", f.artifact, f.mallory); got != "error: requester does not match invited identity" {
		t.Fatalf("mallory %#v", got)
	}

	chatSet(t, f.chat, "audience.declineInvites", []any{f.bob.UUID}, f.alice)
	fresh := chatSet(t, f.chat, "audience.generateInvitationArtifacts", []any{f.bob.UUID}, f.alice).([]any)
	if fresh[0].(map[string]any)["invitationID"] == f.artifact.(map[string]any)["invitationID"] {
		t.Fatal("fresh artifact reused the id")
	}
	if got := chatSet(t, f.chat, "audience.acceptInvitationArtifact", map[string]any{"artifact": f.artifact, "acceptance": f.acceptance}, remoteBob); got != "error: invitation artifact has been superseded" {
		t.Fatalf("stale %#v", got)
	}
}

func TestChatComposerAndFlowEvents(t *testing.T) {
	f := invitedChat(t)
	remoteBob := publicChatIdentity(t, f.bob)
	chatSet(t, f.chat, "audience.acceptInvitationArtifact", map[string]any{"artifact": f.artifact, "acceptance": f.acceptance}, remoteBob)
	if agree(t, f.chat, chatRequest(t, f.chat, remoteBob), remoteBob, nil) != AgreementSigned {
		t.Fatal("not signed")
	}
	chatSet(t, f.chat, "compose.body", "  utkast  ", remoteBob)
	if state := chatGet(t, f.chat, "compose.state", remoteBob).(map[string]any); state["canSend"] != true {
		t.Fatalf("state %#v", state)
	}
	sent := chatSet(t, f.chat, "sendComposedMessage", nil, remoteBob).(map[string]any)
	if sent["message"].(map[string]any)["content"] != "utkast" {
		t.Fatalf("sent %#v", sent)
	}
	if got := chatSet(t, f.chat, "sendComposedMessage", nil, remoteBob); got != "error: empty composer body" {
		t.Fatalf("empty %#v", got)
	}
	topics := map[string]bool{}
	for _, element := range f.chat.FlowHistory() {
		topics[element.Topic] = true
	}
	for _, topic := range []string{"chat.message", "chat.participant", "chat.status"} {
		if !topics[topic] {
			t.Fatalf("missing %s in %v", topic, topics)
		}
	}
}

func TestChatAgreementConditionsDecideAdmissionAsInSwift(t *testing.T) {
	f := invitedChat(t, "member")
	ctx := context.Background()
	remoteBob := publicChatIdentity(t, f.bob)
	// An owner-accepted invitee is a member without presenting proof.
	chatSet(t, f.chat, "audience.acceptInvites", []any{f.bob.UUID}, f.alice)
	if agree(t, f.chat, chatRequest(t, f.chat, remoteBob), remoteBob, nil) != AgreementSigned {
		t.Fatal("member not signed")
	}
	if sent := chatSet(t, f.chat, "sendMessage", "hei", remoteBob).(map[string]any); sent["status"] != "sent" {
		t.Fatalf("sent %#v", sent)
	}

	// The same identity does not meet "invitationAccepted" without proof.
	g := invitedChat(t, "invitationAccepted")
	chatSet(t, g.chat, "audience.acceptInvites", []any{g.bob.UUID}, g.alice)
	if agree(t, g.chat, chatRequest(t, g.chat, publicChatIdentity(t, g.bob)), publicChatIdentity(t, g.bob), nil) != AgreementRejected {
		t.Fatal("signed without proof")
	}

	// A guest cannot widen the grants or drop the conditions.
	widened := chatRequest(t, f.chat, remoteBob)
	widened.Grants = append(widened.Grants, NewGrant("Condition grant", "audience.admissionConditions", "rw--"))
	if agree(t, f.chat, widened, remoteBob, nil) != AgreementRejected {
		t.Fatal("widened signed")
	}
	dropped := chatRequest(t, f.chat, remoteBob)
	dropped.Conditions = nil
	if agree(t, f.chat, dropped, remoteBob, nil) != AgreementRejected {
		t.Fatal("dropped conditions signed")
	}

	// Without conditions only the owner approves.
	chatSet(t, f.chat, "audience.admissionConditions", []any{}, f.alice)
	remoteMallory := publicChatIdentity(t, f.mallory)
	if agree(t, f.chat, chatRequest(t, f.chat, remoteMallory), remoteMallory, nil) != AgreementRejected {
		t.Fatal("stranger signed without owner")
	}
	if agree(t, f.chat, chatRequest(t, f.chat, remoteMallory, "messages"), remoteMallory, f.alice) != AgreementSigned {
		t.Fatal("owner approval not signed")
	}
	if _, err := f.chat.Get(ctx, "messages", remoteMallory); err != nil {
		t.Fatal(err)
	}
}

func TestChatConditionsTravelInSwiftsAgreementWireFormat(t *testing.T) {
	f := invitedChat(t, "invitationAccepted", "member")
	request := chatRequest(t, f.chat, publicChatIdentity(t, f.bob))
	data, _ := json.Marshal(request)
	var wire map[string]any
	_ = json.Unmarshal(data, &wire)
	conditions := wire["conditions"].([]any)
	if len(conditions) != 2 {
		t.Fatalf("conditions %#v", conditions)
	}
	first := conditions[0].(map[string]any)
	inner := first["condition"].(map[string]any)
	if first["type"] != "lookup" || inner["keypath"] != "target.audience.admission.invitationAccepted" || inner["expectedValue"] != true || inner["name"] != "Lookup condition" {
		t.Fatalf("condition %#v", first)
	}
	for _, raw := range wire["grants"].([]any) {
		grant := raw.(map[string]any)
		if grant["keypath"] == "sendMessage" {
			permission := grant["permission"].(map[string]any)
			if permission["group"] != float64(6) || permission["other"] != float64(0) {
				t.Fatalf("permission %#v", permission)
			}
			return
		}
	}
	t.Fatal("no sendMessage grant")
}
