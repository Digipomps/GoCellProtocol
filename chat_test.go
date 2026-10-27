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

func invitedChat(t *testing.T) chatFixture {
	t.Helper()
	f := chatFixture{alice: newChatIdentity(t, "Alice"), bob: newChatIdentity(t, "Bob"), mallory: newChatIdentity(t, "Mallory")}
	f.chat = NewChatCell(f.alice, ChatCellOptions{})
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

	proof := map[string]any{"artifact": f.artifact, "acceptance": f.acceptance}
	accepted := chatSet(t, f.chat, "audience.acceptInvitationArtifact", proof, remoteBob).(map[string]any)
	if accepted["status"] != "accepted" || accepted["idempotent"] != false {
		t.Fatalf("accepted %#v", accepted)
	}
	again := chatSet(t, f.chat, "audience.acceptInvitationArtifact", proof, remoteBob).(map[string]any)
	if again["idempotent"] != true {
		t.Fatalf("again %#v", again)
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
