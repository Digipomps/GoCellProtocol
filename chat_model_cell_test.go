// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

import (
	"context"
	"testing"
	"time"
)

// The model as a chat participant on a Go ChatCell, as in Swift (PDD_modell-i-felles-chat).

type modelChat struct {
	chat                              *ChatCell
	now                               *time.Time
	alice, bob, carol, model, mallory *Identity
}

func newModelChat(t *testing.T, withCarol bool) *modelChat {
	t.Helper()
	start := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	m := &modelChat{now: &start}
	m.alice = newChatIdentity(t, "Alice")
	m.bob = publicChatIdentity(t, newChatIdentity(t, "Bob"))
	m.carol = publicChatIdentity(t, newChatIdentity(t, "Carol"))
	m.model = publicChatIdentity(t, newChatIdentity(t, "Qwen"))
	m.mallory = publicChatIdentity(t, newChatIdentity(t, "Mallory"))
	m.chat = NewChatCell(m.alice, ChatCellOptions{Clock: func() time.Time {
		*m.now = m.now.Add(10 * time.Millisecond)
		return *m.now
	}})
	chatSet(t, m.chat, "audience.admissionConditions", []any{"member"}, m.alice)
	people := []*Identity{m.bob}
	if withCarol {
		people = append(people, m.carol)
	}
	for _, person := range people {
		chatSet(t, m.chat, "audience.inviteIdentities", []any{identityWire(t, person)}, m.alice)
		chatSet(t, m.chat, "audience.acceptInvites", []any{person.UUID}, m.alice)
		if agree(t, m.chat, chatRequest(t, m.chat, person), person, nil) != AgreementSigned {
			t.Fatalf("%s not signed", person.DisplayName)
		}
	}
	return m
}

func (m *modelChat) modelRequest(t *testing.T) AgreementState {
	return agree(t, m.chat, chatRequest(t, m.chat, m.model, ChatModelParticipantKeys...), m.model, nil)
}

func (m *modelChat) activate(t *testing.T, external bool) {
	t.Helper()
	proposed := chatSet(t, m.chat, "model.propose", map[string]any{"identity": identityWire(t, m.model), "displayName": "Qwen", "external": external}, m.alice).(map[string]any)
	if proposed["status"] != "ok" {
		t.Fatalf("propose %#v", proposed)
	}
	consented := chatSet(t, m.chat, "model.consent", map[string]any{"external": external}, m.bob).(map[string]any)
	if consented["model"].(map[string]any)["isActive"] != true {
		t.Fatalf("not active %#v", consented)
	}
	if m.modelRequest(t) != AgreementSigned {
		t.Fatal("model not signed")
	}
}

func obj(t *testing.T, value any) map[string]any {
	t.Helper()
	out, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("not an object: %#v", value)
	}
	return out
}

func modelState(t *testing.T, m *modelChat, who *Identity) map[string]any {
	return obj(t, chatGet(t, m.chat, "model.state", who))
}

func sendID(t *testing.T, m *modelChat, text string, who *Identity) string {
	return extString(obj(t, obj(t, chatSet(t, m.chat, "sendMessage", text, who))["message"])["id"])
}

func TestChatModelComesInOnlyWhenEveryMemberSaysYes(t *testing.T) {
	m := newModelChat(t, true)
	chatSet(t, m.chat, "model.propose", map[string]any{"identity": identityWire(t, m.model), "displayName": "Qwen"}, m.alice)
	if chatGet(t, m.chat, "audience.admission.modelConsent", m.model) != false || m.modelRequest(t) != AgreementRejected {
		t.Fatal("model admitted before everyone said yes")
	}
	if modelState(t, m, m.carol)["awaitingMe"] != true {
		t.Fatal("carol should be asked")
	}
	chatSet(t, m.chat, "model.consent", map[string]any{}, m.bob)
	if m.modelRequest(t) != AgreementRejected {
		t.Fatal("admitted with carol unanswered")
	}
	state := obj(t, obj(t, chatSet(t, m.chat, "model.consent", map[string]any{}, m.carol))["model"])
	if state["isActive"] != true || state["consentedCount"] != 3 || state["memberCount"] != 3 {
		t.Fatalf("state %#v", state)
	}
	if m.modelRequest(t) != AgreementSigned {
		t.Fatal("model not signed after all said yes")
	}
	if asks := modelState(t, m, m.model)["openAsks"].([]any); len(asks) != 0 {
		t.Fatalf("asks %#v", asks)
	}
}

func TestChatModelReadsOnlyForAnOpenAskAndAnswersAsModel(t *testing.T) {
	m := newModelChat(t, false)
	ctx := context.Background()
	sendID(t, m, "skrevet før modellen kom", m.bob)
	m.activate(t, false)
	if _, err := m.chat.Get(ctx, "messages", m.model); err == nil {
		t.Fatal("model read messages")
	}
	if _, err := m.chat.Set(ctx, "sendMessage", "hei", m.model); err == nil {
		t.Fatal("model sent a message")
	}
	question := sendID(t, m, "@modell hva er et formål?", m.bob)
	if code := obj(t, chatSet(t, m.chat, "model.ask", map[string]any{"messageID": question}, m.alice))["code"]; code != "not_your_message" {
		t.Fatalf("code %v", code)
	}
	opened := obj(t, chatSet(t, m.chat, "model.ask", map[string]any{"messageID": question}, m.bob))
	ask := obj(t, opened["ask"])
	if opened["status"] != "open" || ask["contextCount"] != 1 {
		t.Fatalf("opened %#v", opened)
	}
	provider := &FakeChatModelProvider{Reply: func(q string, _ []any, _ string) string { return "Svar på: " + q + "\r\n\u0007ferdig" }}
	results, err := ServeOpenAsks(ctx, m.chat, m.model, provider)
	if err != nil || len(results) != 1 {
		t.Fatalf("results %#v %v", results, err)
	}
	if got := provider.Calls[0]["messages"].([]any); len(got) != 1 || obj(t, got[0])["content"] != "@modell hva er et formål?" {
		t.Fatalf("context %#v", got)
	}
	answer := obj(t, obj(t, results[0])["message"])
	if answer["authorKind"] != "model" || answer["askedByUUID"] != m.bob.UUID || answer["content"] != "Svar på: @modell hva er et formål?\nferdig" ||
		answer["routeClass"] != "local" || answer["contextCount"] != 1 || answer["model"] != "fake-model" || answer["ownerDisplayName"] != "Qwen" {
		t.Fatalf("answer %#v", answer)
	}
	if code := obj(t, chatSet(t, m.chat, "model.context", map[string]any{"askID": ask["askID"]}, m.model))["code"]; code != "no_open_ask" {
		t.Fatalf("ask not spent: %v", code)
	}
	kinds := map[string]any{}
	for _, row := range chatGet(t, m.chat, "participants", m.alice).([]any) {
		kinds[extString(obj(t, row)["id"])] = obj(t, row)["kind"]
	}
	if kinds[m.model.UUID] != "model" || kinds[m.bob.UUID] != "person" {
		t.Fatalf("kinds %#v", kinds)
	}
}

func TestChatModelContextIsCappedAtTwenty(t *testing.T) {
	m := newModelChat(t, false)
	m.activate(t, false)
	for i := 0; i < 25; i++ {
		sendID(t, m, "melding", m.alice)
	}
	question := sendID(t, m, "@model oppsummer", m.bob)
	ask := obj(t, obj(t, chatSet(t, m.chat, "model.ask", map[string]any{"messageID": question}, m.bob))["ask"])
	messages := obj(t, chatSet(t, m.chat, "model.context", map[string]any{"askID": ask["askID"]}, m.model))["messages"].([]any)
	if len(messages) != 20 || obj(t, messages[19])["content"] != "@model oppsummer" {
		t.Fatalf("context %d", len(messages))
	}
}

func TestChatModelWithdrawalStopsTheModelAtOnce(t *testing.T) {
	m := newModelChat(t, false)
	ctx := context.Background()
	m.activate(t, false)
	question := sendID(t, m, "@modell hei", m.bob)
	chatSet(t, m.chat, "model.ask", map[string]any{"messageID": question}, m.bob)
	chatSet(t, m.chat, "model.decline", nil, m.alice)
	if chatGet(t, m.chat, "audience.admission.modelConsent", m.model) != false {
		t.Fatal("consent still holds")
	}
	if _, err := m.chat.Get(ctx, "model.state", m.model); err == nil {
		t.Fatal("model still reads")
	}
	if notice := modelState(t, m, m.bob)["notice"]; notice == nil || obj(t, notice)["code"] != "model_removed" {
		t.Fatalf("notice %#v", notice)
	}
	if modelState(t, m, m.alice)["notice"] != nil {
		t.Fatal("alice got bob's notice")
	}
	chatSet(t, m.chat, "model.consent", map[string]any{}, m.alice)
	if chatGet(t, m.chat, "audience.admission.modelConsent", m.model) != true {
		t.Fatal("yes again did not restore")
	}
	removed := obj(t, obj(t, chatSet(t, m.chat, "model.remove", nil, m.bob))["model"])
	if removed["status"] != "removed" || removed["canPropose"] != true {
		t.Fatalf("removed %#v", removed)
	}
	if code := obj(t, chatSet(t, m.chat, "model.consent", map[string]any{}, m.alice))["code"]; code != "no_proposal" {
		t.Fatalf("code %v", code)
	}
}

func TestChatModelNewcomerKeepsModelButExternalNeedsTheirYes(t *testing.T) {
	m := newModelChat(t, false)
	m.activate(t, true)
	if modelState(t, m, m.alice)["externalAllowed"] != true {
		t.Fatal("external not allowed")
	}
	chatSet(t, m.chat, "audience.inviteIdentities", []any{identityWire(t, m.carol)}, m.alice)
	chatSet(t, m.chat, "audience.acceptInvites", []any{m.carol.UUID}, m.alice)
	if agree(t, m.chat, chatRequest(t, m.chat, m.carol), m.carol, nil) != AgreementSigned {
		t.Fatal("carol not signed")
	}
	state := modelState(t, m, m.carol)
	if state["isActive"] != true || state["externalAllowed"] != false {
		t.Fatalf("state %#v", state)
	}
	question := sendID(t, m, "@modell ekstern?", m.bob)
	external := map[string]any{"messageID": question, "route": "external"}
	if code := obj(t, chatSet(t, m.chat, "model.ask", external, m.bob))["code"]; code != "external_not_allowed" {
		t.Fatalf("code %v", code)
	}
	chatSet(t, m.chat, "model.consent", map[string]any{"external": true}, m.carol)
	opened := obj(t, chatSet(t, m.chat, "model.ask", external, m.bob))
	if opened["status"] != "open" {
		t.Fatalf("opened %#v", opened)
	}
	chatSet(t, m.chat, "model.consent", map[string]any{"external": false}, m.carol)
	answered := obj(t, chatSet(t, m.chat, "model.answer", map[string]any{"askID": obj(t, opened["ask"])["askID"], "text": "hei"}, m.model))
	if answered["code"] != "external_not_allowed" || obj(t, modelState(t, m, m.bob)["notice"])["code"] != "external_not_allowed" {
		t.Fatalf("answered %#v", answered)
	}
	for _, msg := range chatGet(t, m.chat, "messages", m.alice).([]any) {
		if obj(t, msg)["authorKind"] != "person" {
			t.Fatal("model answer shown")
		}
	}
}

func TestChatModelFailureIsShownOnlyToTheAsker(t *testing.T) {
	m := newModelChat(t, false)
	m.activate(t, false)
	question := sendID(t, m, "@modell hei", m.bob)
	chatSet(t, m.chat, "model.ask", map[string]any{"messageID": question}, m.bob)
	failing := &FakeChatModelProvider{Failure: &ChatModelUnavailable{Code: "model_unavailable", Message: "Den lokale modellen er ikke i gang."}}
	if _, err := ServeOpenAsks(context.Background(), m.chat, m.model, failing); err != nil {
		t.Fatal(err)
	}
	if obj(t, modelState(t, m, m.bob)["notice"])["message"] != "Den lokale modellen er ikke i gang." || modelState(t, m, m.alice)["notice"] != nil {
		t.Fatal("notice wrong")
	}
	if n := len(chatGet(t, m.chat, "messages", m.alice).([]any)); n != 1 {
		t.Fatalf("messages %d", n)
	}
	if obj(t, obj(t, chatSet(t, m.chat, "model.dismissNotice", nil, m.bob))["model"])["notice"] != nil {
		t.Fatal("not dismissed")
	}
}

func TestChatModelAskExpiresAfterTenMinutes(t *testing.T) {
	m := newModelChat(t, false)
	m.activate(t, false)
	question := sendID(t, m, "@modell hei", m.bob)
	ask := obj(t, obj(t, chatSet(t, m.chat, "model.ask", map[string]any{"messageID": question}, m.bob))["ask"])
	*m.now = m.now.Add(601 * time.Second)
	if code := obj(t, chatSet(t, m.chat, "model.context", map[string]any{"askID": ask["askID"]}, m.model))["code"]; code != "no_open_ask" {
		t.Fatalf("code %v", code)
	}
	if obj(t, modelState(t, m, m.bob)["notice"])["code"] != "ask_expired" {
		t.Fatal("no expiry notice")
	}
}

func TestChatModelStrangersAndImpostorsStayOut(t *testing.T) {
	m := newModelChat(t, false)
	ctx := context.Background()
	if code := obj(t, chatSet(t, m.chat, "model.propose", map[string]any{"identity": identityWire(t, m.bob)}, m.alice))["code"]; code != "invalid_model" {
		t.Fatalf("code %v", code)
	}
	m.activate(t, false)
	if _, err := m.chat.Set(ctx, "model.propose", map[string]any{"identity": identityWire(t, m.mallory)}, m.mallory); err == nil {
		t.Fatal("stranger proposed")
	}
	if _, err := m.chat.Get(ctx, "model.state", m.mallory); err == nil {
		t.Fatal("stranger read state")
	}
	impostor := publicChatIdentity(t, m.mallory)
	impostor.UUID = m.model.UUID
	if chatGet(t, m.chat, "audience.admission.modelConsent", impostor) != false {
		t.Fatal("impostor consent")
	}
	if _, err := m.chat.Set(ctx, "model.answer", map[string]any{"askID": "x", "text": "hei"}, impostor); err == nil {
		t.Fatal("impostor answered")
	}
	if got := chatSet(t, m.chat, "model.answer", map[string]any{"askID": "x", "text": "hei"}, m.bob); got != "denied" {
		t.Fatalf("member posed as model: %v", got)
	}
}

func TestChatModelNodeHostedChatCountsOnlyItsPeople(t *testing.T) {
	m := newModelChat(t, true)
	ctx := context.Background()
	if got := obj(t, chatSet(t, m.chat, "model.ownerIsMember", false, m.alice)); got["ownerIsMember"] != false {
		t.Fatalf("got %#v", got)
	}
	if _, err := m.chat.Set(ctx, "model.ownerIsMember", true, m.bob); err == nil {
		t.Fatal("member changed hosting")
	}
	chatSet(t, m.chat, "model.propose", map[string]any{"identity": identityWire(t, m.model), "displayName": "Qwen"}, m.bob)
	state := obj(t, obj(t, chatSet(t, m.chat, "model.consent", map[string]any{}, m.carol))["model"])
	if state["isActive"] != true || state["memberCount"] != 2 {
		t.Fatalf("state %#v", state)
	}
	if got := chatSet(t, m.chat, "model.decline", nil, m.alice); got != "denied" {
		t.Fatalf("node answered for people: %v", got)
	}
	if m.modelRequest(t) != AgreementSigned {
		t.Fatal("model not admitted")
	}
	chatSet(t, m.chat, "model.remove", nil, m.bob)
	if code := obj(t, chatSet(t, m.chat, "model.propose", map[string]any{"identity": identityWire(t, m.alice)}, m.bob))["code"]; code != "invalid_model" {
		t.Fatalf("code %v", code)
	}
}
