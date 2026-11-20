// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

// The model participant on ChatCell (PDD_modell-i-felles-chat_2026-11-15):
// the same model.* keys and result shapes as CellBase Swift.

import (
	"context"
	"sort"
	"time"

	"github.com/Digipomps/GoCellProtocol/interop"
)

type chatModelAsk struct {
	id, askedByUUID, askedByDisplayName, questionMessageID string
	routeClass, createdAt, status                          string
	contextMessageIDs                                      []string
}

func (a *chatModelAsk) object() map[string]any {
	return map[string]any{
		"askID": a.id, "askedByUUID": a.askedByUUID, "askedByDisplayName": a.askedByDisplayName,
		"questionMessageID": a.questionMessageID, "routeClass": a.routeClass, "createdAt": a.createdAt,
		"contextCount": len(a.contextMessageIDs), "status": a.status,
	}
}

func chatModelRefusal(code, message string) map[string]any {
	return map[string]any{"status": "refused", "code": code, "message": message}
}

// Caller holds stateMu for everything below unless the name is exported.

func (c *ChatCell) isModel(requester *Identity) bool {
	return c.modelPerson != nil && c.modelPerson.matches(requester)
}

// humanMemberUUIDs are the owner and everyone with an accepted invitation, the model left out.
func (c *ChatCell) humanMemberUUIDs() []string {
	seen := map[string]bool{}
	if owner := c.ownerIdentity(); owner != nil {
		seen[owner.UUID] = true
	}
	for uuid, record := range c.invitations {
		if record.status == "accepted" && (c.modelPerson == nil || uuid != c.modelPerson.uuid) {
			seen[uuid] = true
		}
	}
	out := make([]string, 0, len(seen))
	for uuid := range seen {
		out = append(out, uuid)
	}
	sort.Strings(out)
	return out
}

func (c *ChatCell) isHumanMember(requester *Identity) bool {
	if requester == nil || c.isModel(requester) {
		return false
	}
	if c.ownerPerson != nil && c.ownerPerson.matches(requester) {
		return true
	}
	return c.memberFor(requester) != nil
}

func (c *ChatCell) modelConsentHolds() bool {
	return c.modelLedger.ModelConsentHolds(c.humanMemberUUIDs())
}

func (c *ChatCell) modelMembersChanged() {
	c.modelLedger.MembersChanged(c.humanMemberUUIDs(), c.now())
	c.failAsksIfModelLostAccess()
}

func (c *ChatCell) displayNameFor(uuid string) string {
	if owner := c.ownerIdentity(); owner != nil && owner.UUID == uuid {
		return owner.DisplayName
	}
	if record, ok := c.invitations[uuid]; ok {
		return record.person.displayName
	}
	if row, ok := c.participants[uuid]; ok {
		return extString(row["displayName"])
	}
	return uuid
}

func (c *ChatCell) notice(ask *chatModelAsk, code, message string) {
	c.modelNotices[ask.askedByUUID] = map[string]any{
		"askID": ask.id, "code": code, "message": message, "routeClass": ask.routeClass, "at": c.now(),
	}
}

func (c *ChatCell) failAsksIfModelLostAccess() {
	if c.modelConsentHolds() {
		return
	}
	for _, ask := range c.modelAsks {
		if ask.status == "open" {
			ask.status = "failed"
			c.notice(ask, "model_removed", "Modellen er ikke lenger med i samtalen, så spørsmålet ble ikke besvart.")
		}
	}
}

func (c *ChatCell) expireOldAsks() {
	cutoff := interop.ChatTimestamp(c.opts.Clock().Add(-ChatModelAskLifetimeSeconds * time.Second))
	for _, ask := range c.modelAsks {
		if ask.status == "open" && ask.createdAt < cutoff {
			ask.status = "expired"
			c.notice(ask, "ask_expired", "Modellen svarte ikke i tide. Prøv igjen.")
		}
	}
}

func orNilString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func (c *ChatCell) modelState(requester *Identity) map[string]any {
	ledger, members := c.modelLedger, c.humanMemberUUIDs()
	uuid := ""
	if requester != nil {
		uuid = requester.UUID
	}
	consented := ledger.ConsentedMembers(members)
	consentedNames, declinedNames := []any{}, []any{}
	externalCount := 0
	for _, m := range consented {
		consentedNames = append(consentedNames, c.displayNameFor(m))
	}
	for _, m := range members {
		if ledger.declined(m) {
			declinedNames = append(declinedNames, c.displayNameFor(m))
		}
		if consent, ok := ledger.Consents[m]; ok && consent.External {
			externalCount++
		}
	}
	isMember := containsString(members, uuid) && !c.isModel(requester)
	state := map[string]any{
		"status":                 ledger.Status,
		"hasProposal":            ledger.Status == "proposed",
		"isActive":               c.modelConsentHolds(),
		"canPropose":             isMember && (ledger.Status == "none" || ledger.Status == "removed"),
		"awaitingMe":             ledger.AwaitingAnswer(uuid, members),
		"externalAllowed":        ledger.ExternalAllowed(members),
		"consentedCount":         len(consented),
		"memberCount":            len(members),
		"consentedNames":         consentedNames,
		"declinedNames":          declinedNames,
		"externalConsentedCount": externalCount,
		"modelUUID":              orNilString(ledger.ModelUUID),
		"modelDisplayName":       orNilString(ledger.ModelDisplayName),
		"proposedByName":         nil,
		"proposedAt":             orNilString(ledger.ProposedAt),
		"activatedAt":            orNilString(ledger.ActivatedAt),
		"myConsent":              nil,
		"contextLimit":           ChatModelContextLimit,
		"notice":                 nil,
	}
	if ledger.ProposedByUUID != "" {
		state["proposedByName"] = c.displayNameFor(ledger.ProposedByUUID)
	}
	if consent, ok := ledger.Consents[uuid]; ok {
		state["myConsent"] = map[string]any{"external": consent.External, "at": consent.At}
	}
	if notice, ok := c.modelNotices[uuid]; ok {
		state["notice"] = copyMap(notice)
	}
	if c.isModel(requester) {
		open := []*chatModelAsk{}
		for _, ask := range c.modelAsks {
			if ask.status == "open" {
				open = append(open, ask)
			}
		}
		sort.Slice(open, func(i, j int) bool { return open[i].createdAt < open[j].createdAt })
		asks := []any{}
		for _, ask := range open {
			asks = append(asks, ask.object())
		}
		state["openAsks"] = asks
	}
	return state
}

func (c *ChatCell) modelConsent(ctx context.Context, keypath string, requester *Identity) (any, error) {
	_, _ = ctx, keypath
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.isModel(requester) && c.modelConsentHolds(), nil
}

func (c *ChatCell) modelGet(ctx context.Context, keypath string, requester *Identity) (any, error) {
	_, _ = ctx, keypath
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if !c.isHumanMember(requester) && !(c.isModel(requester) && c.modelConsentHolds()) {
		return "denied", nil
	}
	c.expireOldAsks()
	return c.modelState(requester), nil
}

func (c *ChatCell) modelSet(ctx context.Context, keypath string, value any, requester *Identity) (any, error) {
	_ = ctx
	payload, _ := ObjectValue(NormalizeJSON(value))
	if payload == nil {
		payload = map[string]any{}
	}
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	switch keypath {
	case "model.context", "model.answer", "model.fail":
		if !c.isModel(requester) || (keypath != "model.fail" && !c.modelConsentHolds()) {
			return "denied", nil
		}
		switch keypath {
		case "model.context":
			return c.modelContext(payload), nil
		case "model.answer":
			return c.modelAnswer(payload, requester), nil
		}
		return c.modelFail(payload), nil
	}
	if !c.isHumanMember(requester) {
		return "denied", nil
	}
	switch keypath {
	case "model.ask":
		return c.openModelAsk(payload, requester), nil
	case "model.dismissNotice":
		delete(c.modelNotices, requester.UUID)
		return map[string]any{"status": "ok", "model": c.modelState(requester)}, nil
	}
	members, now, by := c.humanMemberUUIDs(), c.now(), requester.UUID
	external, _ := payload["external"].(bool)
	var err error
	switch keypath {
	case "model.propose":
		model := chatPersonFromValue(payload["identity"])
		if model == nil || model.descriptor == nil {
			return chatModelRefusal("invalid_payload", "model.propose needs {identity}"), nil
		}
		if model.uuid == by || containsString(members, model.uuid) {
			return chatModelRefusal("invalid_model", "A member cannot be the model participant."), nil
		}
		name := extString(payload["displayName"])
		if name == "" {
			name = "Språkmodell"
		}
		if err = c.modelLedger.Propose(model.uuid, name, by, external, now, members); err == nil {
			c.modelPerson = model
			c.modelAsks = map[string]*chatModelAsk{}
		}
	case "model.consent":
		err = c.modelLedger.Consent(by, external, now, members)
	case "model.decline":
		err = c.modelLedger.Decline(by, now, members)
	case "model.remove":
		err = c.modelLedger.Remove(by, now, members)
	}
	if refusal, ok := err.(*ChatModelRefusal); ok {
		return chatModelRefusal(refusal.Code, refusal.Code), nil
	}
	c.failAsksIfModelLostAccess()
	return map[string]any{"status": "ok", "model": c.modelState(requester)}, nil
}

func (c *ChatCell) openModelAsk(payload map[string]any, requester *Identity) any {
	c.expireOldAsks()
	activatedAt := c.modelLedger.ActivatedAt
	if !c.modelConsentHolds() || activatedAt == "" {
		return chatModelRefusal("model_not_active", "Modellen er ikke med i samtalen.")
	}
	route := extString(payload["route"])
	if route == "" {
		route = "local"
	}
	if route != "local" && route != "external" {
		return chatModelRefusal("invalid_route", "route must be local or external")
	}
	if route == "external" && !c.modelLedger.ExternalAllowed(c.humanMemberUUIDs()) {
		return chatModelRefusal("external_not_allowed", "Alle i samtalen må si ja til ekstern modell først.")
	}
	messageID := extString(payload["messageID"])
	var question map[string]any
	stamps := make([]ChatModelMessageStamp, 0, len(c.messages))
	for _, m := range c.messages {
		if extString(m["id"]) == messageID {
			question = m
		}
		stamps = append(stamps, ChatModelMessageStamp{ID: extString(m["id"]), CreatedAt: extString(m["createdAt"])})
	}
	if question == nil {
		return chatModelRefusal("no_question", "Fant ikke spørsmålet.")
	}
	if extString(question["ownerUUID"]) != requester.UUID || extString(question["authorKind"]) != "person" {
		return chatModelRefusal("not_your_message", "Du kan bare spørre modellen om din egen melding.")
	}
	contextIDs := ChatModelContextMessageIDs(stamps, activatedAt, messageID, ChatModelContextLimit)
	if !containsString(contextIDs, messageID) {
		return chatModelRefusal("question_before_model", "Spørsmålet ble skrevet før modellen kom inn.")
	}
	name := requester.DisplayName
	if name == "" {
		name = c.displayNameFor(requester.UUID)
	}
	ask := &chatModelAsk{
		id: "ask-" + c.opts.NewUUID(), askedByUUID: requester.UUID, askedByDisplayName: name,
		questionMessageID: messageID, routeClass: route, createdAt: c.now(), status: "open",
		contextMessageIDs: contextIDs,
	}
	c.modelAsks[ask.id] = ask
	delete(c.modelNotices, requester.UUID)
	return map[string]any{"status": "open", "ask": ask.object()}
}

func (c *ChatCell) openAsk(payload map[string]any) *chatModelAsk {
	ask, ok := c.modelAsks[extString(payload["askID"])]
	if !ok || ask.status != "open" {
		return nil
	}
	return ask
}

func (c *ChatCell) modelContext(payload map[string]any) any {
	c.expireOldAsks()
	ask := c.openAsk(payload)
	if ask == nil {
		return chatModelRefusal("no_open_ask", "No open ask with that id.")
	}
	byID := map[string]map[string]any{}
	for _, m := range c.messages {
		byID[extString(m["id"])] = m
	}
	messages := []any{}
	for _, id := range ask.contextMessageIDs {
		if m, ok := byID[id]; ok {
			messages = append(messages, map[string]any{
				"id": m["id"], "authorDisplayName": m["ownerDisplayName"], "authorKind": m["authorKind"],
				"content": m["content"], "createdAt": m["createdAt"],
			})
		}
	}
	question := ""
	if m, ok := byID[ask.questionMessageID]; ok {
		question = extString(m["content"])
	}
	return map[string]any{"status": "ok", "ask": ask.object(), "question": question, "messages": messages}
}

func (c *ChatCell) modelAnswer(payload map[string]any, requester *Identity) any {
	ask := c.openAsk(payload)
	if ask == nil {
		return chatModelRefusal("no_open_ask", "No open ask with that id.")
	}
	if ask.routeClass == "external" && !c.modelLedger.ExternalAllowed(c.humanMemberUUIDs()) {
		ask.status = "failed"
		c.notice(ask, "external_not_allowed", "Noen har trukket ja til ekstern modell, så svaret ble ikke vist.")
		return chatModelRefusal("external_not_allowed", "External routes are no longer allowed in this chat.")
	}
	text := SanitizeChatModelAnswer(extString(payload["text"]))
	if text == "" {
		return chatModelRefusal("empty_answer", "The answer is empty.")
	}
	fields := map[string]any{
		"askedByUUID": ask.askedByUUID, "askedByDisplayName": ask.askedByDisplayName,
		"routeClass": ask.routeClass, "contextCount": len(ask.contextMessageIDs),
	}
	if model := extString(payload["model"]); model != "" {
		fields["model"] = model
	}
	ask.status = "answered"
	return c.storeMessage(text, "text/plain", c.opts.Topic, requester, fields)
}

func (c *ChatCell) modelFail(payload map[string]any) any {
	ask := c.openAsk(payload)
	if ask == nil {
		return chatModelRefusal("no_open_ask", "No open ask with that id.")
	}
	ask.status = "failed"
	code := extString(payload["code"])
	if code == "" {
		code = "model_unavailable"
	}
	message := extString(payload["message"])
	if message == "" {
		message = "Modellen svarte ikke."
	}
	c.notice(ask, code, SanitizeChatModelAnswer(message))
	return map[string]any{"status": "ok", "askID": ask.id}
}
