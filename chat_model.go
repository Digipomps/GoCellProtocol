// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

// A language model as a named participant in a chat
// (PDD_modell-i-felles-chat_2026-11-15). The same pure rules as CellBase
// Swift's ChatModelConsentLedger and ChatModelRules, checked against the same
// scenario fixtures (testdata/chat-model-v1, copied from CellProtocol).
//
//   - The model comes in only when every human member has said yes.
//   - Any member can say no or take back a yes; the model loses access at once.
//   - A member who joins after the model came in does not stop it, but external
//     routes need every current member's explicit yes, including the newcomer's.
//   - Any member can remove the model. It must be proposed again to come back.
//
// ChatModelProvider is the pluggable model; FakeChatModelProvider answers in
// tests, and ServeOpenAsks drives one round of asks for a model identity.

import (
	"context"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	ChatModelContextLimit       = 20
	ChatModelAnswerLimitScalars = 4000
	ChatModelAskLifetimeSeconds = 600
)

// ChatModelMentionTokens address a message to the model.
var ChatModelMentionTokens = []string{"@modell", "@model"}

// ChatModelRefusal is a refused ledger event; Code is the shared wire value.
type ChatModelRefusal struct{ Code string }

func (r *ChatModelRefusal) Error() string { return r.Code }

const (
	ChatModelNotMember      = "not_member"
	ChatModelAlreadyPresent = "already_present"
	ChatModelNoProposal     = "no_proposal"
)

type ChatModelConsent struct {
	External bool
	At       string
}

// ChatModelConsentLedger records who said yes or no to the model.
type ChatModelConsentLedger struct {
	Status           string // none | proposed | active | removed
	ModelUUID        string
	ModelDisplayName string
	ProposedByUUID   string
	ProposedAt       string
	ActivatedAt      string // empty when not active
	Consents         map[string]ChatModelConsent
	Declined         map[string]string
}

func NewChatModelConsentLedger() *ChatModelConsentLedger {
	return &ChatModelConsentLedger{Status: "none", Consents: map[string]ChatModelConsent{}, Declined: map[string]string{}}
}

func containsString(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func (l *ChatModelConsentLedger) Propose(modelUUID, displayName, by string, external bool, at string, members []string) error {
	if !containsString(members, by) {
		return &ChatModelRefusal{ChatModelNotMember}
	}
	if l.Status != "none" && l.Status != "removed" {
		return &ChatModelRefusal{ChatModelAlreadyPresent}
	}
	l.Status, l.ModelUUID, l.ModelDisplayName = "proposed", modelUUID, displayName
	l.ProposedByUUID, l.ProposedAt, l.ActivatedAt = by, at, ""
	l.Consents = map[string]ChatModelConsent{by: {External: external, At: at}}
	l.Declined = map[string]string{}
	l.reevaluate(members, at)
	return nil
}

func (l *ChatModelConsentLedger) requireOpen(by string, members []string) error {
	if !containsString(members, by) {
		return &ChatModelRefusal{ChatModelNotMember}
	}
	if l.Status != "proposed" && l.Status != "active" {
		return &ChatModelRefusal{ChatModelNoProposal}
	}
	return nil
}

func (l *ChatModelConsentLedger) Consent(by string, external bool, at string, members []string) error {
	if err := l.requireOpen(by, members); err != nil {
		return err
	}
	l.Consents[by] = ChatModelConsent{External: external, At: at}
	delete(l.Declined, by)
	l.reevaluate(members, at)
	return nil
}

// Decline says no to a proposal, or takes back a yes. The model stops at once.
func (l *ChatModelConsentLedger) Decline(by, at string, members []string) error {
	if err := l.requireOpen(by, members); err != nil {
		return err
	}
	delete(l.Consents, by)
	l.Declined[by] = at
	l.reevaluate(members, at)
	return nil
}

func (l *ChatModelConsentLedger) Remove(by, at string, members []string) error {
	_ = at
	if err := l.requireOpen(by, members); err != nil {
		return err
	}
	l.Status, l.ActivatedAt = "removed", ""
	l.Consents = map[string]ChatModelConsent{}
	l.Declined = map[string]string{}
	return nil
}

// MembersChanged re-checks activation after someone joined or left.
func (l *ChatModelConsentLedger) MembersChanged(members []string, at string) {
	l.reevaluate(members, at)
}

func (l *ChatModelConsentLedger) said(member string) bool {
	_, yes := l.Consents[member]
	_, no := l.Declined[member]
	return yes && !no
}

func (l *ChatModelConsentLedger) declined(member string) bool {
	_, no := l.Declined[member]
	return no
}

func (l *ChatModelConsentLedger) reevaluate(members []string, at string) {
	switch l.Status {
	case "proposed":
		all := len(members) > 0
		for _, m := range members {
			if !l.said(m) {
				all = false
			}
		}
		if all {
			l.Status, l.ActivatedAt = "active", at
		}
	case "active":
		anyNo := len(members) == 0
		for _, m := range members {
			if l.declined(m) {
				anyNo = true
			}
		}
		if anyNo {
			l.Status, l.ActivatedAt = "proposed", ""
		}
	}
}

// ModelConsentHolds is the Agreement condition for the model identity.
func (l *ChatModelConsentLedger) ModelConsentHolds(members []string) bool {
	if l.Status != "active" || len(members) == 0 {
		return false
	}
	for _, m := range members {
		if l.declined(m) {
			return false
		}
	}
	return true
}

// ExternalAllowed needs every current member's explicit yes to external.
func (l *ChatModelConsentLedger) ExternalAllowed(members []string) bool {
	if !l.ModelConsentHolds(members) {
		return false
	}
	for _, m := range members {
		if consent, ok := l.Consents[m]; !ok || !consent.External {
			return false
		}
	}
	return true
}

func (l *ChatModelConsentLedger) AwaitingAnswer(member string, members []string) bool {
	_, yes := l.Consents[member]
	return l.Status == "proposed" && containsString(members, member) && !yes && !l.declined(member)
}

func (l *ChatModelConsentLedger) ConsentedMembers(members []string) []string {
	out := []string{}
	for _, m := range members {
		if l.said(m) {
			out = append(out, m)
		}
	}
	return out
}

// ---- pure rules ------------------------------------------------------------------

func chatModelWordRune(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsMark(r) || unicode.IsNumber(r)
}

// IsAddressedToModel: @modell or @model (any case) not inside a word.
func IsAddressedToModel(text string) bool {
	lower := strings.ToLower(text)
	for _, token := range ChatModelMentionTokens {
		start := 0
		for {
			index := strings.Index(lower[start:], token)
			if index < 0 {
				break
			}
			index += start
			end := index + len(token)
			precededOK := index == 0
			if !precededOK {
				r, _ := utf8.DecodeLastRuneInString(lower[:index])
				precededOK = !chatModelWordRune(r)
			}
			followedOK := end == len(lower)
			if !followedOK {
				r, _ := utf8.DecodeRuneInString(lower[end:])
				followedOK = !chatModelWordRune(r)
			}
			if precededOK && followedOK {
				return true
			}
			start = end
		}
	}
	return false
}

// ChatModelMessageStamp is the part of a message the context window looks at.
type ChatModelMessageStamp struct{ ID, CreatedAt string }

// ChatModelContextMessageIDs: messages written at or after activatedAt, up to
// and including the question, newest limit kept.
func ChatModelContextMessageIDs(messages []ChatModelMessageStamp, activatedAt, questionID string, limit int) []string {
	index := -1
	for i, m := range messages {
		if m.ID == questionID {
			index = i
			break
		}
	}
	out := []string{}
	if index < 0 {
		return out
	}
	for _, m := range messages[:index+1] {
		if m.CreatedAt >= activatedAt {
			out = append(out, m.ID)
		}
	}
	if limit < 0 {
		limit = 0
	}
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

// SanitizeChatModelAnswer: CRLF/CR to LF, controls other than LF and TAB
// dropped, trimmed, at most 4000 Unicode scalars.
func SanitizeChatModelAnswer(text string) string {
	normalized := strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
	var b strings.Builder
	for _, r := range normalized {
		if r == '\n' || r == '\t' {
			b.WriteRune(r)
			continue
		}
		if r < 0x20 || r == 0x7F || (r >= 0x80 && r <= 0x9F) {
			continue
		}
		b.WriteRune(r)
	}
	runes := []rune(strings.TrimSpace(b.String()))
	if len(runes) > ChatModelAnswerLimitScalars {
		runes = runes[:ChatModelAnswerLimitScalars]
	}
	return string(runes)
}

// ---- pluggable provider --------------------------------------------------------------

// ChatModelUnavailable means the provider could not answer. Only the asker is told.
type ChatModelUnavailable struct{ Code, Message string }

func (e *ChatModelUnavailable) Error() string { return e.Message }

type ChatModelReply struct{ Text, Model string }

type ChatModelProvider interface {
	Answer(ctx context.Context, question string, messages []any, route string) (ChatModelReply, error)
}

// FakeChatModelProvider answers with Reply, or fails with Failure. It records each call.
type FakeChatModelProvider struct {
	Reply   func(question string, messages []any, route string) string
	Model   string
	Failure *ChatModelUnavailable
	Calls   []map[string]any
}

func (f *FakeChatModelProvider) Answer(ctx context.Context, question string, messages []any, route string) (ChatModelReply, error) {
	_ = ctx
	f.Calls = append(f.Calls, map[string]any{"question": question, "messages": messages, "route": route})
	if f.Failure != nil {
		return ChatModelReply{}, f.Failure
	}
	model := f.Model
	if model == "" {
		model = "fake-model"
	}
	text := "Svar fra testmodellen."
	if f.Reply != nil {
		text = f.Reply(question, messages, route)
	}
	return ChatModelReply{Text: text, Model: model}, nil
}

// ServeOpenAsks is one round for the model identity: read each open ask, ask
// the provider, then answer or fail.
func ServeOpenAsks(ctx context.Context, chat *ChatCell, model *Identity, provider ChatModelProvider) ([]any, error) {
	stateValue, err := chat.Get(ctx, "model.state", model)
	if err != nil {
		return nil, err
	}
	state, ok := stateValue.(map[string]any)
	if !ok {
		return nil, nil
	}
	asks, _ := state["openAsks"].([]any)
	results := []any{}
	for _, item := range asks {
		ask, _ := item.(map[string]any)
		askID := extString(ask["askID"])
		contextValue, err := chat.Set(ctx, "model.context", map[string]any{"askID": askID}, model)
		if err != nil {
			return results, err
		}
		context, ok := contextValue.(map[string]any)
		if !ok || context["status"] != "ok" {
			results = append(results, contextValue)
			continue
		}
		messages, _ := context["messages"].([]any)
		reply, err := provider.Answer(ctx, extString(context["question"]), messages, extString(ask["routeClass"]))
		var result any
		if failure, isFailure := err.(*ChatModelUnavailable); isFailure {
			result, err = chat.Set(ctx, "model.fail", map[string]any{"askID": askID, "code": failure.Code, "message": failure.Message}, model)
		} else if err != nil {
			result, err = chat.Set(ctx, "model.fail", map[string]any{"askID": askID, "code": "model_unavailable", "message": "Modellen svarte ikke."}, model)
		} else {
			result, err = chat.Set(ctx, "model.answer", map[string]any{"askID": askID, "text": reply.Text, "model": reply.Model}, model)
		}
		if err != nil {
			return results, err
		}
		results = append(results, result)
	}
	return results, nil
}
