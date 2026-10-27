// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

// ChatCell is CellBase Swift's ChatCell for a Go node, with the same keypaths
// and result shapes for what a cross-language chat needs: messages,
// participants, audience, the signed invitation artifact and acceptance
// (ChatInvitationProofUtility), the composer, and the chat.message /
// chat.participant / chat.status flow events.
//
// Who may use the cell:
//   - the owner, proven as for every Go cell;
//   - an invited identity once it has accepted: the owner signs a
//     ChatInvitationArtifact for it (audience.generateInvitationArtifacts),
//     the invitee signs a ChatInvitationAcceptance on its own node
//     (audience.generateInvitationAcceptance), and anyone may hand both to
//     audience.acceptInvitationArtifact, which checks both signatures. From
//     then on that identity's key may read and send. Revoking takes it away.
//
// Swift reaches the same result through its Agreement grants; Go has no
// Agreement admission yet, so the verified acceptance is what admits here. A
// member is recognised by its signing key, which the authenticated bridge
// checks on every command.
//
// Not ported: end-to-end encrypted envelopes (crypto.* says plaintext only),
// rekey tracking, the invitation ledger history and the demo emitter.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/Digipomps/GoCellProtocol/interop"
)

var (
	chatReadKeys = []string{"status", "state", "messages", "participants", "members", "audience", "audience.mode",
		"audience.inheritedRecipients", "audience.invitedRecipients", "audience.resolvedRecipients",
		"audience.invitations", "audience.invitationArtifacts", "compose.body", "compose.contentType",
		"compose.state", "compose.availableFormats", "crypto", "crypto.state"}
	chatWriteKeys = []string{"audience.mode", "audience.inviteIdentities", "audience.generateInvitationArtifacts",
		"audience.generateInvitationAcceptance", "audience.acceptInvitationArtifact",
		"audience.inspectInvitationArtifact", "audience.acceptInvites", "audience.declineInvites",
		"audience.revokeInvites", "audience.clearInvites", "compose.body", "compose.contentType",
		"sendMessage", "addMessage", "sendComposedMessage", "clearComposer"}
	chatMemberKeys = map[string]bool{"status": true, "state": true, "messages": true, "participants": true, "members": true,
		"audience": true, "audience.mode": true, "audience.inheritedRecipients": true, "audience.invitedRecipients": true,
		"audience.resolvedRecipients": true, "compose.body": true, "compose.contentType": true, "compose.state": true,
		"compose.availableFormats": true, "crypto": true, "crypto.state": true,
		"sendMessage": true, "addMessage": true, "sendComposedMessage": true, "clearComposer": true}
	chatOpenKeys    = map[string]bool{"audience.acceptInvitationArtifact": true, "audience.inspectInvitationArtifact": true}
	chatAudienceMod = map[string][2]string{
		"contextMembers":    {"Context members", "Bruk kjente deltakere og kontekstmedlemmer som mottakere."},
		"invitedIdentities": {"Invited identities", "Bruk bare eksplisitt inviterte identities som mottakere."},
		"hybrid":            {"Hybrid", "Bruk både kontekstmedlemmer og eksplisitt inviterte identities."},
	}
	chatStatusLabels = map[string]string{"pending": "Pending", "accepted": "Accepted", "declined": "Declined", "revoked": "Revoked"}
)

func chatFormats() []any {
	return []any{
		map[string]any{"id": "plain", "label": "Plain text", "contentType": "text/plain", "description": "Vanlig tekst uten formattering."},
		map[string]any{"id": "markdown", "label": "Markdown", "contentType": "text/markdown", "description": "Markdown for overskrifter, lister og lenker."},
	}
}

type chatPerson struct {
	uuid, displayName string
	descriptor        *interop.IdentityPublicKeyDescriptor
}

func (p *chatPerson) matches(requester *Identity) bool {
	if p.descriptor == nil || requester == nil || requester.UUID != p.uuid {
		return false
	}
	key, err := base64.StdEncoding.DecodeString(requester.PublicSecureKey)
	return err == nil && string(key) == string(p.descriptor.PublicKey)
}

func (p *chatPerson) publicJSON() map[string]any {
	out := map[string]any{"uuid": p.uuid, "displayName": p.displayName}
	if p.descriptor != nil {
		out["publicSecureKey"] = base64.StdEncoding.EncodeToString(p.descriptor.PublicKey)
	}
	return out
}

func chatPersonFromIdentity(identity *Identity) *chatPerson {
	descriptor, ok := DescriptorFor(identity)
	person := &chatPerson{uuid: identity.UUID, displayName: identity.DisplayName}
	if ok {
		person.descriptor = &descriptor
	}
	return person
}

func chatPersonFromValue(value any) *chatPerson {
	obj, ok := ObjectValue(value)
	if !ok {
		return nil
	}
	if _, hasKey := obj["publicKey"].(string); hasKey {
		if _, hasAlg := obj["algorithm"]; hasAlg {
			var descriptor interop.IdentityPublicKeyDescriptor
			if !decodeObject(obj, &descriptor) {
				return nil
			}
			name := descriptor.UUID
			if descriptor.DisplayName != nil {
				name = *descriptor.DisplayName
			}
			return &chatPerson{uuid: descriptor.UUID, displayName: name, descriptor: &descriptor}
		}
	}
	data, err := json.Marshal(obj)
	if err != nil {
		return nil
	}
	var identity Identity
	if identity.UnmarshalJSON(data) != nil || identity.UUID == "" {
		return nil
	}
	return chatPersonFromIdentity(&identity)
}

type chatInvitation struct {
	person               *chatPerson
	status, source       string
	createdAt, updatedAt string
	artifact             *interop.ChatInvitationArtifact
	acceptance           *interop.ChatInvitationAcceptance
}

// ChatCellOptions configures ChatCell. Sign defaults to the owner identity's vault.
type ChatCellOptions struct {
	Sign          func([]byte) ([]byte, error)
	Topic         string
	MessagesLimit int
	Clock         func() time.Time
	Random        func(int) []byte
	NewUUID       func() string
}

type ChatCell struct {
	*GeneralCell
	opts         ChatCellOptions
	stateMu      sync.Mutex
	ownerPerson  *chatPerson
	audienceMode string
	messages     []map[string]any
	participants map[string]map[string]any
	invitations  map[string]*chatInvitation
	consumed     map[string]map[string]any
	drafts       map[string]map[string]string
}

func NewChatCell(owner *Identity, opts ChatCellOptions) *ChatCell {
	if opts.Topic == "" {
		opts.Topic = "chat"
	}
	if opts.MessagesLimit == 0 {
		opts.MessagesLimit = 200
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.Random == nil {
		opts.Random = interop.MakeNonce
	}
	if opts.NewUUID == nil {
		opts.NewUUID = func() string { return strings.ToUpper(NewUUID()) }
	}
	if opts.Sign == nil && owner != nil {
		opts.Sign = func(m []byte) ([]byte, error) { return owner.Sign(context.Background(), m) }
	}
	cell := &ChatCell{
		GeneralCell:  NewGeneralCell(owner, "Chat"),
		opts:         opts,
		audienceMode: "hybrid",
		participants: map[string]map[string]any{},
		invitations:  map[string]*chatInvitation{},
		consumed:     map[string]map[string]any{},
		drafts:       map[string]map[string]string{},
	}
	if owner != nil {
		cell.ownerPerson = chatPersonFromIdentity(owner)
	}
	for _, key := range chatReadKeys {
		cell.agreementTemplate.AddGrant("r---", key)
		cell.AddGetHandler(key, cell.read)
	}
	for _, key := range chatWriteKeys {
		cell.agreementTemplate.AddGrant("rw--", key)
		cell.AddSetHandler(key, cell.write)
	}
	return cell
}

// ---- access --------------------------------------------------------------------

func (c *ChatCell) memberFor(requester *Identity) *chatPerson {
	for _, record := range c.invitations {
		if record.status == "accepted" && record.acceptance != nil && record.person.matches(requester) {
			return record.person
		}
	}
	return nil
}

// admitsDirectly is true for open keys and for accepted members on member
// keys; everything else goes through GeneralCell's owner proof.
func (c *ChatCell) admitsDirectly(keypath string, requester *Identity) bool {
	if chatOpenKeys[keypath] {
		return true
	}
	if !chatMemberKeys[keypath] {
		return false
	}
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.memberFor(requester) != nil
}

func (c *ChatCell) Get(ctx context.Context, keypath string, requester *Identity) (any, error) {
	if c.admitsDirectly(keypath, requester) {
		return c.read(ctx, keypath, requester)
	}
	return c.GeneralCell.Get(ctx, keypath, requester)
}

func (c *ChatCell) Set(ctx context.Context, keypath string, value any, requester *Identity) (any, error) {
	if c.admitsDirectly(keypath, requester) {
		return c.write(ctx, keypath, value, requester)
	}
	return c.GeneralCell.Set(ctx, keypath, value, requester)
}

func (c *ChatCell) isOwnerPerson(p *chatPerson) bool {
	return c.ownerPerson != nil && p.uuid == c.ownerPerson.uuid
}

// ---- dispatch ------------------------------------------------------------------

func (c *ChatCell) now() string { return interop.ChatTimestamp(c.opts.Clock()) }

func (c *ChatCell) read(ctx context.Context, keypath string, requester *Identity) (any, error) {
	_ = ctx
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	switch keypath {
	case "state", "status", "messages", "participants":
		if update := c.observe(requester, keypath, false); update != nil {
			c.publish("Chat participant", "chat.participant", extString(update["id"]), update)
			c.publishStatus()
		}
	}
	switch keypath {
	case "status":
		return c.statusSummary(), nil
	case "state":
		return c.statePayload(requester), nil
	case "messages":
		return c.messageList(), nil
	case "participants", "members":
		return c.participantRows(), nil
	case "audience":
		return c.audiencePayload(), nil
	case "audience.mode":
		return c.audienceMode, nil
	case "audience.inheritedRecipients":
		return c.recipients(c.contextPeople(), "context"), nil
	case "audience.invitedRecipients":
		return c.recipients(c.invitedPeople(), "invited"), nil
	case "audience.resolvedRecipients":
		return c.resolvedRecipients(), nil
	case "audience.invitations":
		return c.invitationRows(), nil
	case "audience.invitationArtifacts":
		out := []any{}
		for _, record := range c.sortedInvitations() {
			if record.artifact != nil && c.artifactState(record) == "issued" {
				out = append(out, toWireMap(record.artifact))
			}
		}
		return out, nil
	case "compose.body":
		return c.draft(requester)["body"], nil
	case "compose.contentType":
		return c.draft(requester)["contentType"], nil
	case "compose.state":
		return c.composerPayload(requester), nil
	case "compose.availableFormats":
		return chatFormats(), nil
	case "crypto", "crypto.state":
		return c.cryptoPayload(), nil
	}
	return nil, nil
}

func (c *ChatCell) write(ctx context.Context, keypath string, value any, requester *Identity) (any, error) {
	_ = ctx
	value = NormalizeJSON(value)
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	switch keypath {
	case "audience.mode":
		mode := extString(value)
		if _, ok := chatAudienceMod[mode]; !ok {
			return "error: unsupported audience mode", nil
		}
		c.audienceMode = mode
		return c.audiencePayload(), nil
	case "audience.inviteIdentities":
		return c.inviteIdentities(value), nil
	case "audience.generateInvitationArtifacts":
		return c.generateArtifacts(value), nil
	case "audience.generateInvitationAcceptance":
		return c.generateAcceptance(value, requester), nil
	case "audience.acceptInvitationArtifact":
		return c.acceptArtifact(value), nil
	case "audience.inspectInvitationArtifact":
		artifact := chatArtifactFrom(value)
		if artifact == nil {
			return "error: invalid invitation artifact payload", nil
		}
		return c.inspect(artifact), nil
	case "audience.acceptInvites":
		return c.updateStatuses(value, "accepted"), nil
	case "audience.declineInvites":
		return c.updateStatuses(value, "declined"), nil
	case "audience.revokeInvites":
		return c.updateStatuses(value, "revoked"), nil
	case "audience.clearInvites":
		c.invitations = map[string]*chatInvitation{}
		c.consumed = map[string]map[string]any{}
		return c.audiencePayload(), nil
	case "compose.body":
		c.draft(requester)["body"] = extString(value)
		return c.composerPayload(requester), nil
	case "compose.contentType":
		c.draft(requester)["contentType"] = normalizedChatContentType(extString(value))
		return c.composerPayload(requester), nil
	case "sendMessage", "addMessage":
		return c.sendMessage(value, requester), nil
	case "sendComposedMessage":
		if !isTriggerPayload(value) {
			return "error: invalid trigger payload", nil
		}
		draft := c.draft(requester)
		body := strings.TrimSpace(draft["body"])
		if body == "" {
			return "error: empty composer body", nil
		}
		draft["body"] = ""
		return c.store(body, draft["contentType"], c.opts.Topic, requester), nil
	case "clearComposer":
		if !isTriggerPayload(value) {
			return "error: invalid trigger payload", nil
		}
		c.draft(requester)["body"] = ""
		return map[string]any{"body": "", "contentType": c.draft(requester)["contentType"]}, nil
	}
	return nil, nil
}

func isTriggerPayload(value any) bool {
	switch value.(type) {
	case nil, bool, map[string]any:
		return true
	}
	return false
}

func normalizedChatContentType(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch value {
	case "", "plain", "plaintext", "text", "text/plain":
		return "text/plain"
	case "markdown", "md", "text/markdown":
		return "text/markdown"
	}
	if strings.Contains(value, "/") {
		return value
	}
	return "text/plain"
}

func chatInitials(name string) string {
	words := strings.FieldsFunc(name, func(r rune) bool { return unicode.IsSpace(r) || r == '-' })
	if len(words) > 2 {
		words = words[:2]
	}
	out := ""
	for _, word := range words {
		for _, r := range word {
			if unicode.IsLetter(r) || unicode.IsNumber(r) {
				out += strings.ToUpper(string(r))
				break
			}
		}
	}
	return out
}

// ---- messages ------------------------------------------------------------------

func (c *ChatCell) personFor(requester *Identity) *chatPerson {
	if requester != nil && c.ownerPerson != nil && requester.UUID == c.ownerPerson.uuid {
		return c.ownerPerson
	}
	if member := c.memberFor(requester); member != nil {
		return member
	}
	if requester == nil {
		return &chatPerson{uuid: "anonymous", displayName: "Ukjent"}
	}
	return &chatPerson{uuid: requester.UUID, displayName: requester.DisplayName}
}

func (c *ChatCell) sendMessage(value any, requester *Identity) any {
	body, contentType, topic := "", c.draft(requester)["contentType"], c.opts.Topic
	if s, ok := value.(string); ok {
		body = s
	} else if obj, ok := ObjectValue(value); ok {
		body = firstNonEmpty(extString(obj["content"]), extString(obj["body"]), extString(obj["text"]))
		if ct := firstNonEmpty(extString(obj["contentType"]), extString(obj["format"])); ct != "" {
			contentType = ct
		}
		if t := extString(obj["topic"]); t != "" {
			topic = t
		}
	}
	body = strings.TrimSpace(body)
	if body == "" {
		return "error: invalid chat payload"
	}
	return c.store(body, normalizedChatContentType(contentType), topic, requester)
}

func (c *ChatCell) store(body, contentType, topic string, requester *Identity) map[string]any {
	person := c.personFor(requester)
	name := person.displayName
	if requester != nil && requester.DisplayName != "" {
		name = requester.DisplayName
	}
	preview := body
	if runes := []rune(body); len(runes) > 140 {
		preview = string(runes[:139]) + "…"
	}
	label := "Plain text"
	if contentType == "text/markdown" {
		label = "Markdown"
	}
	message := map[string]any{
		"id": c.opts.NewUUID(), "owner": person.publicJSON(), "ownerUUID": person.uuid, "ownerDisplayName": name,
		"ownerInitials": chatInitials(name), "content": body, "contentPreview": preview, "contentType": contentType,
		"formatLabel": label, "isMarkdown": contentType == "text/markdown", "topic": topic, "createdAt": c.now(),
		"cryptoState": "plaintextOnly", "encryptedCompanionAvailable": false,
	}
	c.messages = append(c.messages, message)
	if over := len(c.messages) - c.opts.MessagesLimit; over > 0 {
		c.messages = c.messages[over:]
	}
	participant := c.observe(requester, "sentMessage", true)
	c.publish("Chat message", "chat.message", message["id"].(string), copyMap(message))
	if participant != nil {
		c.publish("Chat participant", "chat.participant", extString(participant["id"]), participant)
	}
	c.publishStatus()
	return map[string]any{"status": "sent", "message": copyMap(message), "messageCount": len(c.messages), "participantCount": len(c.participants)}
}

func copyMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (c *ChatCell) observe(requester *Identity, action string, increment bool) map[string]any {
	if requester == nil {
		return nil
	}
	person := c.personFor(requester)
	name := firstNonEmpty(requester.DisplayName, person.displayName)
	now := c.now()
	record, existing := c.participants[person.uuid]
	if !existing {
		record = map[string]any{"id": person.uuid, "displayName": name, "joinedAt": now, "messageCount": 0}
	}
	renamed := record["displayName"] != name
	record["displayName"], record["lastSeenAt"], record["lastAction"] = name, now, action
	record["presence"] = "present"
	if increment {
		record["presence"] = "messaging"
		record["messageCount"] = record["messageCount"].(int) + 1
	}
	record["initials"] = chatInitials(name)
	c.participants[person.uuid] = record
	if !existing || increment || renamed {
		return copyMap(record)
	}
	return nil
}

func (c *ChatCell) publish(title, topic, id string, content map[string]any) {
	element := NewFlowElement(title, content)
	if id != "" {
		element.ID = id
	}
	element.Origin = c.uuid
	element.Properties = &FlowProperties{Type: "event", ContentType: ContentObject}
	c.PushFlowElement(element, topic)
}

func (c *ChatCell) publishStatus() { c.publish("Chat status", "chat.status", "", c.statusPayload()) }

func (c *ChatCell) draft(requester *Identity) map[string]string {
	key := "anonymous"
	if requester != nil {
		key = requester.UUID
	}
	if _, ok := c.drafts[key]; !ok {
		c.drafts[key] = map[string]string{"body": "", "contentType": "text/plain"}
	}
	return c.drafts[key]
}

// ---- invitations ---------------------------------------------------------------

func (c *ChatCell) peopleFrom(value any) []*chatPerson {
	items, ok := value.([]any)
	if !ok {
		items = []any{value}
	}
	out := []*chatPerson{}
	for _, item := range items {
		if s, isString := item.(string); isString {
			if record, ok := c.invitations[s]; ok {
				out = append(out, record.person)
			}
			continue
		}
		if person := chatPersonFromValue(item); person != nil {
			out = append(out, person)
		}
	}
	return out
}

func (c *ChatCell) inviteIdentities(value any) map[string]any {
	now := c.now()
	for _, person := range c.peopleFrom(value) {
		if c.isOwnerPerson(person) || person.descriptor == nil {
			continue
		}
		if existing, ok := c.invitations[person.uuid]; ok {
			existing.person = person
			if existing.status != "accepted" {
				existing.status = "pending"
			}
			existing.source, existing.updatedAt, existing.acceptance = "inviteIdentities", now, nil
			continue
		}
		c.invitations[person.uuid] = &chatInvitation{person: person, status: "pending", source: "inviteIdentities", createdAt: now, updatedAt: now}
	}
	return c.audiencePayload()
}

// targets returns nil for an invalid payload, the empty-but-non-nil "all" set otherwise expanded.
func (c *ChatCell) targets(value any, allowTrue bool) (map[string]bool, bool) {
	all := map[string]bool{}
	for id := range c.invitations {
		all[id] = true
	}
	if value == nil || (allowTrue && value == true) {
		return all, true
	}
	items, ok := value.([]any)
	if !ok {
		return nil, false
	}
	if len(items) == 0 {
		return all, true
	}
	out := map[string]bool{}
	for _, item := range items {
		if s, isString := item.(string); isString && s != "" {
			out[s] = true
		} else if person := chatPersonFromValue(item); person != nil {
			out[person.uuid] = true
		} else {
			return nil, false
		}
	}
	return out, false
}

func (c *ChatCell) generateArtifacts(value any) any {
	targets, isAll := c.targets(value, true)
	if targets == nil {
		return "error: invalid invitation target payload"
	}
	eligible := map[string]bool{}
	for id, record := range c.invitations {
		if record.status != "revoked" {
			eligible[id] = true
		}
	}
	if !isAll {
		for id := range targets {
			if !eligible[id] {
				return "error: invitation targets must all reference eligible invitation records"
			}
		}
	}
	if c.ownerPerson == nil || c.ownerPerson.descriptor == nil || c.opts.Sign == nil {
		return "error: owner has no signing key"
	}
	ids := []string{}
	for id := range targets {
		if eligible[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	out := []any{}
	for _, id := range ids {
		record := c.invitations[id]
		if record.artifact != nil && c.artifactState(record) == "issued" {
			out = append(out, toWireMap(record.artifact))
			continue
		}
		if record.status == "declined" {
			record.status = "pending"
		}
		prior := record.artifact
		artifact, err := interop.BuildChatInvitation(*c.ownerPerson.descriptor, *record.person.descriptor, c.opts.Sign, interop.ChatInvitationInput{
			ChatCellUUID: c.uuid, Topic: c.opts.Topic, AudienceMode: c.audienceMode, PersistenceMode: "draftCacheOnly",
			InvitationID: c.opts.NewUUID(), Now: c.opts.Clock(), Nonce: c.opts.Random(interop.ChatInvitationNonceSize),
		})
		if err != nil {
			return "error: " + err.Error()
		}
		if prior != nil {
			delete(c.consumed, prior.InvitationID)
		}
		record.artifact, record.acceptance, record.updatedAt = artifact, nil, artifact.CreatedAt
		out = append(out, toWireMap(artifact))
	}
	return out
}

func (c *ChatCell) generateAcceptance(value any, requester *Identity) any {
	artifact := chatArtifactFrom(value)
	if artifact == nil {
		return "error: invalid invitation artifact payload"
	}
	if requester == nil || requester.UUID != artifact.InvitedIdentity.UUID || c.ownerPerson == nil || c.ownerPerson.descriptor == nil {
		return "error: requester does not match invited identity"
	}
	acceptance, err := interop.BuildChatAcceptance(artifact, *c.ownerPerson.descriptor, c.opts.Sign, c.opts.NewUUID(), c.opts.Clock(), c.opts.Random(interop.ChatInvitationNonceSize))
	if err != nil {
		return "error: " + interop.VerdictOf(err)
	}
	return toWireMap(acceptance)
}

func (c *ChatCell) acceptArtifact(value any) any {
	obj, _ := ObjectValue(value)
	artifactValue := value
	if obj != nil && obj["artifact"] != nil {
		artifactValue = obj["artifact"]
	}
	artifact := chatArtifactFrom(artifactValue)
	var acceptance *interop.ChatInvitationAcceptance
	if obj != nil {
		acceptance = chatAcceptanceFrom(obj["acceptance"])
	}
	if artifact == nil || acceptance == nil {
		return "error: invalid invitation artifact acceptance payload"
	}
	now := c.opts.Clock()
	cellUUID := c.uuid
	options := interop.ChatOptions{ExpectedChatCellUUID: &cellUUID}
	if c.ownerPerson != nil {
		owner := c.ownerPerson.uuid
		options.ExpectedInviterUUID = &owner
	}
	if err := interop.VerifyChatInvitation(artifact, now, options); err != nil {
		return "error: " + interop.VerdictOf(err)
	}
	if err := interop.VerifyChatAcceptance(acceptance, artifact, now, &cellUUID); err != nil {
		return "error: " + interop.VerdictOf(err)
	}
	record, ok := c.invitations[artifact.InvitedIdentity.UUID]
	if !ok {
		return "error: invitation record not found for artifact"
	}
	if record.artifact == nil {
		return "error: invitation artifact is no longer active"
	}
	currentHash, _ := interop.InvitationHash(record.artifact)
	presentedHash, _ := interop.InvitationHash(artifact)
	if record.artifact.InvitationID != artifact.InvitationID || string(currentHash) != string(presentedHash) {
		return "error: invitation artifact has been superseded"
	}
	switch record.status {
	case "revoked":
		return "error: invitation artifact has been revoked"
	case "declined":
		return "error: invitation artifact has been declined"
	}
	idempotent := false
	if existing, ok := c.consumed[artifact.InvitationID]; ok {
		if existing["acceptanceID"] != acceptance.AcceptanceID {
			return "error: invitation artifact already consumed"
		}
		idempotent = true
	} else {
		for _, row := range c.consumed {
			if row["acceptanceID"] == acceptance.AcceptanceID {
				return "error: acceptance proof already consumed"
			}
		}
	}
	stamp := c.now()
	record.status, record.source, record.updatedAt, record.artifact, record.acceptance = "accepted", "artifactAccepted", stamp, artifact, acceptance
	c.consumed[artifact.InvitationID] = map[string]any{"invitationID": artifact.InvitationID, "acceptanceID": acceptance.AcceptanceID, "inviteeIdentityUUID": artifact.InvitedIdentity.UUID, "consumedAt": stamp}
	return map[string]any{
		"status": "accepted", "idempotent": idempotent, "invitationID": artifact.InvitationID,
		"acceptanceID": acceptance.AcceptanceID, "audience": c.audiencePayload(), "invitation": c.invitationRow(record),
	}
}

func (c *ChatCell) updateStatuses(value any, status string) any {
	targets, _ := c.targets(value, false)
	if targets == nil {
		return "error: invalid invitation target payload"
	}
	for id := range targets {
		if _, ok := c.invitations[id]; !ok {
			return "error: invitation targets must all reference known invitation records"
		}
	}
	now := c.now()
	for id := range targets {
		c.invitations[id].status, c.invitations[id].updatedAt = status, now
	}
	return c.audiencePayload()
}

func (c *ChatCell) artifactState(record *chatInvitation) string {
	switch {
	case record.status == "revoked" || record.status == "declined":
		return record.status
	case record.artifact == nil:
		return "notIssued"
	case record.acceptance != nil:
		return "consumed"
	}
	if interop.VerifyChatInvitation(record.artifact, c.opts.Clock(), interop.ChatOptions{}) != nil {
		return "expired"
	}
	return "issued"
}

func (c *ChatCell) inspect(artifact *interop.ChatInvitationArtifact) map[string]any {
	state := "notFound"
	if record, ok := c.invitations[artifact.InvitedIdentity.UUID]; ok && record.artifact != nil {
		if record.artifact.InvitationID != artifact.InvitationID {
			state = "superseded"
		} else {
			state = c.artifactState(record)
		}
	}
	return map[string]any{"invitationID": artifact.InvitationID, "state": state, "acceptanceAllowed": state == "issued", "chatCellUUID": artifact.ChatCellUUID}
}

func chatArtifactFrom(value any) *interop.ChatInvitationArtifact {
	if obj, ok := ObjectValue(value); ok {
		if _, has := obj["invitationID"]; !has && obj["artifact"] != nil {
			value = obj["artifact"]
		}
	}
	var artifact interop.ChatInvitationArtifact
	if decodeTransport(value, "artifact", &artifact) {
		return &artifact
	}
	return nil
}

func chatAcceptanceFrom(value any) *interop.ChatInvitationAcceptance {
	var acceptance interop.ChatInvitationAcceptance
	if value != nil && decodeTransport(value, "acceptance", &acceptance) {
		return &acceptance
	}
	return nil
}

// ---- presentation --------------------------------------------------------------

func (c *ChatCell) sortedInvitations() []*chatInvitation {
	out := []*chatInvitation{}
	for _, record := range c.invitations {
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].status != out[j].status {
			return out[i].status < out[j].status
		}
		return strings.ToLower(out[i].person.displayName) < strings.ToLower(out[j].person.displayName)
	})
	return out
}

func orNil(s string, ok bool) any {
	if !ok {
		return nil
	}
	return s
}

func (c *ChatCell) invitationRow(record *chatInvitation) map[string]any {
	state := c.artifactState(record)
	a, b := record.artifact, record.acceptance
	row := map[string]any{
		"identityUUID": record.person.uuid, "displayName": record.person.displayName, "status": record.status,
		"statusLabel": chatStatusLabels[record.status], "source": record.source, "createdAt": record.createdAt,
		"updatedAt": record.updatedAt, "isResolvedRecipient": record.status == "accepted", "hasKeyAgreementKey": false,
		"hasSigningKey": record.person.descriptor != nil, "artifactAvailable": a != nil, "artifactState": state,
		"artifactAcceptanceAllowed": state == "issued", "proofBackedAcceptance": b != nil, "acceptanceAvailable": b != nil,
		"artifactInvitationID": nil, "artifactIssuedAt": nil, "artifactExpiresAt": nil,
		"artifactConsumedAt": nil, "acceptanceID": nil, "acceptanceCreatedAt": nil,
	}
	if a != nil {
		row["artifactInvitationID"], row["artifactIssuedAt"], row["artifactExpiresAt"] = a.InvitationID, a.CreatedAt, a.ExpiresAt
	}
	if b != nil {
		row["artifactConsumedAt"], row["acceptanceID"], row["acceptanceCreatedAt"] = b.CreatedAt, b.AcceptanceID, b.CreatedAt
	}
	return row
}

func (c *ChatCell) invitationRows() []any {
	out := []any{}
	for _, record := range c.sortedInvitations() {
		out = append(out, c.invitationRow(record))
	}
	return out
}

func (c *ChatCell) contextPeople() []*chatPerson {
	people := []*chatPerson{}
	if c.ownerPerson != nil {
		people = append(people, c.ownerPerson)
	}
	rows := c.participantRows()
	for _, item := range rows {
		row := item.(map[string]any)
		id := extString(row["id"])
		if c.ownerPerson != nil && id == c.ownerPerson.uuid {
			continue
		}
		if record, ok := c.invitations[id]; ok {
			people = append(people, record.person)
		} else {
			people = append(people, &chatPerson{uuid: id, displayName: extString(row["displayName"])})
		}
	}
	return people
}

func (c *ChatCell) invitedPeople() []*chatPerson {
	people := []*chatPerson{}
	if c.ownerPerson != nil {
		people = append(people, c.ownerPerson)
	}
	for _, record := range c.sortedInvitations() {
		if record.status == "accepted" {
			people = append(people, record.person)
		}
	}
	return people
}

func (c *ChatCell) recipient(p *chatPerson, source string) map[string]any {
	if c.isOwnerPerson(p) {
		source = "owner"
	}
	return map[string]any{"identityUUID": p.uuid, "displayName": p.displayName, "source": source, "isOwner": c.isOwnerPerson(p), "hasKeyAgreementKey": false, "hasSigningKey": p.descriptor != nil}
}

func (c *ChatCell) recipients(people []*chatPerson, source string) []any {
	out := []any{}
	for _, p := range people {
		out = append(out, c.recipient(p, source))
	}
	return out
}

func (c *ChatCell) resolvedPeople() []*chatPerson {
	var chosen []*chatPerson
	switch c.audienceMode {
	case "contextMembers":
		chosen = c.contextPeople()
	case "invitedIdentities":
		chosen = c.invitedPeople()
	default:
		chosen = append(c.contextPeople(), c.invitedPeople()...)
	}
	seen := map[string]bool{}
	out := []*chatPerson{}
	for _, p := range chosen {
		if !seen[p.uuid] {
			seen[p.uuid] = true
			out = append(out, p)
		}
	}
	return out
}

func (c *ChatCell) resolvedRecipients() []any {
	context, invited := map[string]bool{}, map[string]bool{}
	for _, p := range c.contextPeople() {
		context[p.uuid] = true
	}
	for _, p := range c.invitedPeople() {
		invited[p.uuid] = true
	}
	out := []any{}
	for _, p := range c.resolvedPeople() {
		source := "context"
		switch {
		case context[p.uuid] && invited[p.uuid]:
			source = "hybrid"
		case invited[p.uuid]:
			source = "invited"
		}
		out = append(out, c.recipient(p, source))
	}
	return out
}

func (c *ChatCell) audiencePayload() map[string]any {
	count := func(status string) int {
		n := 0
		for _, record := range c.invitations {
			if record.status == status {
				n++
			}
		}
		return n
	}
	mode := chatAudienceMod[c.audienceMode]
	return map[string]any{
		"mode": c.audienceMode, "modeLabel": mode[0], "summary": mode[1],
		"inheritedRecipients": c.recipients(c.contextPeople(), "context"),
		"invitedRecipients":   c.recipients(c.invitedPeople(), "invited"),
		"resolvedRecipients":  c.resolvedRecipients(), "invitations": c.invitationRows(),
		"invitationLedgerCount": len(c.consumed), "inheritedCount": max(len(c.contextPeople())-1, 0),
		"invitedCount": count("accepted"), "resolvedCount": len(c.resolvedPeople()), "invitationCount": len(c.invitations),
		"pendingInviteCount": count("pending"), "acceptedInviteCount": count("accepted"),
		"declinedInviteCount": count("declined"), "revokedInviteCount": count("revoked"),
		"supportsContextMembers": true, "supportsExplicitInvites": true, "defaultForEmbeddedComponent": "hybrid",
	}
}

func (c *ChatCell) messageList() []any {
	out := []any{}
	for _, m := range c.messages {
		out = append(out, copyMap(m))
	}
	return out
}

func (c *ChatCell) participantRows() []any {
	rows := []map[string]any{}
	for _, row := range c.participants {
		rows = append(rows, copyMap(row))
	}
	sort.Slice(rows, func(i, j int) bool {
		return strings.ToLower(extString(rows[i]["displayName"])) < strings.ToLower(extString(rows[j]["displayName"]))
	})
	out := []any{}
	for _, row := range rows {
		out = append(out, row)
	}
	return out
}

func (c *ChatCell) statusSummary() string {
	return fmt.Sprintf("participants: %d · messages: %d · topic: %s", len(c.participants), len(c.messages), c.opts.Topic)
}

func (c *ChatCell) statusPayload() map[string]any {
	out := map[string]any{
		"summary": c.statusSummary(), "topic": c.opts.Topic, "messageCount": len(c.messages),
		"participantCount": len(c.participants), "messagesLimit": c.opts.MessagesLimit, "running": false,
		"latestMessageAt": nil, "latestMessagePreview": nil, "latestMessageContentType": nil,
	}
	if n := len(c.messages); n > 0 {
		latest := c.messages[n-1]
		out["latestMessageAt"], out["latestMessagePreview"], out["latestMessageContentType"] = latest["createdAt"], latest["contentPreview"], latest["contentType"]
	}
	return out
}

func (c *ChatCell) composerPayload(requester *Identity) map[string]any {
	draft := c.draft(requester)
	return map[string]any{"body": draft["body"], "contentType": draft["contentType"], "canSend": strings.TrimSpace(draft["body"]) != "", "availableFormats": chatFormats()}
}

func (c *ChatCell) cryptoPayload() map[string]any {
	return map[string]any{
		"state": "plaintextOnly", "supported": false,
		"summary":          "Denne noden sender meldinger i klartekst over den autentiserte broen. Krypterte konvolutter er ikke portet.",
		"preferredSuiteID": interop.ChatDefaultSuiteID, "persistenceMode": "draftCacheOnly",
	}
}

func (c *ChatCell) statePayload(requester *Identity) map[string]any {
	return map[string]any{
		"topic": c.opts.Topic, "status": c.statusSummary(), "statusDetail": c.statusPayload(),
		"messages": c.messageList(), "participants": c.participantRows(), "members": c.participantRows(),
		"audience": c.audiencePayload(), "messageCount": len(c.messages), "participantCount": len(c.participants),
		"messagesLimit": c.opts.MessagesLimit, "running": false, "composer": c.composerPayload(requester),
		"crypto": c.cryptoPayload(), "availableFormats": chatFormats(),
	}
}
