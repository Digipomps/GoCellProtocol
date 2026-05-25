// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

func nowMillis() int64 {
	return time.Now().UnixMilli()
}

type VaultNoteRecord struct {
	ID               string   `json:"id"`
	Slug             string   `json:"slug,omitempty"`
	Title            string   `json:"title"`
	Content          string   `json:"content"`
	Tags             []string `json:"tags"`
	CreatedAtEpochMs int64    `json:"createdAtEpochMs"`
	UpdatedAtEpochMs int64    `json:"updatedAtEpochMs"`
}

type VaultCell struct {
	*GeneralCell
	notes        map[string]VaultNoteRecord
	links        []map[string]any
	operations   []map[string]any
	stateVersion int
}

func NewVaultCell(owner *Identity) *VaultCell {
	cell := &VaultCell{
		GeneralCell: NewGeneralCell(owner, "Vault"),
		notes:       map[string]VaultNoteRecord{},
	}
	cell.agreementTemplate.AddGrant("rw--", "vault")
	cell.AddGetHandler("vault.state", cell.getState)
	for _, key := range []string{
		"vault.note.create",
		"vault.note.update",
		"vault.note.get",
		"vault.note.list",
		"vault.link.add",
		"vault.links.forward",
		"vault.links.backlinks",
	} {
		cell.AddSetHandler(key, cell.setVault)
	}
	return cell
}

func (c *VaultCell) getState(context.Context, string, *Identity) (any, error) {
	return c.statePayload(), nil
}

func (c *VaultCell) setVault(ctx context.Context, keypath string, value any, requester *Identity) (any, error) {
	_ = ctx
	payload, ok := ObjectValue(value)
	if !ok {
		return c.vaultError(keypath, "invalid_payload", "Vault payload must be an object", nil), nil
	}
	switch keypath {
	case "vault.note.create":
		return c.createNote(payload, requester), nil
	case "vault.note.update":
		return c.updateNote(payload, requester), nil
	case "vault.note.get":
		return c.getNote(payload), nil
	case "vault.note.list":
		return c.listNotes(payload), nil
	case "vault.link.add":
		return c.addLink(payload, requester), nil
	case "vault.links.forward":
		return c.linksFor(payload, "fromNoteID", "toNoteID"), nil
	case "vault.links.backlinks":
		return c.linksFor(payload, "toNoteID", "fromNoteID"), nil
	default:
		return c.vaultError(keypath, "unknown_operation", keypath, nil), nil
	}
}

func (c *VaultCell) createNote(payload map[string]any, requester *Identity) map[string]any {
	title, _ := payload["title"].(string)
	content, contentOK := payload["content"].(string)
	if title == "" || !contentOK {
		return c.vaultError("vault.note.create", "field_errors", "title and content are required", map[string]any{"title": "required", "content": "required"})
	}
	id, _ := payload["id"].(string)
	if id == "" {
		id, _ = payload["slug"].(string)
	}
	if id == "" {
		id = NewUUID()
	}
	slug, _ := payload["slug"].(string)
	tags := stringList(payload["tags"])
	now := nowMillis()
	note := VaultNoteRecord{ID: id, Slug: slug, Title: title, Content: content, Tags: tags, CreatedAtEpochMs: now, UpdatedAtEpochMs: now}
	c.notes[note.ID] = note
	c.mutate("note.create", "note", note.ID, requester)
	return map[string]any{"status": "ok", "note": note}
}

func (c *VaultCell) updateNote(payload map[string]any, requester *Identity) map[string]any {
	id, _ := payload["id"].(string)
	note, ok := c.notes[id]
	if id == "" || !ok {
		return c.vaultError("vault.note.update", "not_found", "note not found", nil)
	}
	if title, ok := payload["title"].(string); ok {
		note.Title = title
	}
	if content, ok := payload["content"].(string); ok {
		note.Content = content
	}
	if _, ok := payload["tags"]; ok {
		note.Tags = stringList(payload["tags"])
	}
	note.UpdatedAtEpochMs = nowMillis()
	c.notes[id] = note
	c.mutate("note.update", "note", note.ID, requester)
	return map[string]any{"status": "ok", "note": note}
}

func (c *VaultCell) getNote(payload map[string]any) map[string]any {
	id, _ := payload["id"].(string)
	note, ok := c.notes[id]
	if !ok {
		return c.vaultError("vault.note.get", "not_found", "note not found", nil)
	}
	return map[string]any{"status": "ok", "note": note}
}

func (c *VaultCell) listNotes(payload map[string]any) map[string]any {
	notes := make([]VaultNoteRecord, 0, len(c.notes))
	for _, note := range c.notes {
		notes = append(notes, note)
	}
	ids := stringList(payload["ids"])
	if len(ids) > 0 {
		wanted := map[string]struct{}{}
		for _, id := range ids {
			wanted[id] = struct{}{}
		}
		filtered := notes[:0]
		for _, note := range notes {
			if _, ok := wanted[note.ID]; ok {
				filtered = append(filtered, note)
			}
		}
		notes = filtered
	}
	if text, ok := payload["text"].(string); ok && text != "" {
		needle := strings.ToLower(text)
		filtered := notes[:0]
		for _, note := range notes {
			if strings.Contains(strings.ToLower(note.Title), needle) || strings.Contains(strings.ToLower(note.Content), needle) {
				filtered = append(filtered, note)
			}
		}
		notes = filtered
	}
	tags := stringList(payload["tags"])
	if len(tags) > 0 {
		filtered := notes[:0]
		for _, note := range notes {
			if containsAll(note.Tags, tags) {
				filtered = append(filtered, note)
			}
		}
		notes = filtered
	}
	sortBy, _ := payload["sortBy"].(string)
	if sortBy == "" {
		sortBy = "id"
	}
	descending, _ := payload["descending"].(bool)
	sort.Slice(notes, func(i, j int) bool {
		less := vaultSortValue(notes[i], sortBy) < vaultSortValue(notes[j], sortBy)
		if descending {
			return !less
		}
		return less
	})
	offset := intNumber(payload["offset"], 0)
	limit := intNumber(payload["limit"], len(notes))
	if offset > len(notes) {
		offset = len(notes)
	}
	end := offset + limit
	if end > len(notes) {
		end = len(notes)
	}
	sliced := notes[offset:end]
	out := make([]any, len(sliced))
	for i, note := range sliced {
		out[i] = note
	}
	return map[string]any{"status": "ok", "notes": out, "count": len(out)}
}

func (c *VaultCell) addLink(payload map[string]any, requester *Identity) map[string]any {
	fromID, _ := payload["fromNoteID"].(string)
	if fromID == "" {
		fromID, _ = payload["from"].(string)
	}
	toID, _ := payload["toNoteID"].(string)
	if toID == "" {
		toID, _ = payload["to"].(string)
	}
	if fromID == "" || toID == "" {
		return c.vaultError("vault.link.add", "field_errors", "fromNoteID and toNoteID are required", nil)
	}
	relationship, _ := payload["relationship"].(string)
	if relationship == "" {
		relationship = "wiki"
	}
	link := map[string]any{"fromNoteID": fromID, "toNoteID": toID, "relationship": relationship, "createdAtEpochMs": nowMillis()}
	if !linkExists(c.links, fromID, toID, relationship) {
		c.links = append(c.links, link)
		c.mutate("link.add", "link", fromID+"->"+toID, requester)
	}
	return map[string]any{"status": "ok", "link": link}
}

func (c *VaultCell) linksFor(payload map[string]any, sourceKey, targetKey string) map[string]any {
	id, _ := payload["id"].(string)
	if id == "" {
		id, _ = payload["noteID"].(string)
	}
	if id == "" {
		id, _ = payload["note_id"].(string)
	}
	if id == "" {
		return c.vaultError("vault.links", "field_errors", "id is required", nil)
	}
	links := []any{}
	ids := []string{}
	for _, link := range c.links {
		if link[sourceKey] == id {
			links = append(links, link)
			if target, ok := link[targetKey].(string); ok {
				ids = append(ids, target)
			}
		}
	}
	return map[string]any{"status": "ok", "links": links, "ids": ids}
}

func (c *VaultCell) statePayload() map[string]any {
	notes := make([]VaultNoteRecord, 0, len(c.notes))
	for _, note := range c.notes {
		notes = append(notes, note)
	}
	sort.Slice(notes, func(i, j int) bool { return notes[i].ID < notes[j].ID })
	return map[string]any{
		"status":           "ready",
		"cell":             c.Name(),
		"schemaVersion":    "haven.vault.state.v1",
		"stateVersion":     c.stateVersion,
		"noteCount":        len(c.notes),
		"linkCount":        len(c.links),
		"note_count":       len(c.notes),
		"link_count":       len(c.links),
		"notes":            notes,
		"links":            c.links,
		"operations":       c.operations,
		"updatedAtEpochMs": nowMillis(),
	}
}

func (c *VaultCell) mutate(operation, recordKind, recordID string, requester *Identity) {
	_ = requester
	c.stateVersion++
	event := map[string]any{
		"schemaVersion":    "haven.vault.mutation.v1",
		"stateVersion":     c.stateVersion,
		"operation":        operation,
		"recordKind":       recordKind,
		"recordID":         recordID,
		"result":           "ok",
		"emittedAtEpochMs": nowMillis(),
	}
	c.operations = append(c.operations, event)
	flow := NewFlowElement("VaultMutationEvent", event)
	flow.Topic = "vault.mutation"
	flow.Origin = c.CellUUID()
	c.PushFlowElement(flow, flow.Topic)
}

func (c *VaultCell) vaultError(operation, code, message string, fieldErrors map[string]any) map[string]any {
	if fieldErrors == nil {
		fieldErrors = map[string]any{}
	}
	return map[string]any{"status": "error", "operation": operation, "code": code, "message": message, "field_errors": fieldErrors}
}

type GraphIndexCell struct {
	*GeneralCell
	nodes map[string]struct{}
	edges map[string]map[string]struct{}
}

func NewGraphIndexCell(owner *Identity) *GraphIndexCell {
	cell := &GraphIndexCell{GeneralCell: NewGeneralCell(owner, "GraphIndex"), nodes: map[string]struct{}{}, edges: map[string]map[string]struct{}{}}
	cell.agreementTemplate.AddGrant("rw--", "graph")
	cell.AddGetHandler("graph.state", cell.getGraphState)
	for _, key := range []string{"graph.reindex", "graph.outgoing", "graph.incoming", "graph.neighbors"} {
		cell.AddSetHandler(key, cell.setGraph)
	}
	return cell
}

func (c *GraphIndexCell) getGraphState(context.Context, string, *Identity) (any, error) {
	edges := []any{}
	for from, targets := range c.edges {
		for to := range targets {
			edges = append(edges, map[string]any{"from": from, "to": to})
		}
	}
	return map[string]any{"status": "ready", "nodeCount": len(c.nodes), "edgeCount": len(edges), "nodes": mapKeys(c.nodes), "edges": edges}, nil
}

func (c *GraphIndexCell) setGraph(ctx context.Context, keypath string, value any, requester *Identity) (any, error) {
	_ = ctx
	_ = requester
	payload, ok := ObjectValue(value)
	if !ok {
		return map[string]any{"status": "error", "message": "payload must be object"}, nil
	}
	if keypath == "graph.reindex" {
		return c.reindex(payload), nil
	}
	id := nodeID(payload)
	if id == "" {
		return map[string]any{"status": "error", "message": "id is required"}, nil
	}
	switch keypath {
	case "graph.outgoing":
		return map[string]any{"status": "ok", "ids": mapKeys(c.edges[id])}, nil
	case "graph.incoming":
		ids := []string{}
		for source, targets := range c.edges {
			if _, ok := targets[id]; ok {
				ids = append(ids, source)
			}
		}
		sort.Strings(ids)
		return map[string]any{"status": "ok", "ids": ids}, nil
	case "graph.neighbors":
		seen := map[string]struct{}{}
		for target := range c.edges[id] {
			seen[target] = struct{}{}
		}
		for source, targets := range c.edges {
			if _, ok := targets[id]; ok {
				seen[source] = struct{}{}
			}
		}
		return map[string]any{"status": "ok", "ids": mapKeys(seen)}, nil
	default:
		return map[string]any{"status": "error", "message": "unknown operation " + keypath}, nil
	}
}

var wikiLinkPattern = regexp.MustCompile(`\[\[([^\]]+)\]\]`)

func (c *GraphIndexCell) reindex(payload map[string]any) map[string]any {
	c.nodes = map[string]struct{}{}
	c.edges = map[string]map[string]struct{}{}
	notes, _ := ListValue(payload["notes"])
	for _, item := range notes {
		note, ok := ObjectValue(item)
		if !ok {
			continue
		}
		id, _ := note["id"].(string)
		if id == "" {
			continue
		}
		content, _ := note["content"].(string)
		c.nodes[id] = struct{}{}
		if c.edges[id] == nil {
			c.edges[id] = map[string]struct{}{}
		}
		for _, match := range wikiLinkPattern.FindAllStringSubmatch(content, -1) {
			target := match[1]
			c.edges[id][target] = struct{}{}
			c.nodes[target] = struct{}{}
		}
	}
	edgeCount := 0
	for _, targets := range c.edges {
		edgeCount += len(targets)
	}
	return map[string]any{"status": "ok", "nodeCount": len(c.nodes), "edgeCount": edgeCount}
}

var entityRoots = []string{"person", "purposes", "relations", "proofs", "signedAgreementEntity", "entityRepresentation", "agreements", "chronicle", "bindings", "identityLinks"}

type EntityAnchorCell struct {
	*GeneralCell
}

func NewEntityAnchorCell(owner *Identity) *EntityAnchorCell {
	cell := &EntityAnchorCell{GeneralCell: NewGeneralCell(owner, "EntityAnchor")}
	for _, root := range entityRoots {
		cell.storage[root] = map[string]any{}
		cell.agreementTemplate.AddGrant("rw--", root)
		cell.AddGetHandler(root, cell.getEntity)
		cell.AddSetHandler(root, cell.setEntity)
	}
	cell.storage["chronicle"] = []any{}
	for _, action := range []string{"identityLinks.approveEnrollment", "identityLinks.completeEnrollment", "identityLinks.revoke", "entity.batchPersist"} {
		cell.AddSetHandler(action, cell.setEntityAction)
	}
	return cell
}

func (c *EntityAnchorCell) getEntity(ctx context.Context, keypath string, requester *Identity) (any, error) {
	_ = ctx
	_ = requester
	if keypath == "identityLinks" || keypath == "identityLinks.state" {
		records, _ := GetKeyPath(c.storage, "identityLinks.records")
		used, _ := GetKeyPath(c.storage, "identityLinks.usedApprovalJTIs")
		return map[string]any{"status": "ready", "records": records, "usedApprovalJTIs": used, "summary": "EntityAnchor identityLinks er klar for approveEnrollment, completeEnrollment og revoke."}, nil
	}
	return GetKeyPath(c.storage, keypath)
}

func (c *EntityAnchorCell) setEntity(ctx context.Context, keypath string, value any, requester *Identity) (any, error) {
	_ = ctx
	if err := SetKeyPath(c.storage, keypath, value); err != nil {
		return nil, err
	}
	c.pushEntityEvent(keypath, value, "entity", requester)
	return map[string]any{"status": "stored", "keypath": keypath}, nil
}

func (c *EntityAnchorCell) setEntityAction(ctx context.Context, keypath string, value any, requester *Identity) (any, error) {
	_ = ctx
	payload := NormalizeJSON(value)
	switch keypath {
	case "entity.batchPersist":
		return c.batchPersist(payload, requester)
	case "identityLinks.approveEnrollment":
		return c.approve(payload, requester), nil
	case "identityLinks.completeEnrollment":
		return c.complete(payload, requester), nil
	case "identityLinks.revoke":
		return c.revoke(payload, requester), nil
	default:
		return map[string]any{"status": "error", "message": "unknown action " + keypath}, nil
	}
}

func (c *EntityAnchorCell) batchPersist(payload any, requester *Identity) (map[string]any, error) {
	obj, ok := ObjectValue(payload)
	if !ok {
		return map[string]any{"status": "failed", "error": "invalid entity.batchPersist envelope"}, nil
	}
	schema, ok := obj["schema"].(string)
	mutations, listOK := ListValue(obj["mutations"])
	if !ok || !listOK {
		return map[string]any{"status": "failed", "error": "invalid entity.batchPersist envelope"}, nil
	}
	persisted := []string{}
	for _, item := range mutations {
		mutation, ok := ObjectValue(item)
		if !ok {
			return map[string]any{"status": "failed", "error": "invalid mutation"}, nil
		}
		keypath, ok := mutation["keypath"].(string)
		if !ok {
			return map[string]any{"status": "failed", "error": "invalid mutation"}, nil
		}
		if _, ok := mutation["value"]; !ok {
			return map[string]any{"status": "failed", "error": "invalid mutation"}, nil
		}
		if err := SetKeyPath(c.storage, keypath, mutation["value"]); err != nil {
			return nil, err
		}
		persisted = append(persisted, keypath)
	}
	response := map[string]any{"status": "persisted", "schema": schema, "persistedPaths": persisted}
	c.pushEntityEvent("entity.batchPersist", response, "entity", requester)
	return response, nil
}

func (c *EntityAnchorCell) approve(payload any, requester *Identity) map[string]any {
	obj, _ := ObjectValue(payload)
	approvalID, _ := obj["approvalID"].(string)
	if approvalID == "" {
		approvalID, _ = obj["approvalId"].(string)
	}
	if approvalID == "" {
		approvalID = NewUUID()
	}
	issuer := ""
	if requester != nil {
		issuer = requester.UUID
	}
	approval := map[string]any{"approvalID": approvalID, "issuerIdentityUUID": issuer, "status": "approved", "request": obj}
	keypath := "identityLinks.approvals." + safeKey(approvalID)
	_ = SetKeyPath(c.storage, keypath, approval)
	c.pushEntityEvent(keypath, approval, "entity.identityLinks", requester)
	return map[string]any{"status": "approved", "approvalID": approvalID, "approvalPackage": approval}
}

func (c *EntityAnchorCell) complete(payload any, requester *Identity) map[string]any {
	obj, _ := ObjectValue(payload)
	linkID, _ := obj["linkID"].(string)
	if linkID == "" {
		linkID, _ = obj["linkId"].(string)
	}
	if linkID == "" {
		linkID = NewUUID()
	}
	approvalJTI, _ := obj["approvalJTI"].(string)
	if approvalJTI == "" {
		approvalJTI, _ = obj["approvalJti"].(string)
	}
	if approvalJTI == "" {
		approvalJTI, _ = obj["jti"].(string)
	}
	if approvalJTI == "" {
		approvalJTI = NewUUID()
	}
	jtiKey := safeKey(approvalJTI)
	if _, err := GetKeyPath(c.storage, "identityLinks.usedApprovalJTIs."+jtiKey); err == nil {
		return map[string]any{"status": "error", "message": "approval JTI already used"}
	}
	issuer := ""
	if requester != nil {
		issuer = requester.UUID
	}
	record := map[string]any{
		"linkID":                   linkID,
		"entityBinding":            valueOrDefault(obj["entityBinding"], map[string]any{}),
		"linkedIdentity":           valueOrDefault(obj["linkedIdentity"], map[string]any{}),
		"approvedDomains":          valueOrDefault(obj["approvedDomains"], []any{}),
		"approvedIdentityContexts": valueOrDefault(obj["approvedIdentityContexts"], []any{}),
		"approvedScopes":           valueOrDefault(obj["approvedScopes"], []any{}),
		"issuerIdentityUUID":       issuer,
		"issuerType":               valueOrDefault(obj["issuerType"], "entity-anchor"),
		"status":                   "active",
		"linkedAt":                 valueOrDefault(obj["linkedAt"], ""),
		"lastUsedAt":               nil,
		"revokedAt":                nil,
	}
	recordKey := safeKey(linkID)
	recordKeypath := "identityLinks.records." + recordKey
	proofKeypath := "proofs.identityLinks." + recordKey
	_ = SetKeyPath(c.storage, recordKeypath, record)
	_ = SetKeyPath(c.storage, proofKeypath, map[string]any{"record": record, "approvalJTI": approvalJTI})
	_ = SetKeyPath(c.storage, "identityLinks.usedApprovalJTIs."+jtiKey, approvalJTI)
	c.pushEntityEvent(recordKeypath, record, "entity.identityLinks", requester)
	return map[string]any{"status": "completed", "record": record, "recordKeypath": recordKeypath, "proofKeypath": proofKeypath, "approvalJTI": approvalJTI}
}

func (c *EntityAnchorCell) revoke(payload any, requester *Identity) map[string]any {
	linkID, _ := payload.(string)
	if linkID == "" {
		if obj, ok := ObjectValue(payload); ok {
			linkID, _ = obj["linkID"].(string)
		}
	}
	if linkID == "" {
		return map[string]any{"status": "error", "message": "linkID is required"}
	}
	recordKey := safeKey(linkID)
	recordKeypath := "identityLinks.records." + recordKey
	value, err := GetKeyPath(c.storage, recordKeypath)
	record, ok := ObjectValue(value)
	if err != nil || !ok {
		return map[string]any{"status": "error", "message": "identity link record not found"}
	}
	record["status"] = "revoked"
	record["revokedAt"] = ""
	_ = SetKeyPath(c.storage, recordKeypath, record)
	_ = SetKeyPath(c.storage, "proofs.identityLinks."+recordKey+".record", record)
	c.pushEntityEvent(recordKeypath, record, "entity.identityLinks", requester)
	return map[string]any{"status": "revoked", "record": record, "recordKeypath": recordKeypath}
}

func (c *EntityAnchorCell) pushEntityEvent(keypath string, value any, topic string, requester *Identity) {
	_ = requester
	title := "PDS update"
	if topic == "entity.identityLinks" {
		title = "Identity link update"
	}
	flow := NewFlowElement(title, map[string]any{"keypath": keypath, "data": value, "status": "persisted"})
	flow.Topic = topic
	flow.Origin = c.CellUUID()
	c.PushFlowElement(flow, topic)
}

type CredentialVerifier interface {
	Evaluate(context.Context, map[string]any, *Identity) (map[string]any, error)
}

type UnavailableCredentialVerifier struct{}

func (UnavailableCredentialVerifier) Evaluate(context.Context, map[string]any, *Identity) (map[string]any, error) {
	return map[string]any{"status": "unavailable", "decision": "unavailable", "trusted": false, "reason": "No Swift TrustedIssuers verifier endpoint is configured."}, nil
}

type TrustedIssuersProxyCell struct {
	*GeneralCell
	verifier CredentialVerifier
}

func NewTrustedIssuersProxyCell(owner *Identity, verifier CredentialVerifier) *TrustedIssuersProxyCell {
	if verifier == nil {
		verifier = UnavailableCredentialVerifier{}
	}
	cell := &TrustedIssuersProxyCell{GeneralCell: NewGeneralCell(owner, "TrustedIssuers"), verifier: verifier}
	cell.agreementTemplate.AddGrant("rw--", "trustedIssuers")
	cell.AddGetHandler("trustedIssuers.state", cell.trustedState)
	cell.AddSetHandler("trustedIssuers.evaluate", cell.evaluateTrusted)
	return cell
}

func (c *TrustedIssuersProxyCell) trustedState(context.Context, string, *Identity) (any, error) {
	return map[string]any{"status": "ready", "mode": fmt.Sprintf("%T", c.verifier), "keys": []string{"trustedIssuers.state", "trustedIssuers.evaluate"}}, nil
}

func (c *TrustedIssuersProxyCell) evaluateTrusted(ctx context.Context, keypath string, value any, requester *Identity) (any, error) {
	_ = keypath
	payload, ok := ObjectValue(value)
	if !ok {
		return map[string]any{"status": "error", "decision": "unavailable", "trusted": false, "reason": "payload must be object"}, nil
	}
	return c.verifier.Evaluate(ctx, payload, requester)
}

type FunctionCell struct {
	*GeneralCell
}

func NewFunctionCell(owner *Identity, name string) *FunctionCell {
	if name == "" {
		name = "GoFunction"
	}
	return &FunctionCell{GeneralCell: NewGeneralCell(owner, name)}
}

func stringList(value any) []string {
	list, ok := ListValue(value)
	if !ok {
		return []string{}
	}
	out := []string{}
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func containsAll(values, required []string) bool {
	seen := map[string]struct{}{}
	for _, value := range values {
		seen[value] = struct{}{}
	}
	for _, value := range required {
		if _, ok := seen[value]; !ok {
			return false
		}
	}
	return true
}

func intNumber(value any, fallback int) int {
	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return fallback
	}
}

func vaultSortValue(note VaultNoteRecord, sortBy string) string {
	switch sortBy {
	case "title":
		return note.Title
	case "createdAt":
		return fmt.Sprintf("%020d", note.CreatedAtEpochMs)
	case "updatedAt":
		return fmt.Sprintf("%020d", note.UpdatedAtEpochMs)
	default:
		return note.ID
	}
}

func linkExists(links []map[string]any, from, to, relationship string) bool {
	for _, link := range links {
		if link["fromNoteID"] == from && link["toNoteID"] == to && link["relationship"] == relationship {
			return true
		}
	}
	return false
}

func nodeID(payload map[string]any) string {
	for _, key := range []string{"id", "node-id", "note_id", "noteID"} {
		if value, ok := payload[key].(string); ok {
			return value
		}
	}
	return ""
}

func mapKeys(values map[string]struct{}) []string {
	out := []string{}
	for key := range values {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

var safeKeyPattern = regexp.MustCompile(`[^A-Za-z0-9_-]`)

func safeKey(value string) string {
	return safeKeyPattern.ReplaceAllString(value, "_")
}

func valueOrDefault(value any, fallback any) any {
	if value == nil {
		return fallback
	}
	return value
}
