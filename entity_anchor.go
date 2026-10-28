package cellprotocol

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/Digipomps/GoCellProtocol/interop"
)

var entityRoots = []string{"person", "purposes", "relations", "proofs", "signedAgreementEntity", "entityRepresentation", "agreements", "chronicle", "bindings", "identityLinks"}

var identityLinkActions = []string{"identityLinks.genesis", "identityLinks.approveEnrollment", "identityLinks.completeEnrollment", "identityLinks.revoke"}

// EntityAnchorCell is the owner's entity, with identityLinks.* as in Swift's
// EntityAnchorCell. identityLinks.genesis seals the anchor to the owner;
// approveEnrollment issues an approval and same-entity credential;
// completeEnrollment verifies the full chain (request, approval, credential,
// presentation) and records the link; revoke revokes an exact link. Genesis
// also happens on the owner's first entity.batchPersist.
type EntityAnchorCell struct {
	*GeneralCell
	Clock   func() time.Time
	NewUUID func() string
}

func NewEntityAnchorCell(owner *Identity) *EntityAnchorCell {
	cell := &EntityAnchorCell{
		GeneralCell: NewGeneralCell(owner, "EntityAnchor"),
		Clock:       time.Now,
		NewUUID:     func() string { return strings.ToUpper(NewUUID()) },
	}
	for _, root := range entityRoots {
		cell.storage[root] = map[string]any{}
		cell.agreementTemplate.AddGrant("rw--", root)
		cell.AddGetHandler(root, cell.getEntity)
		cell.AddSetHandler(root, cell.setEntity)
	}
	cell.storage["chronicle"] = []any{}
	for _, action := range append(append([]string{}, identityLinkActions...), "entity.batchPersist") {
		cell.AddSetHandler(action, cell.setEntityAction)
	}
	return cell
}

// DescriptorFor is IdentityLinkProtocolService.descriptor(for:) for a Go identity.
func DescriptorFor(identity *Identity) (interop.IdentityPublicKeyDescriptor, bool) {
	if identity == nil || identity.PublicSecureKey == "" {
		return interop.IdentityPublicKeyDescriptor{}, false
	}
	key, err := base64.StdEncoding.DecodeString(identity.PublicSecureKey)
	if err != nil {
		return interop.IdentityPublicKeyDescriptor{}, false
	}
	descriptor := interop.IdentityPublicKeyDescriptor{UUID: identity.UUID, PublicKey: key, Algorithm: "EdDSA", CurveType: "Curve25519"}
	if identity.DisplayName != "" {
		name := identity.DisplayName
		descriptor.DisplayName = &name
	}
	return descriptor, true
}

func linkError(keypath, code string, detail ...string) map[string]any {
	out := map[string]any{"status": "error", "keypath": keypath, "code": code, "message": code}
	if len(detail) > 0 && detail[0] != "" {
		out["detail"] = detail[0]
	}
	return out
}

// toStored turns a wire model into the plain JSON value kept in storage.
func toStored(model any) (any, error) {
	data, err := interop.EncodedJSON(model)
	if err != nil {
		return nil, err
	}
	var out any
	return out, json.Unmarshal(data, &out)
}

// fromStored decodes a stored or received JSON value into a wire model.
func fromStored(value any, model any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return interop.Decode(data, model)
}

func (c *EntityAnchorCell) now() time.Time { return c.Clock().UTC() }

func (c *EntityAnchorCell) genesisSeal() *interop.EntityGenesisSeal {
	c.mu.RLock()
	value, err := GetKeyPath(c.storage, interop.SealKeypath)
	c.mu.RUnlock()
	if err != nil || value == nil {
		return nil
	}
	var seal interop.EntityGenesisSeal
	if fromStored(value, &seal) != nil {
		return nil
	}
	return &seal
}

func (c *EntityAnchorCell) store(keypath string, value any) {
	c.mu.Lock()
	_ = SetKeyPath(c.storage, keypath, value)
	c.mu.Unlock()
}

func (c *EntityAnchorCell) load(keypath string) (any, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return GetKeyPath(c.storage, keypath)
}

func (c *EntityAnchorCell) getEntity(ctx context.Context, keypath string, requester *Identity) (any, error) {
	_, _ = ctx, requester
	if keypath == "identityLinks" || keypath == "identityLinks.state" {
		records, _ := c.load("identityLinks.records")
		used, _ := c.load("identityLinks.usedApprovalJTIs")
		genesis, _ := c.load(interop.SealKeypath)
		if records == nil {
			records = map[string]any{}
		}
		if used == nil {
			used = map[string]any{}
		}
		return map[string]any{"status": "ready", "sealed": c.genesisSeal() != nil, "genesis": genesis, "records": records,
			"usedApprovalJTIs": used, "summary": "EntityAnchor identityLinks er klar for approveEnrollment, completeEnrollment og revoke."}, nil
	}
	return c.load(keypath)
}

func (c *EntityAnchorCell) setEntity(ctx context.Context, keypath string, value any, requester *Identity) (any, error) {
	_ = ctx
	if interop.IsImmutableGenesisKeypath(keypath) {
		return linkError(keypath, "genesisKeypathIsImmutable"), nil
	}
	if seal := c.genesisSeal(); seal != nil && keypath == interop.RecordKeypath(seal.LinkID) {
		return linkError(keypath, "genesisKeypathIsImmutable"), nil
	}
	c.mu.Lock()
	err := SetKeyPath(c.storage, keypath, value)
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	topic := "entity"
	if strings.HasPrefix(keypath, "identityLinks") {
		topic = "entity.identityLinks"
	}
	c.pushEntityEvent(keypath, value, topic, requester)
	return map[string]any{"status": "stored", "keypath": keypath}, nil
}

func isIdentityLinkAction(keypath string) bool {
	for _, action := range identityLinkActions {
		if action == keypath {
			return true
		}
	}
	return false
}

func (c *EntityAnchorCell) setEntityAction(ctx context.Context, keypath string, value any, requester *Identity) (any, error) {
	if keypath != "entity.batchPersist" && !isIdentityLinkAction(keypath) {
		// A keypath below an action, such as identityLinks.genesis.trigger.
		return c.setEntity(ctx, keypath, value, requester)
	}
	payload := NormalizeJSON(value)
	var (
		result map[string]any
		err    error
	)
	switch keypath {
	case "entity.batchPersist":
		return c.batchPersist(ctx, payload, requester)
	case "identityLinks.genesis":
		result, err = c.genesis(ctx, payload, requester)
	case "identityLinks.approveEnrollment":
		result, err = c.approve(payload, requester)
	case "identityLinks.completeEnrollment":
		result, err = c.complete(payload, requester)
	case "identityLinks.revoke":
		result, err = c.revoke(payload, requester)
	}
	if err != nil {
		var failure *interop.Failure
		if f, ok := err.(*interop.Failure); ok {
			failure = f
		}
		if failure != nil {
			return linkError(keypath, failure.Code), nil
		}
		return linkError(keypath, "bad_payload", err.Error()), nil
	}
	return result, nil
}

func (c *EntityAnchorCell) requesterProvesOwnership(ctx context.Context, requester *Identity, keypath string) bool {
	c.mu.RLock()
	owner, domain, uuid := c.owner, c.identityDomain, c.uuid
	c.mu.RUnlock()
	return owner != nil && requester != nil && identityProvesSigningKeyControl(ctx, owner, requester, domain,
		"cell:///"+uuid+"/"+keypath, "write", "GoCellProtocol.EntityAnchorCell")
}

func (c *EntityAnchorCell) batchPersist(ctx context.Context, payload any, requester *Identity) (map[string]any, error) {
	obj, ok := ObjectValue(payload)
	if !ok {
		return map[string]any{"status": "failed", "error": "invalid entity.batchPersist envelope"}, nil
	}
	schema, ok := obj["schema"].(string)
	mutations, listOK := ListValue(obj["mutations"])
	if !ok || !listOK {
		return map[string]any{"status": "failed", "error": "invalid entity.batchPersist envelope"}, nil
	}
	if !c.requesterProvesOwnership(ctx, requester, "entity.batchPersist") {
		return map[string]any{"status": "failed", "error": "requesterMismatch"}, nil
	}
	// Genesis on first need, as in Swift: only a proven owner seals.
	if c.genesisSeal() == nil {
		if _, _, err := c.performGenesis(ctx, requester, "firstPersist"); err != nil {
			return map[string]any{"status": "failed", "error": err.Error()}, nil
		}
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
		if interop.IsImmutableGenesisKeypath(keypath) {
			return map[string]any{"status": "failed", "error": "genesisKeypathIsImmutable"}, nil
		}
		c.mu.Lock()
		err := SetKeyPath(c.storage, keypath, mutation["value"])
		c.mu.Unlock()
		if err != nil {
			return nil, err
		}
		persisted = append(persisted, keypath)
	}
	response := map[string]any{"status": "persisted", "schema": schema, "persistedPaths": persisted}
	c.pushEntityEvent("entity.batchPersist", response, "entity", requester)
	return response, nil
}

// ---- Genesis ---------------------------------------------------------------------

func (c *EntityAnchorCell) genesis(ctx context.Context, payload any, requester *Identity) (map[string]any, error) {
	trigger := "firstPersist"
	raw, _ := payload.(string)
	if obj, ok := ObjectValue(payload); ok {
		raw, _ = obj["trigger"].(string)
	}
	for _, known := range interop.GenesisTriggers {
		if raw == known {
			trigger = raw
		}
	}
	if existing := c.genesisSeal(); existing != nil {
		return nil, &interop.Failure{Code: "alreadySealed", Detail: existing.LinkID}
	}
	if !c.requesterProvesOwnership(ctx, requester, "identityLinks.genesis") {
		return nil, &interop.Failure{Code: "initiatorIsNotOwner"}
	}
	seal, record, err := c.performGenesis(ctx, requester, trigger)
	if err != nil {
		return nil, err
	}
	sealValue, _ := toStored(seal)
	recordValue, _ := toStored(record)
	return map[string]any{"status": "sealed", "seal": sealValue, "record": recordValue}, nil
}

func (c *EntityAnchorCell) performGenesis(ctx context.Context, requester *Identity, trigger string) (*interop.EntityGenesisSeal, *interop.IdentityLinkRecord, error) {
	if c.genesisSeal() != nil {
		return nil, nil, &interop.Failure{Code: "alreadySealed"}
	}
	initiator, ok := DescriptorFor(requester)
	if !ok {
		return nil, nil, &interop.Failure{Code: "initiatorHasNoSigningKey"}
	}
	domain := c.IdentityDomain()
	if domain == "" {
		domain = "private"
	}
	sign := func(m []byte) ([]byte, error) { return requester.Sign(ctx, m) }
	seal, record, err := interop.SealGenesis(c.CellUUID(), initiator, sign, domain, trigger, c.now())
	if err != nil {
		return nil, nil, err
	}
	sealValue, err := toStored(seal)
	if err != nil {
		return nil, nil, err
	}
	recordValue, err := toStored(record)
	if err != nil {
		return nil, nil, err
	}
	c.store(interop.SealKeypath, sealValue)
	c.store(interop.RecordKeypath(record.LinkID), recordValue)
	c.store("proofs.identityLinks."+interop.SafeRecordKey(record.LinkID), map[string]any{"record": recordValue, "seal": sealValue})
	c.pushEntityEvent(interop.SealKeypath, sealValue, "entity.identityLinks", requester)
	return seal, record, nil
}

// ---- Enrollment ----------------------------------------------------------------

func (c *EntityAnchorCell) approve(payload any, requester *Identity) (map[string]any, error) {
	var envelope interop.IdentityLinkApprovalEnvelope
	if err := fromStored(payload, &envelope); err != nil {
		return nil, err
	}
	issuer, ok := DescriptorFor(requester)
	if !ok {
		return nil, &interop.Failure{Code: "missingRequiredContext", Detail: "issuerIdentity"}
	}
	sign := func(m []byte) ([]byte, error) { return requester.Sign(context.Background(), m) }
	pkg, err := interop.ApproveEnrollment(&envelope, issuer, sign, c.now(), c.NewUUID(), c.NewUUID())
	if err != nil {
		return nil, err
	}
	value, err := toStored(pkg)
	if err != nil {
		return nil, err
	}
	keypath := "identityLinks.approvals." + interop.SafeRecordKey(pkg.Approval.ApprovalID)
	c.store(keypath, value)
	c.pushEntityEvent(keypath, value, "entity.identityLinks", requester)
	return map[string]any{"status": "approved", "approvalID": pkg.Approval.ApprovalID, "approvalPackage": value}, nil
}

func (c *EntityAnchorCell) usedApprovalJTIs() map[string]bool {
	used := map[string]bool{}
	value, _ := c.load("identityLinks.usedApprovalJTIs")
	if obj, ok := ObjectValue(value); ok {
		for key, item := range obj {
			if jti, ok := item.(string); ok {
				used[jti] = true
			} else {
				used[key] = true
			}
		}
	}
	return used
}

func (c *EntityAnchorCell) complete(payload any, requester *Identity) (map[string]any, error) {
	var envelope interop.IdentityLinkCompletionEnvelope
	if err := fromStored(payload, &envelope); err != nil {
		return nil, err
	}
	result, err := interop.VerifyCompletion(&envelope, c.now(), c.usedApprovalJTIs(), nil)
	if err != nil {
		return nil, err
	}
	recordValue, err := toStored(&result.Record)
	if err != nil {
		return nil, err
	}
	recordKey := interop.SafeRecordKey(result.Record.LinkID)
	recordKeypath := "identityLinks.records." + recordKey
	proofKeypath := "proofs.identityLinks." + recordKey
	c.store(recordKeypath, recordValue)
	c.store(proofKeypath, map[string]any{
		"record":         recordValue,
		"requestHash":    base64.StdEncoding.EncodeToString(result.RequestHash),
		"approvalJTI":    result.ApprovalJTI,
		"credentialID":   result.CredentialID,
		"presentationID": result.PresentationID,
		"completedAt":    result.Record.LinkedAt,
	})
	c.store("identityLinks.usedApprovalJTIs."+interop.SafeRecordKey(result.ApprovalJTI), result.ApprovalJTI)
	c.pushEntityEvent(recordKeypath, recordValue, "entity.identityLinks", requester)
	return map[string]any{"status": "completed", "record": recordValue, "recordKeypath": recordKeypath,
		"proofKeypath": proofKeypath, "approvalJTI": result.ApprovalJTI}, nil
}

func (c *EntityAnchorCell) revoke(payload any, requester *Identity) (map[string]any, error) {
	linkID, _ := payload.(string)
	if obj, ok := ObjectValue(payload); ok {
		linkID, _ = obj["linkID"].(string)
	}
	if linkID == "" {
		return nil, &interop.Failure{Code: "missingRequiredContext", Detail: "linkID"}
	}
	if interop.IsGenesisLink(linkID) {
		return nil, &interop.Failure{Code: "cannotRevokeGenesisLink", Detail: linkID}
	}
	recordKey := interop.SafeRecordKey(linkID)
	recordKeypath := "identityLinks.records." + recordKey
	stored, err := c.load(recordKeypath)
	if err != nil || stored == nil {
		return nil, &interop.Failure{Code: "recordNotFound", Detail: linkID}
	}
	var record interop.IdentityLinkRecord
	if err := fromStored(stored, &record); err != nil {
		return nil, err
	}
	record.Status = "revoked"
	revokedAt := interop.ISO8601(c.now())
	record.RevokedAt = &revokedAt
	value, err := toStored(&record)
	if err != nil {
		return nil, err
	}
	c.store(recordKeypath, value)
	c.store("proofs.identityLinks."+recordKey+".record", value)
	c.pushEntityEvent(recordKeypath, value, "entity.identityLinks", requester)
	return map[string]any{"status": "revoked", "record": value, "recordKeypath": recordKeypath}, nil
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
