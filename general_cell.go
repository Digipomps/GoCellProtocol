// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type CellUsageScope string

const (
	ScopeScaffoldUnique CellUsageScope = "scaffoldUnique"
	ScopeTemplate       CellUsageScope = "template"
	ScopeIdentityUnique CellUsageScope = "identityUnique"
)

type Persistancy string

const (
	Persistant Persistancy = "persistant"
	Ephemeral  Persistancy = "ephemeral"
)

type GetHandler func(context.Context, string, *Identity) (any, error)
type SetHandler func(context.Context, string, any, *Identity) (any, error)

type ExploreContract struct {
	Key         string   `json:"key"`
	Method      string   `json:"method"`
	Input       any      `json:"input"`
	Returns     any      `json:"returns"`
	Permissions []string `json:"permissions"`
	Required    bool     `json:"required"`
	Description string   `json:"description"`
}

type AnyCell struct {
	UUID              string            `json:"uuid"`
	Name              string            `json:"name"`
	CellScope         CellUsageScope    `json:"cellScope"`
	Persistancy       Persistancy       `json:"persistancy"`
	IdentityDomain    string            `json:"identityDomain"`
	ContractTemplate  Agreement         `json:"contractTemplate"`
	AgreementTemplate AgreementTemplate `json:"agreementTemplate"`
	Keys              []string          `json:"keys"`
}

type GeneralCell struct {
	mu                sync.RWMutex
	uuid              string
	name              string
	owner             *Identity
	agreementTemplate AgreementTemplate
	identityDomain    string
	cellScope         CellUsageScope
	persistancy       Persistancy
	storage           map[string]any
	getHandlers       map[string]GetHandler
	setHandlers       map[string]SetHandler
	exploreContracts  map[string]ExploreContract
	attached          map[string]Emit
	flowHistory       []FlowElement
	subscribers       map[int]chan FlowElement
	nextSubscriber    int
	nextSequence      uint64
	agreements        map[string]Agreement
	admissionPolicy   string
	contracts         []Contract
	revokedBefore     map[string]time.Time
	conditionTarget   Meddle
	closed            bool
}

const (
	DefaultAgreementDuration = 60 * 60 * 24 * 365
	// MaximumAgreementDuration is Swift's Contract.maximumDuration.
	MaximumAgreementDuration = 60 * 60 * 24 * 365

	OwnerApprovalRequired      = "ownerApprovalRequired"
	AutomaticWhenConditionsMet = "automaticWhenConditionsMet"
	OwnerPublishedRead         = "ownerPublishedRead"
)

// Contract is one the cell signed for a subject. The cell keeps it; every
// access re-checks it against the current template and its conditions.
type Contract struct {
	UUID       string
	Subject    *Identity
	Grants     []Grant
	Conditions []Condition
	Duration   int
	IssuedAt   time.Time
}

func NewGeneralCell(owner *Identity, name string) *GeneralCell {
	if name == "" {
		name = "General"
	}
	cell := &GeneralCell{
		uuid:              NewUUID(),
		name:              name,
		owner:             owner,
		cellScope:         ScopeScaffoldUnique,
		persistancy:       Ephemeral,
		storage:           map[string]any{},
		getHandlers:       map[string]GetHandler{},
		setHandlers:       map[string]SetHandler{},
		exploreContracts:  map[string]ExploreContract{},
		attached:          map[string]Emit{},
		subscribers:       map[int]chan FlowElement{},
		agreements:        map[string]Agreement{},
		agreementTemplate: AgreementTemplate{},
		admissionPolicy:   OwnerApprovalRequired,
		revokedBefore:     map[string]time.Time{},
	}
	cell.agreementTemplate.AddGrant("r--", "description")
	cell.agreementTemplate.AddGrant("r--", "keys")
	return cell
}

func (c *GeneralCell) SetUUID(uuid string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.uuid = uuid
}

func (c *GeneralCell) CellUUID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.uuid
}

func (c *GeneralCell) Name() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.name
}

func (c *GeneralCell) IdentityDomain() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.identityDomain
}

func (c *GeneralCell) SetIdentityDomain(domain string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.identityDomain = domain
}

func (c *GeneralCell) AgreementTemplate() *AgreementTemplate {
	return &c.agreementTemplate
}

// TemplateConditions are the Agreement template's conditions.
func (c *GeneralCell) TemplateConditions() []Condition {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]Condition(nil), c.agreementTemplate.Conditions...)
}

// SetTemplateConditions replaces the Agreement template's conditions.
func (c *GeneralCell) SetTemplateConditions(conditions []Condition) {
	c.mu.Lock()
	c.agreementTemplate.Conditions = append([]Condition(nil), conditions...)
	c.mu.Unlock()
}

func (c *GeneralCell) ownerIdentity() *Identity {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.owner
}

func (c *GeneralCell) AddGetHandler(key string, handler GetHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.getHandlers[key] = handler
}

func (c *GeneralCell) AddSetHandler(key string, handler SetHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setHandlers[key] = handler
}

func (c *GeneralCell) RegisterExploreContract(contract ExploreContract) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if contract.Input == nil {
		contract.Input = map[string]any{"type": "null"}
	}
	if contract.Returns == nil {
		contract.Returns = map[string]any{"type": "unknown"}
	}
	contract.Required = true
	c.exploreContracts[contract.Key] = contract
}

func (c *GeneralCell) Get(ctx context.Context, keypath string, requester *Identity) (any, error) {
	if keypath == "description" {
		return c.Advertise(ctx, requester)
	}
	if keypath == "keys" {
		return c.Keys(ctx, requester)
	}
	if err := c.ValidateAccess(ctx, "read", keypath, requester); err != nil {
		return nil, err
	}
	handler := c.handlerForGet(keypath)
	if handler != nil {
		return handler(ctx, keypath, requester)
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return GetKeyPath(c.storage, keypath)
}

func (c *GeneralCell) Set(ctx context.Context, keypath string, value any, requester *Identity) (any, error) {
	if err := c.ValidateAccess(ctx, "write", keypath, requester); err != nil {
		return nil, err
	}
	handler := c.handlerForSet(keypath)
	if handler != nil {
		return handler(ctx, keypath, value, requester)
	}
	c.mu.Lock()
	err := SetKeyPath(c.storage, keypath, value)
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	c.PushFlowElement(NewFlowElement("Cell update", map[string]any{
		"keypath": keypath,
		"data":    NormalizeJSON(value),
	}), "cell.update")
	return nil, nil
}

func (c *GeneralCell) Keys(ctx context.Context, requester *Identity) ([]string, error) {
	_ = ctx
	_ = requester
	c.mu.RLock()
	defer c.mu.RUnlock()
	seen := map[string]struct{}{}
	for key := range c.exploreContracts {
		seen[key] = struct{}{}
	}
	for key := range c.getHandlers {
		seen[key] = struct{}{}
	}
	for key := range c.setHandlers {
		seen[key] = struct{}{}
	}
	for key := range c.storage {
		seen[key] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for key := range seen {
		out = append(out, key)
	}
	sort.Strings(out)
	return out, nil
}

func (c *GeneralCell) TypeForKey(ctx context.Context, keypath string, requester *Identity) (string, error) {
	c.mu.RLock()
	contract, hasContract := c.exploreContracts[keypath]
	c.mu.RUnlock()
	if hasContract {
		if obj, ok := ObjectValue(contract.Returns); ok {
			if typ, ok := obj["type"].(string); ok {
				return typ, nil
			}
		}
	}
	value, err := c.Get(ctx, keypath, requester)
	if err != nil {
		return "unknown", nil
	}
	switch NormalizeJSON(value).(type) {
	case nil:
		return "null", nil
	case bool:
		return "bool", nil
	case int, int64, uint, uint64:
		return "integer", nil
	case float64:
		return "float", nil
	case string:
		return "string", nil
	case []any:
		return "list", nil
	case map[string]any:
		return "object", nil
	default:
		return "unknown", nil
	}
}

func (c *GeneralCell) Attach(ctx context.Context, emitter Emit, label string, requester *Identity) (ConnectState, error) {
	if err := c.ValidateAccess(ctx, "write", label, requester); err != nil {
		return ConnectDenied, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.attached[label] = emitter
	return ConnectConnected, nil
}

func (c *GeneralCell) AbsorbFlow(ctx context.Context, label string, requester *Identity) error {
	if err := c.ValidateAccess(ctx, "write", label, requester); err != nil {
		return err
	}
	c.mu.RLock()
	emitter := c.attached[label]
	c.mu.RUnlock()
	if emitter == nil {
		return KeyPathError{Path: label, Msg: "no attached emitter"}
	}
	flow, err := emitter.Flow(ctx, requester)
	if err != nil {
		return err
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case element, ok := <-flow:
				if !ok {
					return
				}
				c.PushFlowElement(element, element.Topic)
			}
		}
	}()
	return nil
}

func (c *GeneralCell) Detach(ctx context.Context, label string, requester *Identity) error {
	if err := c.ValidateAccess(ctx, "write", label, requester); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.attached, label)
	return nil
}

func (c *GeneralCell) DropFlow(ctx context.Context, label string, requester *Identity) error {
	return c.Detach(ctx, label, requester)
}

func (c *GeneralCell) DropAllFlows(ctx context.Context, requester *Identity) error {
	return c.DetachAll(ctx, requester)
}

func (c *GeneralCell) DetachAll(ctx context.Context, requester *Identity) error {
	if err := c.ValidateAccess(ctx, "write", "connections", requester); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.attached = map[string]Emit{}
	return nil
}

func (c *GeneralCell) AttachedStatus(ctx context.Context, label string, requester *Identity) (ConnectionStatus, error) {
	if err := c.ValidateAccess(ctx, "read", label, requester); err != nil {
		return ConnectionStatus{}, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if _, ok := c.attached[label]; ok {
		return ConnectionStatus{Label: label, State: ConnectConnected}, nil
	}
	return ConnectionStatus{Label: label, State: ConnectNotConnected}, nil
}

func (c *GeneralCell) AttachedStatuses(ctx context.Context, requester *Identity) ([]ConnectionStatus, error) {
	if err := c.ValidateAccess(ctx, "read", "connections", requester); err != nil {
		return nil, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]ConnectionStatus, 0, len(c.attached))
	for label := range c.attached {
		out = append(out, ConnectionStatus{Label: label, State: ConnectConnected})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out, nil
}

func (c *GeneralCell) Flow(ctx context.Context, requester *Identity) (<-chan FlowElement, error) {
	if err := c.ValidateAccess(ctx, "flow.read", "feed", requester); err != nil {
		return nil, err
	}
	ch := make(chan FlowElement, 64)
	c.mu.Lock()
	if c.closed {
		close(ch)
		c.mu.Unlock()
		return ch, nil
	}
	for _, element := range c.flowHistory {
		ch <- element
	}
	id := c.nextSubscriber
	c.nextSubscriber++
	c.subscribers[id] = ch
	c.mu.Unlock()
	go func() {
		<-ctx.Done()
		c.mu.Lock()
		if existing, ok := c.subscribers[id]; ok {
			delete(c.subscribers, id)
			close(existing)
		}
		c.mu.Unlock()
	}()
	return ch, nil
}

func (c *GeneralCell) Admit(ctx context.Context, connect ConnectContext) (ConnectState, error) {
	requester := connect.Requester
	if requester == nil {
		return ConnectDenied, nil
	}
	if !c.HoldsContract(ctx, requester) {
		return ConnectSignContract, nil
	}
	for _, capability := range connect.RequestedCapabilities {
		if !c.ContractAllows(ctx, "-w--", capabilityKeypath(capability), requester) && !c.ContractAllows(ctx, "r---", capabilityKeypath(capability), requester) {
			return ConnectDenied, nil
		}
	}
	return ConnectConnected, nil
}

func (c *GeneralCell) Close(ctx context.Context, requester *Identity) error {
	if err := c.ValidateAccess(ctx, "write", "lifecycle.close", requester); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	for id, ch := range c.subscribers {
		close(ch)
		delete(c.subscribers, id)
	}
	return nil
}

func (c *GeneralCell) AddAgreement(ctx context.Context, contract Agreement, identity *Identity) (AgreementState, error) {
	return c.AddAgreementAuthorizedBy(ctx, contract, identity, nil)
}

// SetAdmissionPolicy is Swift's agreementAdmissionPolicy.
func (c *GeneralCell) SetAdmissionPolicy(policy string) {
	c.mu.Lock()
	c.admissionPolicy = policy
	c.mu.Unlock()
}

func (c *GeneralCell) AdmissionPolicy() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.admissionPolicy
}

// SetConditionTarget names the cell conditions read "target." from: the
// outer cell when GeneralCell is embedded.
func (c *GeneralCell) SetConditionTarget(target Meddle) {
	c.mu.Lock()
	c.conditionTarget = target
	c.mu.Unlock()
}

func (c *GeneralCell) target() Meddle {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.conditionTarget != nil {
		return c.conditionTarget
	}
	return c
}

// AddAgreementAuthorizedBy is Swift's addAgreement(_:for:authorizedBy:): sign a
// contract for identity, or reject. The request must stay inside the template
// (same owner, granted keypaths only, the template's conditions, no longer
// duration). The owner approves it, or the policy is automaticWhenConditionsMet
// and the template has an enforcing condition. Then every condition must hold.
func (c *GeneralCell) AddAgreementAuthorizedBy(ctx context.Context, request Agreement, identity, authority *Identity) (AgreementState, error) {
	c.mu.RLock()
	owner := c.owner
	template := c.agreementTemplate
	policy := c.admissionPolicy
	cellUUID, domain := c.uuid, c.identityDomain
	c.mu.RUnlock()
	if identity == nil || owner == nil {
		return AgreementRejected, nil
	}
	if identity.Vault() != nil && !identityProvesSigningKeyControl(ctx, identity, identity, domain, "cell:///"+cellUUID+"/agreement", "addAgreement", "GoCellProtocol.GeneralCell") {
		return AgreementRejected, nil
	}
	ownerAuthorized := authority != nil && identitiesReferenceSameSigningKey(owner, authority) &&
		identityProvesSigningKeyControl(ctx, owner, authority, domain, "cell:///"+cellUUID+"/agreement", "addAgreement", "GoCellProtocol.GeneralCell")
	if request.Owner == nil || !identitiesReferenceSameSigningKey(owner, request.Owner) ||
		request.State != AgreementStateTemplate || request.Duration <= 0 ||
		request.Duration > template.duration() || request.Duration > MaximumAgreementDuration ||
		len(request.Grants) == 0 || !conditionsMatch(request.Conditions, template.Conditions) {
		return AgreementRejected, nil
	}
	for _, grant := range request.Grants {
		if !template.CheckGrant(grant) {
			return AgreementRejected, nil
		}
	}
	if !ownerAuthorized {
		switch policy {
		case AutomaticWhenConditionsMet:
			enforcing := false
			for _, condition := range template.Conditions {
				enforcing = enforcing || condition.Enforcing()
			}
			if !enforcing {
				return AgreementRejected, nil
			}
		case OwnerPublishedRead:
			for _, grant := range request.Grants {
				if group, other, ok := permissionBits(grant.Permission); !ok || group != 4 || other != 0 {
					return AgreementRejected, nil
				}
			}
		default:
			return AgreementRejected, nil
		}
	}
	if !c.conditionsHold(ctx, template.Conditions, identity) {
		return AgreementRejected, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	issuedAt := time.Now()
	if cutoff, ok := c.revokedBefore[identity.UUID]; ok && !issuedAt.After(cutoff) {
		issuedAt = cutoff.Add(time.Microsecond)
	}
	c.contracts = append(c.contracts, Contract{
		UUID:       strings.ToUpper(NewUUID()),
		Subject:    identity,
		Grants:     append([]Grant(nil), request.Grants...),
		Conditions: append([]Condition(nil), template.Conditions...),
		Duration:   request.Duration,
		IssuedAt:   issuedAt,
	})
	return AgreementSigned, nil
}

func (c *GeneralCell) conditionsHold(ctx context.Context, conditions []Condition, identity *Identity) bool {
	target := c.target()
	ctx = withEvaluatingConditions(ctx)
	for _, condition := range conditions {
		if !condition.Met(ctx, target, identity) {
			return false
		}
	}
	return true
}

// ContractAllows is true when a current contract of requester grants
// permission ("r---", "-w--") at exactly keypath. As Swift, the contract must
// still match the template and its conditions must still hold.
func (c *GeneralCell) ContractAllows(ctx context.Context, permission, keypath string, requester *Identity) bool {
	if requester == nil || evaluatingConditions(ctx) {
		return false
	}
	requested := Grant{Keypath: keypath, Permission: permission}
	for _, contract := range c.currentContracts(requester) {
		covered := false
		for _, grant := range contract.Grants {
			covered = covered || grant.CoversExactly(requested)
		}
		if covered && c.conditionsHold(ctx, contract.Conditions, requester) {
			return true
		}
	}
	return false
}

// HoldsContract is true when requester has any current contract whose conditions hold.
func (c *GeneralCell) HoldsContract(ctx context.Context, requester *Identity) bool {
	if requester == nil || evaluatingConditions(ctx) {
		return false
	}
	for _, contract := range c.currentContracts(requester) {
		if c.conditionsHold(ctx, contract.Conditions, requester) {
			return true
		}
	}
	return false
}

func (c *GeneralCell) currentContracts(requester *Identity) []Contract {
	c.mu.RLock()
	defer c.mu.RUnlock()
	now := time.Now()
	var out []Contract
	for _, contract := range c.contracts {
		if !identitiesReferenceSameSigningKey(contract.Subject, requester) {
			continue
		}
		if cutoff, ok := c.revokedBefore[contract.Subject.UUID]; ok && !contract.IssuedAt.After(cutoff) {
			continue
		}
		if now.Before(contract.IssuedAt) || !now.Before(contract.IssuedAt.Add(time.Duration(contract.Duration)*time.Second)) {
			continue
		}
		if contract.Duration > c.agreementTemplate.duration() || !conditionsMatch(contract.Conditions, c.agreementTemplate.Conditions) {
			continue
		}
		inside := true
		for _, grant := range contract.Grants {
			inside = inside && c.agreementTemplate.CheckGrant(grant)
		}
		if inside {
			out = append(out, contract)
		}
	}
	return out
}

// RemoveContracts is Swift's removeMember: contracts issued up to now stop counting.
func (c *GeneralCell) RemoveContracts(subjectUUID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.revokedBefore[subjectUUID] = time.Now()
	kept := c.contracts[:0]
	for _, contract := range c.contracts {
		if contract.Subject.UUID != subjectUUID {
			kept = append(kept, contract)
		}
	}
	c.contracts = kept
}

func (c *GeneralCell) Advertise(ctx context.Context, requester *Identity) (AnyCell, error) {
	keys, err := c.Keys(ctx, requester)
	if err != nil && c.owner != nil {
		return AnyCell{}, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	owner := c.owner
	if owner == nil {
		owner = requester
	}
	contract := NewAgreement(owner)
	contract.Grants = append([]Grant(nil), c.agreementTemplate.Grants...)
	contract.Conditions = append([]Condition(nil), c.agreementTemplate.Conditions...)
	contract.Duration = c.agreementTemplate.duration()
	return AnyCell{
		UUID:              c.uuid,
		Name:              c.name,
		CellScope:         c.cellScope,
		Persistancy:       c.persistancy,
		IdentityDomain:    c.identityDomain,
		ContractTemplate:  contract,
		AgreementTemplate: c.agreementTemplate,
		Keys:              keys,
	}, nil
}

func (c *GeneralCell) State(ctx context.Context, requester *Identity) (any, error) {
	if state, err := c.Get(ctx, "state", requester); err == nil {
		return state, nil
	}
	if err := c.ValidateAccess(ctx, "read", "state", requester); err != nil {
		return nil, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return NormalizeJSON(c.storage), nil
}

func (c *GeneralCell) GetOwner(ctx context.Context, requester *Identity) (*Identity, error) {
	if err := c.ValidateAccess(ctx, "read", "owner", requester); err != nil {
		return nil, err
	}
	if c.owner == nil {
		return nil, fmt.Errorf("cell has no owner")
	}
	return c.owner, nil
}

func (c *GeneralCell) GetEmitterWithUUID(ctx context.Context, uuid string, requester *Identity) (Emit, error) {
	if err := c.ValidateAccess(ctx, "read", "emitters", requester); err != nil {
		return nil, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.uuid == uuid {
		return c, nil
	}
	for _, emitter := range c.attached {
		if emitter.CellUUID() == uuid {
			return emitter, nil
		}
	}
	return nil, nil
}

func (c *GeneralCell) IsMember(ctx context.Context, identity *Identity, requester *Identity) (bool, error) {
	if err := c.ValidateAccess(ctx, "read", "membership", requester); err != nil {
		return false, err
	}
	if c.owner == nil || identity == nil {
		return false, nil
	}
	return identitiesReferenceSameSigningKey(c.owner, identity), nil
}

func (c *GeneralCell) PushFlowElement(element FlowElement, topic string) {
	c.mu.Lock()
	if element.ID == "" {
		element.ID = NewUUID()
	}
	c.nextSequence++
	if element.Sequence == 0 {
		element.Sequence = c.nextSequence
	}
	if element.LogicalTime == 0 {
		element.LogicalTime = element.Sequence
	}
	if topic != "" {
		element.Topic = topic
	}
	if element.Topic == "" {
		element.Topic = "*"
	}
	if element.Origin == "" {
		element.Origin = c.uuid
	}
	if element.ProducerIdentity == "" && c.owner != nil {
		element.ProducerIdentity = c.owner.UUID
	}
	element.Content = NormalizeJSON(element.Content)
	c.flowHistory = append(c.flowHistory, element)
	subscribers := make([]chan FlowElement, 0, len(c.subscribers))
	for _, ch := range c.subscribers {
		subscribers = append(subscribers, ch)
	}
	c.mu.Unlock()
	for _, ch := range subscribers {
		select {
		case ch <- element:
		default:
		}
	}
}

func (c *GeneralCell) FlowHistory() []FlowElement {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]FlowElement, len(c.flowHistory))
	copy(out, c.flowHistory)
	return out
}

func (c *GeneralCell) ValidateAccess(ctx context.Context, operation, keypath string, requester *Identity) error {
	c.mu.RLock()
	owner := c.owner
	cellUUID := c.uuid
	identityDomain := c.identityDomain
	c.mu.RUnlock()
	if owner == nil {
		return fmt.Errorf("access denied: cell has no owner or explicit public policy")
	}
	if requester != nil && requester.UUID == owner.UUID {
		if !identitiesReferenceSameSigningKey(owner, requester) {
			return fmt.Errorf("access denied: owner UUID matched but signing key differed")
		}
		if identityProvesSigningKeyControl(
			ctx,
			owner,
			requester,
			identityDomain,
			"cell:///"+cellUUID+"/"+keypath,
			operation,
			"GoCellProtocol.GeneralCell",
		) {
			return nil
		}
		return fmt.Errorf("access denied: owner signing-key proof failed")
	}
	if c.ContractAllows(ctx, swiftPermission(operation), keypath, requester) {
		return nil
	}
	return fmt.Errorf("access denied: no contract for %s grants %s on %s", identityLabel(requester), swiftPermission(operation), keypath)
}

// swiftPermission maps an operation to the Swift permission a grant must hold.
func swiftPermission(operation string) string {
	switch operation {
	case "read", "flow.read":
		return "r---"
	default:
		return "-w--"
	}
}

func (c *GeneralCell) handlerForGet(keypath string) GetHandler {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return handlerFor(keypath, c.getHandlers)
}

func (c *GeneralCell) handlerForSet(keypath string) SetHandler {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return handlerFor(keypath, c.setHandlers)
}

func handlerFor[T any](keypath string, handlers map[string]T) T {
	var zero T
	candidates := make([]string, 0)
	for key := range handlers {
		if keypath == key || strings.HasPrefix(keypath, key+".") {
			candidates = append(candidates, key)
		}
	}
	if len(candidates) == 0 {
		return zero
	}
	sort.Slice(candidates, func(i, j int) bool { return len(candidates[i]) > len(candidates[j]) })
	return handlers[candidates[0]]
}

func permissionForOperation(operation, keypath string) string {
	switch operation {
	case "read":
		return "state.read:" + keypath
	case "flow.read":
		return "flow.read"
	case "write":
		return "state.write:" + keypath
	default:
		return operation
	}
}

func capabilityKeypath(capability string) string {
	if idx := strings.Index(capability, ":"); idx >= 0 && idx+1 < len(capability) {
		return capability[idx+1:]
	}
	if strings.Contains(capability, "flow.read") {
		return "feed"
	}
	return capability
}

func identityLabel(identity *Identity) string {
	if identity == nil {
		return "anonymous"
	}
	return identity.UUID
}
