// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package interop

// Organizations owned by a group, as CellProtocol Swift does it.
//
// An organization is sealed to a signed GovernancePolicy that names its
// owners. Which actions one owner may take alone and which need more is an
// ownership agreement, and it is data: the agreement only builds the policy's
// signing rules. Changing owners or the agreement is a new policy version in a
// hash chain, approved under the previous version's amendment rule.
//
// Owners approve a concrete OrganizationActionProposal with their own keys.
// The organization key signs role credentials and status lists only once
// Evaluate says a rule holds. A node checks a role credential locally against
// a mirrored, signed status list; a missing or stale mirror gives "unknown",
// which fails closed.
//
// Codes are the Swift case names, compared case by case with
// fixtures/interop/v1/org.* (testdata/v1 here).
//
// Swift sources (CellProtocol Sources/CellBase/Organization):
// GovernancePolicy.swift, GovernancePolicyEvaluator.swift,
// OrganizationApproval.swift, OwnershipAgreement.swift,
// OrganizationGenesis.swift, OrganizationRoles.swift; the role access check
// follows VerifiableCredentials/TrustedIssuerCell.swift.

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	ActionRoleIssue         = "role.issue"
	ActionRoleRevoke        = "role.revoke"
	ActionRoleStatusPublish = "role.status.publish"
	ActionPolicyAmend       = "policy.amend"
	ActionWildcard          = "*"

	RoleOwner = "owner"

	RolesRuleID           = "roller"
	GovernanceRuleID      = "styring"
	AgreementEvidenceKind = "ownershipAgreement"
	GenericRoleCredential = "OrganizationRoleCredential"
	DefaultMirrorMaxAge   = 600 * time.Second
	roleFieldOrganization = "organization"
	roleFieldRole         = "role"
	roleFieldCohort       = "cohort"
	roleFieldValidUntil   = "validUntil"
	roleFieldPolicyHash   = "policyHash"
	statusUnknown         = "unknown"
	statusRevoked         = "revoked"
	statusValid           = "valid"
)

// RoleActions are the action classes the roles rule governs.
var RoleActions = []string{ActionRoleIssue, ActionRoleRevoke, ActionRoleStatusPublish}

// ---- Policy --------------------------------------------------------------------

type MonetaryAmount struct {
	MinorUnits int64  `wire:"minorUnits"`
	Currency   string `wire:"currency"`
}

type ActionLimits struct {
	MaxAmount *MonetaryAmount `wire:"maxAmount,opt"`
}

type RoleCount struct {
	Role    string `wire:"role"`
	Minimum int64  `wire:"minimum"`
}

type ApprovalClause struct {
	Requirements    []RoleCount `wire:"requirements"`
	DistinctPersons bool        `wire:"distinctPersons"`
}

type SigningRule struct {
	RuleID            string           `wire:"ruleID"`
	AnyOf             []ApprovalClause `wire:"anyOf"`
	ActionClasses     []string         `wire:"actionClasses"`
	ExcludedActions   []string         `wire:"excludedActions"`
	Limits            *ActionLimits    `wire:"limits,opt"`
	RequiresFreshAuth bool             `wire:"requiresFreshAuth"`
}

type PolicyEvidenceReference struct {
	Kind      string `wire:"kind"`
	Reference string `wire:"reference"`
}

type OrganizationMember struct {
	Identity   IdentityPublicKeyDescriptor `wire:"identity"`
	Roles      []string                    `wire:"roles"`
	ValidFrom  string                      `wire:"validFrom"`
	ValidUntil *string                     `wire:"validUntil,opt"`
}

type GovernancePolicy struct {
	PolicyID           string                    `wire:"policyID"`
	Version            int64                     `wire:"version"`
	PreviousPolicyHash []byte                    `wire:"previousPolicyHash,opt"`
	Members            []OrganizationMember      `wire:"members"`
	Rules              []SigningRule             `wire:"rules"`
	AmendmentRuleID    string                    `wire:"amendmentRuleID"`
	Evidence           []PolicyEvidenceReference `wire:"evidence"`
	ValidFrom          string                    `wire:"validFrom"`
}

func (*GovernancePolicy) ExcludedFromSignature() []string { return nil }

// PolicyHash is SHA-256 of the canonical bytes.
func (p *GovernancePolicy) PolicyHash() ([]byte, error) { return hashOf(p) }

// Owners are the members holding the owner role.
func (p *GovernancePolicy) Owners() []IdentityPublicKeyDescriptor {
	var out []IdentityPublicKeyDescriptor
	for _, member := range p.Members {
		if contains(member.Roles, RoleOwner) {
			out = append(out, member.Identity)
		}
	}
	return out
}

func hashOf(model Model) ([]byte, error) {
	data, err := SignedBytes(model)
	if err != nil {
		return nil, err
	}
	return SHA256(data), nil
}

func contains(list []string, item string) bool {
	for _, entry := range list {
		if entry == item {
			return true
		}
	}
	return false
}

// SameDescriptor is Swift's == on IdentityPublicKeyDescriptor (display name included).
func SameDescriptor(a, b IdentityPublicKeyDescriptor) bool {
	if !a.SameKey(b) {
		return false
	}
	if (a.DisplayName == nil) != (b.DisplayName == nil) {
		return false
	}
	return a.DisplayName == nil || *a.DisplayName == *b.DisplayName
}

func containsDescriptor(list []IdentityPublicKeyDescriptor, item IdentityPublicKeyDescriptor) bool {
	for _, entry := range list {
		if SameDescriptor(entry, item) {
			return true
		}
	}
	return false
}

// ---- Ownership agreement -------------------------------------------------------------

// OwnerQuorum is "one", "all" or "atLeast" Minimum owners.
type OwnerQuorum struct {
	Kind    string
	Minimum int
}

// Required is the number of owners needed among ownerCount, or -1 when it cannot be met.
func (q OwnerQuorum) Required(ownerCount int) int {
	if ownerCount < 1 {
		return -1
	}
	switch q.Kind {
	case "one":
		return 1
	case "all":
		return ownerCount
	case "atLeast":
		if q.Minimum < 1 || q.Minimum > ownerCount {
			return -1
		}
		return q.Minimum
	}
	return -1
}

type OwnershipAgreement struct {
	TemplateID string
	Roles      OwnerQuorum
	Governance OwnerQuorum
}

var (
	QuorumOne              = OwnerQuorum{Kind: "one"}
	QuorumAll              = OwnerQuorum{Kind: "all"}
	RolesOneGovernanceAll  = OwnershipAgreement{"roles-one-governance-all", QuorumOne, QuorumAll}
	AllTwo                 = OwnershipAgreement{"all-two", QuorumAtLeast(2), QuorumAtLeast(2)}
	OneAlone               = OwnershipAgreement{"one-alone", QuorumOne, QuorumOne}
	TwoOfThree             = OwnershipAgreement{"two-of-three", QuorumAtLeast(2), QuorumAtLeast(2)}
	OwnershipAgreementList = []OwnershipAgreement{RolesOneGovernanceAll, AllTwo, OneAlone, TwoOfThree}
)

func QuorumAtLeast(minimum int) OwnerQuorum { return OwnerQuorum{Kind: "atLeast", Minimum: minimum} }

// SigningRules are the two rules the agreement stands for.
func (a OwnershipAgreement) SigningRules(ownerCount int) ([]SigningRule, error) {
	roles := a.Roles.Required(ownerCount)
	if roles < 0 {
		return nil, fail("quorumCannotBeMet", RolesRuleID)
	}
	governance := a.Governance.Required(ownerCount)
	if governance < 0 {
		return nil, fail("quorumCannotBeMet", GovernanceRuleID)
	}
	return []SigningRule{
		{RuleID: RolesRuleID, AnyOf: []ApprovalClause{{Requirements: []RoleCount{{RoleOwner, int64(roles)}}, DistinctPersons: true}},
			ActionClasses: append([]string{}, RoleActions...), ExcludedActions: []string{}},
		{RuleID: GovernanceRuleID, AnyOf: []ApprovalClause{{Requirements: []RoleCount{{RoleOwner, int64(governance)}}, DistinctPersons: true}},
			ActionClasses: []string{ActionPolicyAmend}, ExcludedActions: []string{}},
	}, nil
}

// OwnerGroupPolicy is GovernancePolicy.ownerGroup.
func OwnerGroupPolicy(policyID string, version int64, previous []byte, owners []IdentityPublicKeyDescriptor,
	agreement OwnershipAgreement, validFrom string) (*GovernancePolicy, error) {
	if len(owners) == 0 {
		return nil, fail("noOwners")
	}
	seen := map[string]bool{}
	members := make([]OrganizationMember, 0, len(owners))
	for _, owner := range owners {
		if seen[owner.UUID] {
			return nil, fail("duplicateOwner", owner.UUID)
		}
		seen[owner.UUID] = true
		members = append(members, OrganizationMember{Identity: owner, Roles: []string{RoleOwner}, ValidFrom: validFrom})
	}
	rules, err := agreement.SigningRules(len(owners))
	if err != nil {
		return nil, err
	}
	return &GovernancePolicy{
		PolicyID: policyID, Version: version, PreviousPolicyHash: previous, Members: members, Rules: rules,
		AmendmentRuleID: GovernanceRuleID,
		Evidence:        []PolicyEvidenceReference{{Kind: AgreementEvidenceKind, Reference: agreement.TemplateID}},
		ValidFrom:       validFrom,
	}, nil
}

// ---- Proposals and approvals ------------------------------------------------------

type OrganizationActionProposal struct {
	Version              int64                       `wire:"version"`
	ProposalID           string                      `wire:"proposalID"`
	OrganizationAnchorID string                      `wire:"organizationAnchorID"`
	PolicyHash           []byte                      `wire:"policyHash"`
	ActionClass          string                      `wire:"actionClass"`
	PayloadHash          []byte                      `wire:"payloadHash"`
	PayloadSummary       string                      `wire:"payloadSummary"`
	Amount               *MonetaryAmount             `wire:"amount,opt"`
	Audience             string                      `wire:"audience"`
	CreatedAt            string                      `wire:"createdAt"`
	ExpiresAt            string                      `wire:"expiresAt"`
	Nonce                []byte                      `wire:"nonce"`
	Proposer             IdentityPublicKeyDescriptor `wire:"proposer"`
}

func (*OrganizationActionProposal) ExcludedFromSignature() []string { return nil }

func (p *OrganizationActionProposal) ProposalHash() ([]byte, error) { return hashOf(p) }

type OrganizationApproval struct {
	Version           int64                          `wire:"version"`
	ProposalHash      []byte                         `wire:"proposalHash"`
	Approver          IdentityPublicKeyDescriptor    `wire:"approver"`
	Role              string                         `wire:"role"`
	Decision          string                         `wire:"decision"`
	ApprovedAt        string                         `wire:"approvedAt"`
	FreshAuthEvidence *IdentityLinkFreshAuthEvidence `wire:"freshAuthEvidence,opt"`
	Signature         []byte                         `wire:"signature,opt"`
}

func (*OrganizationApproval) ExcludedFromSignature() []string { return []string{"signature"} }

func (a *OrganizationApproval) SignatureIsValid() bool {
	payload, err := SignedBytes(a)
	return err == nil && VerifySignature(a.Signature, payload, a.Approver)
}

// SignApproval approves proposal as approver with the owner role.
func SignApproval(proposal *OrganizationActionProposal, approver IdentityPublicKeyDescriptor,
	sign func([]byte) ([]byte, error), approvedAt string) (*OrganizationApproval, error) {
	hash, err := proposal.ProposalHash()
	if err != nil {
		return nil, err
	}
	approval := &OrganizationApproval{Version: 1, ProposalHash: hash, Approver: approver, Role: RoleOwner, Decision: "approve", ApprovedAt: approvedAt}
	payload, err := SignedBytes(approval)
	if err != nil {
		return nil, err
	}
	if approval.Signature, err = sign(payload); err != nil {
		return nil, err
	}
	return approval, nil
}

type ApprovalBundle struct {
	Proposal  OrganizationActionProposal `wire:"proposal"`
	Approvals []OrganizationApproval     `wire:"approvals"`
}

func (*ApprovalBundle) ExcludedFromSignature() []string { return nil }

// ---- Evaluator (GovernancePolicyEvaluator): pure, fails closed ---------------------------

type GovernanceEvaluation struct {
	RuleID        string
	ClauseIndex   int
	ApproverUUIDs []string
}

func (e GovernanceEvaluation) Verdict() string {
	return fmt.Sprintf("met:%s:%d", e.RuleID, e.ClauseIndex)
}

func orgDate(text string) (time.Time, error) {
	moment, ok := ParseISO8601(text)
	if !ok {
		return time.Time{}, fail("malformedTimestamp", text)
	}
	return moment, nil
}

type validApproval struct {
	member   OrganizationMember
	approval OrganizationApproval
}

// Evaluate is GovernancePolicyEvaluator.evaluate. Nonce replay and fresh-auth
// evidence verification belong to the vault, not here.
func Evaluate(policy *GovernancePolicy, bundle *ApprovalBundle, now time.Time) (*GovernanceEvaluation, error) {
	proposal := &bundle.Proposal
	policyHash, err := policy.PolicyHash()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(policyHash, proposal.PolicyHash) {
		return nil, fail("policyHashMismatch")
	}
	created, err := orgDate(proposal.CreatedAt)
	if err != nil {
		return nil, err
	}
	if created.After(now) {
		return nil, fail("proposalNotYetValid")
	}
	expires, err := orgDate(proposal.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if now.After(expires) {
		return nil, fail("proposalExpired")
	}
	proposalHash, err := proposal.ProposalHash()
	if err != nil {
		return nil, err
	}
	var valid []validApproval
	for i := range bundle.Approvals {
		approval := bundle.Approvals[i]
		who := approval.Approver.UUID
		if !bytes.Equal(approval.ProposalHash, proposalHash) {
			return nil, fail("approvalForOtherProposal", who)
		}
		if !approval.SignatureIsValid() {
			return nil, fail("approvalSignatureInvalid", who)
		}
		var member *OrganizationMember
		for j := range policy.Members {
			if SameDescriptor(policy.Members[j].Identity, approval.Approver) {
				member = &policy.Members[j]
				break
			}
		}
		if member == nil {
			return nil, fail("approverNotMember", who)
		}
		if !contains(member.Roles, approval.Role) {
			return nil, fail("approverLacksRole", who)
		}
		approvedAt, err := orgDate(approval.ApprovedAt)
		if err != nil {
			return nil, err
		}
		from, err := orgDate(member.ValidFrom)
		if err != nil {
			return nil, err
		}
		inside := !from.After(approvedAt)
		if member.ValidUntil != nil {
			until, err := orgDate(*member.ValidUntil)
			if err != nil {
				return nil, err
			}
			inside = inside && !approvedAt.After(until)
		}
		if !inside {
			return nil, fail("approverNotValidAt", who)
		}
		if approval.Decision == "reject" {
			return nil, fail("rejected", who)
		}
		valid = append(valid, validApproval{*member, approval})
	}

	var candidates []SigningRule
	for _, rule := range policy.Rules {
		if contains(rule.ActionClasses, proposal.ActionClass) || contains(rule.ActionClasses, ActionWildcard) {
			candidates = append(candidates, rule)
		}
	}
	if len(candidates) == 0 {
		return nil, fail("noRuleCoversAction", proposal.ActionClass)
	}
	var firstGate, first error
	for _, rule := range candidates {
		evaluation, err := evaluateRule(rule, proposal, valid)
		if err == nil {
			return evaluation, nil
		}
		if VerdictOf(err) != "clauseNotSatisfied" && firstGate == nil {
			firstGate = err
		}
		if first == nil {
			first = err
		}
	}
	if firstGate != nil {
		return nil, firstGate
	}
	return nil, first
}

func evaluateRule(rule SigningRule, proposal *OrganizationActionProposal, approvals []validApproval) (*GovernanceEvaluation, error) {
	// One vote per person per role. A person approving twice counts once.
	rolesByPerson := map[string]map[string]bool{}
	for _, entry := range approvals {
		uuid := entry.member.Identity.UUID
		if rolesByPerson[uuid] == nil {
			rolesByPerson[uuid] = map[string]bool{}
		}
		rolesByPerson[uuid][entry.approval.Role] = true
	}
	matchIndex := -1
	var people []string
	for index, clause := range rule.AnyOf {
		if used, ok := satisfiers(clause, rolesByPerson); ok {
			matchIndex, people = index, used
			break
		}
	}
	if matchIndex < 0 {
		return nil, fail("clauseNotSatisfied", rule.RuleID)
	}
	if contains(rule.ExcludedActions, proposal.ActionClass) {
		return nil, fail("actionExcluded", rule.RuleID)
	}
	if rule.Limits != nil && rule.Limits.MaxAmount != nil {
		limit, amount := rule.Limits.MaxAmount, proposal.Amount
		if amount == nil || amount.Currency != limit.Currency || amount.MinorUnits > limit.MinorUnits {
			return nil, fail("amountExceedsLimit", rule.RuleID)
		}
	}
	if rule.RequiresFreshAuth {
		for _, entry := range approvals {
			if entry.approval.FreshAuthEvidence == nil {
				return nil, fail("freshAuthRequired", entry.approval.Approver.UUID)
			}
		}
	}
	sort.Strings(people)
	return &GovernanceEvaluation{RuleID: rule.RuleID, ClauseIndex: matchIndex, ApproverUUIDs: people}, nil
}

func satisfiers(clause ApprovalClause, rolesByPerson map[string]map[string]bool) ([]string, bool) {
	var slots []string
	for _, requirement := range clause.Requirements {
		if requirement.Minimum < 1 {
			return nil, false
		}
		for i := int64(0); i < requirement.Minimum; i++ {
			slots = append(slots, requirement.Role)
		}
	}
	persons := make([]string, 0, len(rolesByPerson))
	for person := range rolesByPerson {
		persons = append(persons, person)
	}
	sort.Strings(persons)
	used := map[string]bool{}
	var fill func(int) bool
	fill = func(index int) bool {
		if index == len(slots) {
			return true
		}
		for _, person := range persons {
			if !rolesByPerson[person][slots[index]] {
				continue
			}
			if clause.DistinctPersons && used[person] {
				continue
			}
			inserted := !used[person]
			used[person] = true
			if fill(index + 1) {
				return true
			}
			if inserted {
				delete(used, person)
			}
		}
		return false
	}
	if !fill(0) {
		return nil, false
	}
	out := make([]string, 0, len(used))
	for person := range used {
		out = append(out, person)
	}
	return out, true
}

// BundleVerdict is "met:<rule>:<clause>" or the refusal's Swift case name.
func BundleVerdict(policy *GovernancePolicy, bundle *ApprovalBundle, now time.Time) string {
	evaluation, err := Evaluate(policy, bundle, now)
	if err != nil {
		return VerdictOf(err)
	}
	return evaluation.Verdict()
}

// ---- Genesis and the policy chain ---------------------------------------------------

type OrganizationFounderSignature struct {
	Founder   IdentityPublicKeyDescriptor `wire:"founder"`
	SignedAt  string                      `wire:"signedAt"`
	Signature []byte                      `wire:"signature"`
}

type OrganizationGenesisSeal struct {
	Version           int64                          `wire:"version"`
	Kind              string                         `wire:"kind"`
	AnchorID          string                         `wire:"anchorID"`
	DisplayName       string                         `wire:"displayName"`
	LegalIdentifier   *string                        `wire:"legalIdentifier,opt"`
	InitialPolicyHash []byte                         `wire:"initialPolicyHash"`
	CustodianKey      IdentityPublicKeyDescriptor    `wire:"custodianKey"`
	Founders          []IdentityPublicKeyDescriptor  `wire:"founders"`
	SealedAt          string                         `wire:"sealedAt"`
	Signatures        []OrganizationFounderSignature `wire:"signatures"`
}

func (*OrganizationGenesisSeal) ExcludedFromSignature() []string { return []string{"signatures"} }

func (s *OrganizationGenesisSeal) SealHash() ([]byte, error) { return hashOf(s) }

// Sign adds founder's signature, replacing an earlier one.
func (s *OrganizationGenesisSeal) Sign(founder IdentityPublicKeyDescriptor, sign func([]byte) ([]byte, error), signedAt string) error {
	if !containsDescriptor(s.Founders, founder) {
		return fail("unexpectedSigner", founder.UUID)
	}
	payload, err := SignedBytes(s)
	if err != nil {
		return err
	}
	signature, err := sign(payload)
	if err != nil {
		return err
	}
	kept := s.Signatures[:0:0]
	for _, entry := range s.Signatures {
		if !SameDescriptor(entry.Founder, founder) {
			kept = append(kept, entry)
		}
	}
	s.Signatures = append(kept, OrganizationFounderSignature{Founder: founder, SignedAt: signedAt, Signature: signature})
	return nil
}

// Verify is OrganizationGenesisSeal.verify(initialPolicy:). Fails closed.
func (s *OrganizationGenesisSeal) Verify(initial *GovernancePolicy) error {
	if s.Kind != "organization" || len(s.Founders) == 0 {
		return fail("noFounders")
	}
	if initial.Version != 1 {
		return fail("initialPolicyMustBeVersionOne")
	}
	if initial.PreviousPolicyHash != nil {
		return fail("initialPolicyHasPredecessor")
	}
	hash, err := initial.PolicyHash()
	if err != nil {
		return err
	}
	if !bytes.Equal(hash, s.InitialPolicyHash) {
		return fail("policyHashMismatch")
	}
	owners := initial.Owners()
	for _, founder := range s.Founders {
		if !containsDescriptor(owners, founder) {
			return fail("founderNotOwner", founder.UUID)
		}
	}
	for _, owner := range owners {
		if !containsDescriptor(s.Founders, owner) {
			return fail("ownerNotFounder", owner.UUID)
		}
	}
	payload, err := SignedBytes(s)
	if err != nil {
		return err
	}
	for _, entry := range s.Signatures {
		if !containsDescriptor(s.Founders, entry.Founder) {
			return fail("unexpectedSigner", entry.Founder.UUID)
		}
	}
	for _, founder := range s.Founders {
		var entry *OrganizationFounderSignature
		for i := range s.Signatures {
			if SameDescriptor(s.Signatures[i].Founder, founder) {
				entry = &s.Signatures[i]
				break
			}
		}
		if entry == nil {
			return fail("founderSignatureMissing", founder.UUID)
		}
		if !VerifySignature(entry.Signature, payload, founder) {
			return fail("founderSignatureInvalid", founder.UUID)
		}
	}
	return nil
}

func ownerName(owner IdentityPublicKeyDescriptor) string {
	if owner.DisplayName != nil {
		return *owner.DisplayName
	}
	return owner.UUID
}

func agreementOf(policy *GovernancePolicy) *string {
	for _, evidence := range policy.Evidence {
		if evidence.Kind == AgreementEvidenceKind {
			reference := evidence.Reference
			return &reference
		}
	}
	return nil
}

// AmendmentSummary is GovernancePolicyAmendment.summary: plain Norwegian, from the policies only.
func AmendmentSummary(current, next *GovernancePolicy) string {
	before, after := map[string]bool{}, map[string]bool{}
	for _, owner := range current.Owners() {
		before[owner.UUID] = true
	}
	for _, owner := range next.Owners() {
		after[owner.UUID] = true
	}
	var added, removed []string
	for _, owner := range next.Owners() {
		if !before[owner.UUID] {
			added = append(added, ownerName(owner))
		}
	}
	for _, owner := range current.Owners() {
		if !after[owner.UUID] {
			removed = append(removed, ownerName(owner))
		}
	}
	parts := []string{fmt.Sprintf("Policy v%d → v%d.", current.Version, next.Version)}
	if len(added) > 0 {
		parts = append(parts, "Ny eier: "+strings.Join(added, ", ")+".")
	}
	if len(removed) > 0 {
		parts = append(parts, "Fjernet eier: "+strings.Join(removed, ", ")+".")
	}
	agreementBefore, agreementAfter := agreementOf(current), agreementOf(next)
	if agreementAfter != nil && (agreementBefore == nil || *agreementBefore != *agreementAfter) {
		parts = append(parts, "Eierskapsavtale: "+*agreementAfter+".")
	}
	return strings.Join(parts, " ")
}

// AmendmentProposal is GovernancePolicyAmendment.proposal(replacing:with:...).
func AmendmentProposal(current, next *GovernancePolicy, anchorID, proposalID string, proposer IdentityPublicKeyDescriptor,
	createdAt, expiresAt string, nonce []byte) (*OrganizationActionProposal, error) {
	currentHash, err := current.PolicyHash()
	if err != nil {
		return nil, err
	}
	nextHash, err := next.PolicyHash()
	if err != nil {
		return nil, err
	}
	return &OrganizationActionProposal{
		Version: 1, ProposalID: proposalID, OrganizationAnchorID: anchorID, PolicyHash: currentHash,
		ActionClass: ActionPolicyAmend, PayloadHash: nextHash, PayloadSummary: AmendmentSummary(current, next),
		Audience: anchorID, CreatedAt: createdAt, ExpiresAt: expiresAt, Nonce: nonce, Proposer: proposer,
	}, nil
}

func decisionTime(bundle *ApprovalBundle) time.Time {
	var latest time.Time
	found := false
	for _, approval := range bundle.Approvals {
		if moment, ok := ParseISO8601(approval.ApprovedAt); ok && (!found || moment.After(latest)) {
			latest, found = moment, true
		}
	}
	if found {
		return latest
	}
	if moment, ok := ParseISO8601(bundle.Proposal.CreatedAt); ok {
		return moment
	}
	return time.Time{}
}

// VerifyAmendment is GovernancePolicyChain.verify(step:replacing:organizationAnchorID:).
func VerifyAmendment(current, next *GovernancePolicy, bundle *ApprovalBundle, anchorID string) error {
	proposal := &bundle.Proposal
	if next.PolicyID != current.PolicyID {
		return fail("policyIDChanged")
	}
	if next.Version != current.Version+1 {
		return fail("versionNotNext")
	}
	currentHash, err := current.PolicyHash()
	if err != nil {
		return err
	}
	if !bytes.Equal(next.PreviousPolicyHash, currentHash) {
		return fail("previousHashMismatch")
	}
	if proposal.OrganizationAnchorID != anchorID {
		return fail("proposalNotForThisOrganization")
	}
	if proposal.ActionClass != ActionPolicyAmend {
		return fail("proposalIsNotAnAmendment", proposal.ActionClass)
	}
	if !bytes.Equal(proposal.PolicyHash, currentHash) {
		return fail("proposalNotUnderPreviousPolicy")
	}
	nextHash, err := next.PolicyHash()
	if err != nil {
		return err
	}
	if !bytes.Equal(proposal.PayloadHash, nextHash) {
		return fail("payloadIsNotTheNewPolicy")
	}
	evaluation, err := Evaluate(current, bundle, decisionTime(bundle))
	if err != nil {
		return fail("approvalsRefused", VerdictOf(err))
	}
	if evaluation.RuleID != current.AmendmentRuleID {
		return fail("amendmentRuleNotUsed", evaluation.RuleID)
	}
	return nil
}

// ---- Role credentials and status lists ------------------------------------------------

// UnsignedRoleCredential is OrganizationRoleCredential.unsigned: what the owners approve.
func UnsignedRoleCredential(anchorID, credentialType string, custodian, subject IdentityPublicKeyDescriptor,
	role string, cohort *string, validUntil string, policyHash []byte, issuedAt time.Time, claimUUID string) (*VCClaim, error) {
	issuerDID, err := DIDKey(custodian)
	if err != nil {
		return nil, err
	}
	subjectDID, err := DIDKey(subject)
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		roleFieldOrganization: anchorID,
		roleFieldRole:         role,
		roleFieldValidUntil:   validUntil,
		roleFieldPolicyHash:   base64.StdEncoding.EncodeToString(policyHash),
		"id":                  subjectDID,
	}
	if cohort != nil {
		body[roleFieldCohort] = *cohort
	}
	issued := ISO8601(issuedAt.Truncate(time.Second))
	return &VCClaim{
		Context:           append([]string{}, vcContext...),
		ID:                "cell:///identity/" + subject.UUID + "/claims/" + claimUUID,
		Type:              []string{"VerifiableCredential", GenericRoleCredential, credentialType},
		Issuer:            issuerDID,
		IssuanceDate:      issued,
		CredentialSubject: body,
		Proof:             VCProof{Type: ProofTypeFor(custodian), Created: issued, ProofPurpose: "assertionMethod", VerificationMethod: custodian.UUID},
	}, nil
}

// RolePayloadHash is the hash the owners approve: SHA-256 of the claim without proof.
func RolePayloadHash(claim *VCClaim) ([]byte, error) {
	data, err := claim.UnsignedBytes()
	if err != nil {
		return nil, err
	}
	return SHA256(data), nil
}

// RoleSummary is OrganizationRoleCredential.summary: what the owner is shown.
func RoleSummary(claim *VCClaim, displayName string) string {
	subject, _ := claim.subjectObject()
	text := func(key string) (string, bool) {
		value, ok := subject[key].(string)
		return value, ok
	}
	orUnknown := func(key string) string {
		if value, ok := text(key); ok {
			return value
		}
		return "?"
	}
	out := fmt.Sprintf("%s gir rollen «%s» til %s", displayName, orUnknown(roleFieldRole), orUnknown("id"))
	if cohort, ok := text(roleFieldCohort); ok {
		out += " i kullet " + cohort
	}
	return out + ", gyldig til " + orUnknown(roleFieldValidUntil) + "."
}

func descriptorFromDID(did string) (IdentityPublicKeyDescriptor, bool) {
	curve, key, err := PublicKeyFromDIDKey(did)
	if err != nil {
		return IdentityPublicKeyDescriptor{}, false
	}
	algorithm := map[string]string{"Curve25519": "EdDSA", "P256": "ECDSA"}[curve]
	if algorithm == "" {
		return IdentityPublicKeyDescriptor{}, false
	}
	return IdentityPublicKeyDescriptor{UUID: did, PublicKey: key, Algorithm: algorithm, CurveType: curve}, true
}

// VerifyRoleCredential is VCClaim.verify(): the key comes from the issuer's did:key.
func VerifyRoleCredential(claim *VCClaim) bool {
	issuer, ok := claim.Issuer.(string)
	if !ok {
		return false
	}
	descriptor, ok := descriptorFromDID(issuer)
	if !ok {
		return false
	}
	if claim.Proof.ProofPurpose != "assertionMethod" || len(claim.Proof.SignatureData) == 0 ||
		len(claim.Proof.SignatureData) > 512 || claim.Proof.Type != ProofTypeFor(descriptor) {
		return false
	}
	data, err := claim.UnsignedBytes()
	return err == nil && VerifySignature(claim.Proof.SignatureData, data, descriptor)
}

type OrganizationRoleStatusList struct {
	Version              int64    `wire:"version"`
	OrganizationAnchorID string   `wire:"organizationAnchorID"`
	IssuerDID            string   `wire:"issuerDID"`
	Sequence             int64    `wire:"sequence"`
	IssuedAt             string   `wire:"issuedAt"`
	RevokedCredentialIDs []string `wire:"revokedCredentialIDs"`
	Signature            []byte   `wire:"signature,opt"`
}

func (*OrganizationRoleStatusList) ExcludedFromSignature() []string { return []string{"signature"} }

// NewStatusList is the Swift initializer: revoked ids deduplicated and sorted.
func NewStatusList(anchorID, issuerDID string, sequence int64, issuedAt string, revoked []string) *OrganizationRoleStatusList {
	seen := map[string]bool{}
	ids := []string{}
	for _, id := range revoked {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return &OrganizationRoleStatusList{Version: 1, OrganizationAnchorID: anchorID, IssuerDID: issuerDID,
		Sequence: sequence, IssuedAt: issuedAt, RevokedCredentialIDs: ids}
}

func (l *OrganizationRoleStatusList) SignatureIsValid() bool {
	descriptor, ok := descriptorFromDID(l.IssuerDID)
	if !ok {
		return false
	}
	payload, err := SignedBytes(l)
	return err == nil && VerifySignature(l.Signature, payload, descriptor)
}

func (l *OrganizationRoleStatusList) Summary(displayName string, newlyRevoked []string) string {
	sorted := append([]string{}, newlyRevoked...)
	sort.Strings(sorted)
	return fmt.Sprintf("%s trekker tilbake %d rolle(r): %s. Statusliste nr. %d.", displayName, len(sorted), strings.Join(sorted, ", "), l.Sequence)
}

func sameStatusList(a, b *OrganizationRoleStatusList) bool {
	left, errA := EncodedJSON(a)
	right, errB := EncodedJSON(b)
	return errA == nil && errB == nil && bytes.Equal(left, right)
}

type statusMirror struct {
	list        *OrganizationRoleStatusList
	refreshedAt time.Time
}

// CredentialStatusRegistry is the node's mirror of each issuer's latest list. Checks are local.
type CredentialStatusRegistry struct {
	mirrors map[string]statusMirror
}

func NewCredentialStatusRegistry() *CredentialStatusRegistry {
	return &CredentialStatusRegistry{mirrors: map[string]statusMirror{}}
}

// Accept takes a newer signed list, or refreshes the mirror time for the same list.
func (r *CredentialStatusRegistry) Accept(list *OrganizationRoleStatusList, now time.Time) error {
	if !list.SignatureIsValid() {
		return fail("signatureInvalid")
	}
	if current, ok := r.mirrors[list.IssuerDID]; ok {
		if sameStatusList(current.list, list) {
			r.mirrors[list.IssuerDID] = statusMirror{current.list, now}
			return nil
		}
		if list.Sequence <= current.list.Sequence {
			return fail("sequenceNotNewer", fmt.Sprintf("%d>=%d", current.list.Sequence, list.Sequence))
		}
	}
	r.mirrors[list.IssuerDID] = statusMirror{list, now}
	return nil
}

func (r *CredentialStatusRegistry) HasMirror(issuerDID string) bool {
	_, ok := r.mirrors[issuerDID]
	return ok
}

// Status is "valid", "revoked" or "unknown" (no mirror, or older than maxAge).
func (r *CredentialStatusRegistry) Status(issuerDID, credentialID string, now time.Time, maxAge time.Duration) string {
	mirror, ok := r.mirrors[issuerDID]
	if !ok || now.Sub(mirror.refreshedAt) > maxAge {
		return statusUnknown
	}
	if contains(mirror.list.RevokedCredentialIDs, credentialID) {
		return statusRevoked
	}
	return statusValid
}

// ---- Role access (the TrustedIssuer checks a role condition depends on) -----------------

var roleAccessHardFailures = map[string]bool{
	"issuer_not_registered_or_inactive": true,
	"issuer_context_not_allowed":        true,
	"vc_type_missing":                   true,
	"vc_issuer_mismatch":                true,
	"vc_credential_subject_missing":     true,
	"revocation_check_failed":           true,
	"revocation_check_unsupported":      true,
	"revocation_status_unknown":         true,
	"vc_subject_validity_expired":       true,
	"claim_subject_path_missing":        true,
	"claim_predicate_not_met":           true,
	"subject_binding_missing":           true,
	"subject_binding_mismatch":          true,
	"vc_signature_invalid":              true,
}

// SubjectValidUntil reads credentialSubject.validUntil. present=false when
// absent; ok=false when present but unreadable (fails closed). A plain date
// means the end of that day in UTC.
func SubjectValidUntil(subject map[string]any) (until time.Time, present, ok bool) {
	raw, present := subject[roleFieldValidUntil]
	if !present {
		return time.Time{}, false, false
	}
	text, isText := raw.(string)
	if !isText {
		return time.Time{}, true, false
	}
	if moment, parsed := ParseISO8601(text); parsed {
		return moment, true, true
	}
	if len(text) == 10 {
		if day, err := time.Parse("2006-01-02", text); err == nil {
			return day.UTC().Add(86_399 * time.Second), true, true
		}
	}
	return time.Time{}, true, false
}

// RoleAccessRequest is what a node knows when a role condition is checked.
type RoleAccessRequest struct {
	TrustedIssuers         map[string][]string // issuer DID -> contexts
	ContextID              string
	RequesterDID           string
	RequiredType           string
	ExpectedRole           string
	Registry               *CredentialStatusRegistry
	Now                    time.Time
	RequireRevocationCheck bool
}

// RoleAccessDecision is "trusted" or "untrusted", with TrustedIssuer reason codes.
type RoleAccessDecision struct {
	Decision string
	Reasons  []string
}

// RoleAccess decides whether claim opens a cell whose Agreement condition asks
// for ExpectedRole, with the checks TrustedIssuerCell makes for a
// ProvedClaimCondition and the same reason codes. Any hard failure refuses.
func RoleAccess(claim *VCClaim, request RoleAccessRequest) RoleAccessDecision {
	issuer, _ := claim.Issuer.(string)
	contexts, registered := request.TrustedIssuers[issuer]
	if issuer == "" || !registered {
		return RoleAccessDecision{"untrusted", []string{"issuer_not_registered_or_inactive"}}
	}
	if !contains(contexts, request.ContextID) {
		return RoleAccessDecision{"untrusted", []string{"issuer_context_not_allowed"}}
	}
	var reasons []string
	if !contains(claim.Type, request.RequiredType) {
		reasons = append(reasons, "vc_type_missing")
	}
	subject, _ := claim.subjectObject()
	if until, present, ok := SubjectValidUntil(subject); present {
		if ok && !until.Before(request.Now) {
			reasons = append(reasons, "vc_subject_validity_ok")
		} else {
			reasons = append(reasons, "vc_subject_validity_expired")
		}
	}
	if request.RequireRevocationCheck {
		if request.Registry != nil && request.Registry.HasMirror(issuer) && claim.ID != "" {
			switch request.Registry.Status(issuer, claim.ID, request.Now, DefaultMirrorMaxAge) {
			case statusValid:
				reasons = append(reasons, "revocation_status_valid")
			case statusRevoked:
				reasons = append(reasons, "revocation_check_failed")
			default:
				reasons = append(reasons, "revocation_status_unknown")
			}
		} else {
			reasons = append(reasons, "revocation_check_unsupported")
		}
	}
	if role, present := subject[roleFieldRole]; !present {
		reasons = append(reasons, "claim_subject_path_missing")
	} else if text, _ := role.(string); text != request.ExpectedRole {
		reasons = append(reasons, "claim_predicate_not_met")
	}
	if id, _ := subject["id"].(string); id == "" {
		reasons = append(reasons, "subject_binding_missing")
	} else if id != request.RequesterDID {
		reasons = append(reasons, "subject_binding_mismatch")
	}
	if VerifyRoleCredential(claim) {
		reasons = append(reasons, "vc_signature_valid")
	} else {
		reasons = append(reasons, "vc_signature_invalid")
	}
	sort.Strings(reasons)
	for _, reason := range reasons {
		if roleAccessHardFailures[reason] {
			return RoleAccessDecision{"untrusted", reasons}
		}
	}
	return RoleAccessDecision{"trusted", reasons}
}

// NewOrganizationModel returns an empty model for an org.* fixture type.
func NewOrganizationModel(typeName string) (Model, error) {
	switch typeName {
	case "GovernancePolicy":
		return &GovernancePolicy{}, nil
	case "OrganizationGenesisSeal":
		return &OrganizationGenesisSeal{}, nil
	case "OrganizationActionProposal":
		return &OrganizationActionProposal{}, nil
	case "OrganizationApproval":
		return &OrganizationApproval{}, nil
	case "ApprovalBundle":
		return &ApprovalBundle{}, nil
	case "OrganizationRoleStatusList":
		return &OrganizationRoleStatusList{}, nil
	case "VCClaim":
		return &VCClaim{}, nil
	}
	return nil, fmt.Errorf("interop: unknown organization type %s", typeName)
}
