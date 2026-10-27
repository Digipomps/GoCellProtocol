// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package interop

// Entity extension completion, as CellProtocol Swift does it.
//
// Extending an entity with a new key takes four signed pieces, all checked by
// the Cell that owns the entity (EntityAnchorCell, identityLinks.completeEnrollment):
//
//  1. IdentityEnrollmentRequest, signed by the new key.
//  2. IdentityEnrollmentApproval, signed by an existing key of the entity.
//  3. A SameEntityIdentityLinkCredential (VCClaim) from the approver to the new key.
//  4. A VCPresentation of that credential by the new key, bound to the
//     server's challenge and domain.
//
// VerifyCompletion gives the same answer as Swift's
// IdentityLinkProtocolService.verifyCompletion, with the same
// IdentityLinkCompletionError case names.
//
// VCClaim and VCPresentation sign JSONEncoder with .sortedKeys and
// .withoutEscapingSlashes of themselves without "proof". The claim's uuid is
// never encoded. A presentation writes verifiableCredential as null when it
// has none, and its credentials keep their proofs.

import (
	"bytes"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	CredentialTypeSameEntity   = "SameEntityIdentityLinkCredential"
	PresentationTypeSameEntity = "SameEntityIdentityLinkPresentation"
)

var vcContext = []string{"https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"}

var issuerTypes = map[string]bool{"existingDevice": true, "custodian": true, "recoveryAuthority": true}

// ---- did:key (DIDKeyParser) --------------------------------------------------

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var didKeyPrefixes = map[string][]byte{
	"Curve25519": {0xed, 0x01},
	"secp256k1":  {0xe7, 0x01},
	"P256":       {0x80, 0x24},
}

func Base58Encode(data []byte) string {
	number := new(big.Int).SetBytes(data)
	base := big.NewInt(58)
	remainder := new(big.Int)
	var out []byte
	for number.Sign() > 0 {
		number.DivMod(number, base, remainder)
		out = append(out, base58Alphabet[remainder.Int64()])
	}
	for _, b := range data {
		if b != 0 {
			break
		}
		out = append(out, '1')
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func Base58Decode(text string) ([]byte, error) {
	number := new(big.Int)
	base := big.NewInt(58)
	for _, r := range text {
		index := strings.IndexRune(base58Alphabet, r)
		if index < 0 {
			return nil, fmt.Errorf("not base58")
		}
		number.Mul(number, base).Add(number, big.NewInt(int64(index)))
	}
	leading := len(text) - len(strings.TrimLeft(text, "1"))
	return append(make([]byte, leading), number.Bytes()...), nil
}

// DIDKey is IdentityLinkProtocolService.did(for:) / Identity.did().
func DIDKey(descriptor IdentityPublicKeyDescriptor) (string, error) {
	prefix, ok := didKeyPrefixes[descriptor.CurveType]
	if !ok {
		return "", fail("missingPublicKey", descriptor.UUID)
	}
	return "did:key:z" + Base58Encode(append(append([]byte{}, prefix...), descriptor.PublicKey...)), nil
}

// PublicKeyFromDIDKey returns the curve and raw public key of a did:key.
func PublicKeyFromDIDKey(did string) (string, []byte, error) {
	if !strings.HasPrefix(did, "did:key:z") {
		return "", nil, fmt.Errorf("not a did:key")
	}
	decoded, err := Base58Decode(strings.TrimPrefix(did, "did:key:z"))
	if err != nil {
		return "", nil, err
	}
	for curve, prefix := range didKeyPrefixes {
		if bytes.HasPrefix(decoded, prefix) {
			return curve, decoded[len(prefix):], nil
		}
	}
	return "", nil, fmt.Errorf("unsupported key type")
}

// ---- Dates ---------------------------------------------------------------------

var iso8601Pattern = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(Z|[+-]\d{2}:?\d{2})$`)

// ParseISO8601 accepts what ISO8601DateFormatter accepts by default: whole
// seconds, "Z" or a numeric offset.
func ParseISO8601(text string) (time.Time, bool) {
	match := iso8601Pattern.FindStringSubmatch(text)
	if match == nil {
		return time.Time{}, false
	}
	n := make([]int, 7)
	for i := 1; i <= 6; i++ {
		n[i], _ = strconv.Atoi(match[i])
	}
	moment := time.Date(n[1], time.Month(n[2]), n[3], n[4], n[5], n[6], 0, time.UTC)
	if moment.Year() != n[1] || int(moment.Month()) != n[2] || moment.Day() != n[3] || n[4] > 23 || n[5] > 59 || n[6] > 59 {
		return time.Time{}, false
	}
	if zone := match[7]; zone != "Z" {
		digits := strings.ReplaceAll(zone[1:], ":", "")
		hours, _ := strconv.Atoi(digits[:2])
		minutes, _ := strconv.Atoi(digits[2:])
		offset := time.Duration(hours)*time.Hour + time.Duration(minutes)*time.Minute
		if zone[0] == '+' {
			moment = moment.Add(-offset)
		} else {
			moment = moment.Add(offset)
		}
	}
	return moment, true
}

// ISO8601 is ISO8601DateFormatter().string(from:) in UTC.
func ISO8601(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

func vcEncode(wire map[string]any) ([]byte, error) { return UnescapedSlashJSON(wire) }

// ---- Verifiable credentials ----------------------------------------------------

type VCProof struct {
	Type               string `wire:"type"`
	Created            string `wire:"created"`
	ProofPurpose       string `wire:"proofPurpose"`
	VerificationMethod string `wire:"verificationMethod"`
	SignatureData      []byte `wire:"signatureData"`
}

// ProofTypeFor is VCProof.proofType(for:).
func ProofTypeFor(descriptor IdentityPublicKeyDescriptor) string {
	switch {
	case descriptor.Algorithm == "EdDSA" && descriptor.CurveType == "Curve25519":
		return "Ed25519Signature2020"
	case descriptor.Algorithm == "ECDSA" && descriptor.CurveType == "P256":
		return "EcdsaSecp256r1Signature2019"
	}
	return ""
}

type VCClaim struct {
	Context           []string `wire:"@context,opt"`
	ID                string   `wire:"id"`
	Type              []string `wire:"type"`
	Issuer            any      `wire:"issuer"`
	IssuanceDate      string   `wire:"issuanceDate"`
	CredentialSubject any      `wire:"credentialSubject"`
	Proof             VCProof  `wire:"proof"`
}

func (*VCClaim) ExcludedFromSignature() []string { return []string{"proof"} }

func (c *VCClaim) signedBytes() ([]byte, error) { return c.UnsignedBytes() }

// UnsignedBytes is VCClaim.canonicalUnsignedClaimData.
func (c *VCClaim) UnsignedBytes() ([]byte, error) {
	wire, err := ToWire(c)
	if err != nil {
		return nil, err
	}
	delete(wire, "proof")
	return vcEncode(wire)
}

func (c *VCClaim) subjectObject() (map[string]any, bool) {
	object, ok := c.CredentialSubject.(map[string]any)
	return object, ok
}

// Verify is VCClaim.verify(issuer:).
func (c *VCClaim) Verify(issuer IdentityPublicKeyDescriptor) bool {
	did, err := DIDKey(issuer)
	if err != nil {
		return false
	}
	expected := ProofTypeFor(issuer)
	if text, ok := c.Issuer.(string); !ok || text != did ||
		c.Proof.VerificationMethod != issuer.UUID || c.Proof.ProofPurpose != "assertionMethod" ||
		expected == "" || c.Proof.Type != expected ||
		len(c.Proof.SignatureData) == 0 || len(c.Proof.SignatureData) > 512 {
		return false
	}
	data, err := c.UnsignedBytes()
	return err == nil && VerifySignature(c.Proof.SignatureData, data, issuer)
}

// IssueVCClaim is VCClaim(type:issuerIdentity:subjectIdentity:credentialSubject:)
// followed by generateProof. sign signs the unsigned bytes with the issuer key.
func IssueVCClaim(credentialType string, issuer, subject IdentityPublicKeyDescriptor, credentialSubject map[string]any,
	sign func([]byte) ([]byte, error), claimUUID string, issuedAt time.Time) (*VCClaim, error) {
	proofType := ProofTypeFor(issuer)
	if proofType == "" {
		return nil, fail("missingPublicKey", issuer.UUID)
	}
	issuerDID, err := DIDKey(issuer)
	if err != nil {
		return nil, err
	}
	subjectDID, err := DIDKey(subject)
	if err != nil {
		return nil, err
	}
	body := make(map[string]any, len(credentialSubject)+1)
	for key, value := range credentialSubject {
		body[key] = value
	}
	body["id"] = subjectDID
	claim := &VCClaim{
		Context:           append([]string{}, vcContext...),
		ID:                "cell:///identity/" + subject.UUID + "/claims/" + claimUUID,
		Type:              []string{"VerifiableCredential", credentialType},
		Issuer:            issuerDID,
		IssuanceDate:      ISO8601(issuedAt),
		CredentialSubject: body,
		Proof:             VCProof{Type: proofType, Created: ISO8601(issuedAt), ProofPurpose: "assertionMethod", VerificationMethod: issuer.UUID},
	}
	data, err := claim.UnsignedBytes()
	if err != nil {
		return nil, err
	}
	if claim.Proof.SignatureData, err = sign(data); err != nil {
		return nil, err
	}
	return claim, nil
}

type VCPresentation struct {
	Context              []string                     `wire:"@context,opt"`
	ID                   string                       `wire:"id"`
	Type                 []string                     `wire:"type"`
	Holder               any                          `wire:"holder"`
	Challenge            []byte                       `wire:"challenge,opt"`
	Domain               *string                      `wire:"domain,opt"`
	HolderBinding        *IdentityPublicKeyDescriptor `wire:"holderBinding,opt"`
	VerifiableCredential []VCClaim                    `wire:"verifiableCredential,opt"`
	Proof                VCProof                      `wire:"proof"`
}

func (*VCPresentation) ExcludedFromSignature() []string { return []string{"proof"} }

// Swift encodes verifiableCredential with encode, not encodeIfPresent.
func (p *VCPresentation) afterEncode(wire map[string]any) {
	if _, ok := wire["verifiableCredential"]; !ok {
		wire["verifiableCredential"] = nil
	}
}

func (p *VCPresentation) beforeDecode(map[string]any) {}

func (p *VCPresentation) signedBytes() ([]byte, error) { return p.UnsignedBytes() }

// UnsignedBytes is VCPresentation.canonicalPayloadData.
func (p *VCPresentation) UnsignedBytes() ([]byte, error) {
	wire, err := ToWire(p)
	if err != nil {
		return nil, err
	}
	delete(wire, "proof")
	return vcEncode(wire)
}

// VerifyHolderProof is VCPresentation.verifyHolderProof.
func (p *VCPresentation) VerifyHolderProof(expectedChallenge []byte, expectedDomain string) bool {
	binding := p.HolderBinding
	if p.Challenge == nil || !bytes.Equal(p.Challenge, expectedChallenge) || p.Domain == nil || *p.Domain != expectedDomain ||
		binding == nil || p.Proof.ProofPurpose != "authentication" || p.Proof.VerificationMethod != binding.UUID ||
		len(p.Proof.SignatureData) == 0 {
		return false
	}
	did, err := DIDKey(*binding)
	if err != nil {
		return false
	}
	if holder, ok := p.Holder.(string); !ok || holder != did || p.Proof.Type != ProofTypeFor(*binding) {
		return false
	}
	data, err := p.UnsignedBytes()
	return err == nil && VerifySignature(p.Proof.SignatureData, data, *binding)
}

// BindAndSignPresentation is IdentityLinkProtocolService.makeVerifierBoundPresentation.
func BindAndSignPresentation(credentials []VCClaim, holder IdentityPublicKeyDescriptor, sign func([]byte) ([]byte, error),
	challenge []byte, domain, presentationUUID string, createdAt time.Time) (*VCPresentation, error) {
	proofType := ProofTypeFor(holder)
	if proofType == "" {
		return nil, fail("missingPublicKey", holder.UUID)
	}
	did, err := DIDKey(holder)
	if err != nil {
		return nil, err
	}
	binding := holder
	presentation := &VCPresentation{
		Context:              append([]string{}, vcContext...),
		ID:                   "cell:///identity/" + holder.UUID + "/claims/" + presentationUUID,
		Type:                 []string{"VerifiableCredential", PresentationTypeSameEntity},
		Holder:               did,
		Challenge:            challenge,
		Domain:               &domain,
		HolderBinding:        &binding,
		VerifiableCredential: credentials,
		Proof:                VCProof{Type: proofType, Created: ISO8601(createdAt), ProofPurpose: "authentication", VerificationMethod: holder.UUID},
	}
	data, err := presentation.UnsignedBytes()
	if err != nil {
		return nil, err
	}
	if presentation.Proof.SignatureData, err = sign(data); err != nil {
		return nil, err
	}
	return presentation, nil
}

type SameEntityIdentityLinkCredentialSubject struct {
	ID                       string                      `wire:"id"`
	LinkType                 string                      `wire:"linkType"`
	EntityBinding            EntityBindingDescriptor     `wire:"entityBinding"`
	LinkedIdentity           IdentityPublicKeyDescriptor `wire:"linkedIdentity"`
	ApprovedDomains          []string                    `wire:"approvedDomains"`
	ApprovedIdentityContexts []string                    `wire:"approvedIdentityContexts"`
	ApprovedScopes           []string                    `wire:"approvedScopes"`
	EnrollmentRequestHash    []byte                      `wire:"enrollmentRequestHash"`
	AssuranceSource          string                      `wire:"assuranceSource"`
	AssuranceLevel           string                      `wire:"assuranceLevel"`
	ValidUntil               string                      `wire:"validUntil"`
	RevocationReference      *string                     `wire:"revocationReference,opt"`
}

type IdentityLinkRecord struct {
	LinkID                   string                      `wire:"linkID"`
	EntityBinding            EntityBindingDescriptor     `wire:"entityBinding"`
	LinkedIdentity           IdentityPublicKeyDescriptor `wire:"linkedIdentity"`
	ApprovedDomains          []string                    `wire:"approvedDomains"`
	ApprovedIdentityContexts []string                    `wire:"approvedIdentityContexts"`
	ApprovedScopes           []string                    `wire:"approvedScopes"`
	IssuerIdentityUUID       string                      `wire:"issuerIdentityUUID"`
	IssuerType               string                      `wire:"issuerType"`
	Status                   string                      `wire:"status"`
	LinkedAt                 string                      `wire:"linkedAt"`
	LastUsedAt               *string                     `wire:"lastUsedAt,opt"`
	RevokedAt                *string                     `wire:"revokedAt,opt"`
	RevocationReference      *string                     `wire:"revocationReference,opt"`
}

// IdentityLinkCompletionEnvelope is what identityLinks.completeEnrollment takes.
type IdentityLinkCompletionEnvelope struct {
	Request                       IdentityEnrollmentRequest   `wire:"request"`
	Approval                      IdentityEnrollmentApproval  `wire:"approval"`
	SameEntityCredential          VCClaim                     `wire:"sameEntityCredential"`
	Presentation                  VCPresentation              `wire:"presentation"`
	IssuerIdentity                IdentityPublicKeyDescriptor `wire:"issuerIdentity"`
	ExpectedAudience              string                      `wire:"expectedAudience"`
	ExpectedOrigin                string                      `wire:"expectedOrigin"`
	ExpectedPresentationChallenge []byte                      `wire:"expectedPresentationChallenge"`
	ExpectedPresentationDomain    string                      `wire:"expectedPresentationDomain"`
	RequireFreshAuthEvidence      *bool                       `wire:"requireFreshAuthEvidence,opt"`
}

func (*IdentityLinkCompletionEnvelope) ExcludedFromSignature() []string { return nil }

func (e *IdentityLinkCompletionEnvelope) signedBytes() ([]byte, error) {
	return e.Presentation.UnsignedBytes()
}

// IdentityLinkApprovalEnvelope is what identityLinks.approveEnrollment takes.
type IdentityLinkApprovalEnvelope struct {
	Request                  IdentityEnrollmentRequest      `wire:"request"`
	IssuerType               string                         `wire:"issuerType"`
	ApprovedDomains          []string                       `wire:"approvedDomains,opt"`
	ApprovedIdentityContexts []string                       `wire:"approvedIdentityContexts,opt"`
	ApprovedScopes           []string                       `wire:"approvedScopes,opt"`
	ExpiresAt                *string                        `wire:"expiresAt,opt"`
	JTI                      *string                        `wire:"jti,opt"`
	FreshAuthRequired        bool                           `wire:"freshAuthRequired"`
	FreshAuthPerformedAt     *string                        `wire:"freshAuthPerformedAt,opt"`
	FreshAuthEvidence        *IdentityLinkFreshAuthEvidence `wire:"freshAuthEvidence,opt"`
	RevocationReference      *string                        `wire:"revocationReference,opt"`
}

// IdentityLinkApprovalPackage is what the approver hands back.
type IdentityLinkApprovalPackage struct {
	Approval             IdentityEnrollmentApproval  `wire:"approval"`
	SameEntityCredential VCClaim                     `wire:"sameEntityCredential"`
	IssuerIdentity       IdentityPublicKeyDescriptor `wire:"issuerIdentity"`
}

// CompletionResult is IdentityLinkCompletionResult.
type CompletionResult struct {
	Record         IdentityLinkRecord
	RequestHash    []byte
	ApprovalJTI    string
	CredentialID   string
	PresentationID string
}

// ---- IdentityLinkProtocolService -------------------------------------------------

func ensureNotExpired(expiresAt string, now time.Time) error {
	moment, ok := ParseISO8601(expiresAt)
	if !ok {
		return fail("invalidExpiry", expiresAt)
	}
	if moment.Before(now) {
		return fail("expired", expiresAt)
	}
	return nil
}

func ensureSubset(approved, requested []string, label string) error {
	allowed := map[string]bool{}
	for _, item := range requested {
		allowed[item] = true
	}
	var unknown []string
	for _, item := range approved {
		if !allowed[item] {
			unknown = append(unknown, item)
		}
	}
	if len(unknown) > 0 {
		return fail("scopeEscalation", label+": "+strings.Join(unknown, ","))
	}
	return nil
}

func sameBinding(a EntityBindingDescriptor, b *EntityBindingDescriptor) bool {
	if b == nil {
		return false
	}
	eq := func(x, y *string) bool { return (x == nil && y == nil) || (x != nil && y != nil && *x == *y) }
	return a.Mode == b.Mode && eq(a.EntityAnchorReference, b.EntityAnchorReference) && eq(a.BindingID, b.BindingID) && eq(a.Audience, b.Audience)
}

// ValidateEnrollmentRequest is IdentityLinkProtocolService.validateEnrollmentRequest;
// it returns the request hash.
func ValidateEnrollmentRequest(request *IdentityEnrollmentRequest, now time.Time) ([]byte, error) {
	if request.Purpose != "link_identity" {
		return nil, fail("invalidPurpose", request.Purpose)
	}
	if request.EntityBinding == nil {
		return nil, fail("missingEntityBinding")
	}
	if len(request.Nonce) < 16 {
		return nil, fail("invalidNonce")
	}
	if strings.TrimSpace(request.Audience) == "" || strings.TrimSpace(request.Origin) == "" ||
		len(request.RequestedDomains) == 0 || len(request.RequestedIdentityContexts) == 0 || len(request.RequestedScopes) == 0 {
		return nil, fail("missingRequiredContext", "request")
	}
	if err := ensureNotExpired(request.ExpiresAt, now); err != nil {
		return nil, err
	}
	proof := request.Proof
	if proof == nil || len(proof.Signature) == 0 {
		return nil, fail("missingRequestProof")
	}
	identity := request.NewIdentity
	if proof.ByIdentityUUID != identity.UUID || proof.Algorithm != identity.Algorithm || proof.CurveType != identity.CurveType {
		return nil, fail("identityMismatch", "request proof does not match new identity")
	}
	payload, err := SignedBytes(request)
	if err != nil {
		return nil, err
	}
	if !VerifySignature(proof.Signature, payload, identity) {
		return nil, fail("invalidRequestSignature")
	}
	return SHA256(payload), nil
}

// FreshAuthVerifier checks fresh-auth evidence when the envelope requires it.
type FreshAuthVerifier func(*IdentityEnrollmentApproval) bool

func validateApproval(e *IdentityLinkCompletionEnvelope, hash []byte, now time.Time, usedJTIs map[string]bool, verifier FreshAuthVerifier) error {
	approval, request, issuer := &e.Approval, &e.Request, e.IssuerIdentity
	switch {
	case approval.Purpose != "approve_link_identity":
		return fail("invalidPurpose", approval.Purpose)
	case !bytes.Equal(approval.RequestHash, hash):
		return fail("requestHashMismatch")
	case !approval.SubjectIdentity.SameKey(request.NewIdentity):
		return fail("identityMismatch", "approval subject does not match request identity")
	case !sameBinding(approval.EntityBinding, request.EntityBinding):
		return fail("identityMismatch", "approval entity binding does not match request")
	case approval.Audience != request.Audience || approval.Audience != e.ExpectedAudience:
		return fail("audienceMismatch")
	case approval.Origin != request.Origin || approval.Origin != e.ExpectedOrigin:
		return fail("originMismatch")
	case strings.TrimSpace(approval.JTI) == "":
		return fail("missingRequiredContext", "approval.jti")
	case usedJTIs[approval.JTI]:
		return fail("replayDetected", approval.JTI)
	case !issuerTypes[approval.IssuerType]:
		return fail("issuerTypeNotAllowed", approval.IssuerType)
	case approval.IssuerIdentityUUID == request.NewIdentity.UUID || issuer.SameKey(request.NewIdentity):
		return fail("sameKeyOnBothSides")
	// Policy default: requireFreshApprovalAuth = true.
	case !approval.FreshAuthRequired || approval.FreshAuthPerformedAt == nil:
		return fail("missingFreshAuth")
	}
	if e.RequireFreshAuthEvidence != nil && *e.RequireFreshAuthEvidence {
		evidence := approval.FreshAuthEvidence
		switch {
		case evidence == nil:
			return fail("missingFreshAuth")
		case !bytes.Equal(evidence.Challenge, hash):
			return fail("invalidFreshAuthEvidence", "challenge does not match request hash")
		case verifier == nil:
			return fail("invalidFreshAuthEvidence", "no verifier available")
		case !verifier(approval):
			return fail("invalidFreshAuthEvidence", "verifier rejected evidence")
		}
	}
	if err := ensureNotExpired(approval.ExpiresAt, now); err != nil {
		return err
	}
	if err := ensureSubset(approval.ApprovedDomains, request.RequestedDomains, "domains"); err != nil {
		return err
	}
	if err := ensureSubset(approval.ApprovedIdentityContexts, request.RequestedIdentityContexts, "identityContexts"); err != nil {
		return err
	}
	if err := ensureSubset(approval.ApprovedScopes, request.RequestedScopes, "scopes"); err != nil {
		return err
	}
	proof := approval.Proof
	if proof == nil || len(proof.Signature) == 0 {
		return fail("missingApprovalProof")
	}
	if proof.IssuerIdentityUUID != issuer.UUID || proof.IssuerType != approval.IssuerType ||
		proof.Algorithm != issuer.Algorithm || proof.CurveType != issuer.CurveType || approval.IssuerIdentityUUID != issuer.UUID {
		return fail("issuerMismatch")
	}
	payload, err := SignedBytes(approval)
	if err != nil || !VerifySignature(proof.Signature, payload, issuer) {
		return fail("invalidApprovalSignature")
	}
	return nil
}

func validateCredential(e *IdentityLinkCompletionEnvelope, hash []byte, now time.Time) (*SameEntityIdentityLinkCredentialSubject, error) {
	credential, request, approval, issuer := &e.SameEntityCredential, &e.Request, &e.Approval, e.IssuerIdentity
	found := false
	for _, item := range credential.Type {
		found = found || item == CredentialTypeSameEntity
	}
	if !found {
		return nil, fail("invalidCredentialType")
	}
	issuerDID, err := DIDKey(issuer)
	if text, ok := credential.Issuer.(string); err != nil || !ok || text != issuerDID {
		return nil, fail("issuerMismatch")
	}
	if !credential.Verify(issuer) {
		return nil, fail("invalidCredentialSignature")
	}
	var subject SameEntityIdentityLinkCredentialSubject
	if err := FromWire(credential.CredentialSubject, &subject); err != nil {
		return nil, fail("invalidCredentialSubject", "decode")
	}
	if subject.LinkType != "same_entity" {
		return nil, fail("invalidCredentialSubject", "linkType")
	}
	if holderDID, err := DIDKey(request.NewIdentity); err != nil || subject.ID != holderDID {
		return nil, fail("holderMismatch")
	}
	if !subject.LinkedIdentity.SameKey(request.NewIdentity) {
		return nil, fail("identityMismatch", "credential linked identity")
	}
	if !sameBinding(subject.EntityBinding, &approval.EntityBinding) || !bytes.Equal(subject.EnrollmentRequestHash, hash) ||
		!sameStrings(subject.ApprovedDomains, approval.ApprovedDomains) ||
		!sameStrings(subject.ApprovedIdentityContexts, approval.ApprovedIdentityContexts) ||
		!sameStrings(subject.ApprovedScopes, approval.ApprovedScopes) {
		return nil, fail("invalidCredentialSubject", "approval linkage")
	}
	if err := ensureNotExpired(subject.ValidUntil, now); err != nil {
		return nil, err
	}
	return &subject, nil
}

func validatePresentation(e *IdentityLinkCompletionEnvelope) error {
	p, linked := &e.Presentation, e.Request.NewIdentity
	typed := false
	for _, item := range p.Type {
		typed = typed || item == PresentationTypeSameEntity
	}
	carries := false
	for _, item := range p.VerifiableCredential {
		carries = carries || item.ID == e.SameEntityCredential.ID
	}
	linkedDID, err := DIDKey(linked)
	holder, isText := p.Holder.(string)
	if !typed || !carries || p.HolderBinding == nil || !p.HolderBinding.SameKey(linked) || err != nil || !isText || holder != linkedDID {
		return fail("holderMismatch")
	}
	if !p.VerifyHolderProof(e.ExpectedPresentationChallenge, e.ExpectedPresentationDomain) {
		return fail("invalidPresentation")
	}
	return nil
}

// VerifyCompletion is IdentityLinkProtocolService.verifyCompletion: all four
// pieces, in Swift's order.
func VerifyCompletion(e *IdentityLinkCompletionEnvelope, now time.Time, usedApprovalJTIs map[string]bool, verifier FreshAuthVerifier) (*CompletionResult, error) {
	hash, err := ValidateEnrollmentRequest(&e.Request, now)
	if err != nil {
		return nil, err
	}
	if err := validateApproval(e, hash, now, usedApprovalJTIs, verifier); err != nil {
		return nil, err
	}
	subject, err := validateCredential(e, hash, now)
	if err != nil {
		return nil, err
	}
	if err := validatePresentation(e); err != nil {
		return nil, err
	}
	record := IdentityLinkRecord{
		LinkID:                   e.Approval.ApprovalID,
		EntityBinding:            e.Approval.EntityBinding,
		LinkedIdentity:           e.Request.NewIdentity,
		ApprovedDomains:          append([]string{}, e.Approval.ApprovedDomains...),
		ApprovedIdentityContexts: append([]string{}, e.Approval.ApprovedIdentityContexts...),
		ApprovedScopes:           append([]string{}, e.Approval.ApprovedScopes...),
		IssuerIdentityUUID:       e.IssuerIdentity.UUID,
		IssuerType:               e.Approval.IssuerType,
		Status:                   "active",
		LinkedAt:                 ISO8601(now),
		RevocationReference:      subject.RevocationReference,
	}
	return &CompletionResult{
		Record: record, RequestHash: hash, ApprovalJTI: e.Approval.JTI,
		CredentialID: e.SameEntityCredential.ID, PresentationID: e.Presentation.ID,
	}, nil
}

// ApproveEnrollment is IdentityLinkProtocolService.approveEnrollment: the
// existing key approves and issues the same-entity credential. IDs are passed
// in so the caller decides how they are drawn (Swift uses fresh UUIDs).
func ApproveEnrollment(envelope *IdentityLinkApprovalEnvelope, issuer IdentityPublicKeyDescriptor, sign func([]byte) ([]byte, error),
	now time.Time, approvalID, credentialUUID string) (*IdentityLinkApprovalPackage, error) {
	request := &envelope.Request
	hash, err := ValidateEnrollmentRequest(request, now)
	if err != nil {
		return nil, err
	}
	expiry := now.Add(300 * time.Second)
	if envelope.ExpiresAt != nil {
		parsed, ok := ParseISO8601(*envelope.ExpiresAt)
		if !ok {
			return nil, fail("invalidExpiry", *envelope.ExpiresAt)
		}
		expiry = parsed
	}
	performed := envelope.FreshAuthPerformedAt
	if performed != nil {
		if _, ok := ParseISO8601(*performed); !ok {
			return nil, fail("invalidExpiry", *performed)
		}
	} else if envelope.FreshAuthRequired {
		text := ISO8601(now)
		performed = &text
	}
	pick := func(chosen, requested []string) []string {
		if chosen != nil {
			return append([]string{}, chosen...)
		}
		return append([]string{}, requested...)
	}
	jti := approvalID
	if envelope.JTI != nil {
		jti = *envelope.JTI
	}
	var method *string
	if envelope.FreshAuthRequired {
		text := "local-user-presence"
		method = &text
	}
	approval := IdentityEnrollmentApproval{
		Version: 1, ApprovalID: approvalID, Purpose: "approve_link_identity", RequestHash: hash,
		EntityBinding: *request.EntityBinding, SubjectIdentity: request.NewIdentity,
		ApprovedDomains:          pick(envelope.ApprovedDomains, request.RequestedDomains),
		ApprovedIdentityContexts: pick(envelope.ApprovedIdentityContexts, request.RequestedIdentityContexts),
		ApprovedScopes:           pick(envelope.ApprovedScopes, request.RequestedScopes),
		IssuerIdentityUUID:       issuer.UUID, IssuerType: envelope.IssuerType,
		Audience: request.Audience, Origin: request.Origin,
		CreatedAt: ISO8601(now), ExpiresAt: ISO8601(expiry), JTI: jti,
		FreshAuthRequired: envelope.FreshAuthRequired, FreshAuthMethod: method,
		FreshAuthPerformedAt: performed, FreshAuthEvidence: envelope.FreshAuthEvidence,
		Proof: &IdentityEnrollmentApprovalProof{
			Type: "signature", IssuerIdentityUUID: issuer.UUID, IssuerType: envelope.IssuerType,
			Algorithm: issuer.Algorithm, CurveType: issuer.CurveType,
		},
	}
	payload, err := SignedBytes(&approval)
	if err != nil {
		return nil, err
	}
	if approval.Proof.Signature, err = sign(payload); err != nil {
		return nil, err
	}
	source, level := "possession_only", "medium"
	if approval.FreshAuthRequired {
		source, level = "fresh_auth_and_possession", "high"
	}
	holderDID, err := DIDKey(request.NewIdentity)
	if err != nil {
		return nil, err
	}
	subject := SameEntityIdentityLinkCredentialSubject{
		ID: holderDID, LinkType: "same_entity", EntityBinding: approval.EntityBinding, LinkedIdentity: request.NewIdentity,
		ApprovedDomains: approval.ApprovedDomains, ApprovedIdentityContexts: approval.ApprovedIdentityContexts,
		ApprovedScopes: approval.ApprovedScopes, EnrollmentRequestHash: hash,
		AssuranceSource: source, AssuranceLevel: level, ValidUntil: ISO8601(expiry),
		RevocationReference: envelope.RevocationReference,
	}
	subjectWire, err := ToWire(&subject)
	if err != nil {
		return nil, err
	}
	credential, err := IssueVCClaim(CredentialTypeSameEntity, issuer, request.NewIdentity, subjectWire, sign, credentialUUID, now)
	if err != nil {
		return nil, err
	}
	return &IdentityLinkApprovalPackage{Approval: approval, SameEntityCredential: *credential, IssuerIdentity: issuer}, nil
}

// ---- Genesis seal (EntityGenesis.swift) -----------------------------------------

const (
	SealKeypath       = "identityLinks.genesis"
	RecordsKeypath    = "identityLinks.records"
	GenesisLinkPrefix = "genesis-"
	AnchorReference   = "cell:///EntityAnchor"
	SameEntityScope   = "same_entity"
)

var GenesisTriggers = []string{"onboarding", "addressBookImport", "verifiableCredential", "fileUpload", "directEdit", "firstPersist"}

// EntityGenesisSeal is stored at identityLinks.genesis; its presence means the
// anchor is sealed.
type EntityGenesisSeal struct {
	Version               int64                            `wire:"version"`
	AnchorID              string                           `wire:"anchorID"`
	SealedAt              string                           `wire:"sealedAt"`
	Trigger               string                           `wire:"trigger"`
	LinkID                string                           `wire:"linkID"`
	InitiatorIdentityUUID string                           `wire:"initiatorIdentityUUID"`
	Proof                 *IdentityEnrollmentApprovalProof `wire:"proof,opt"`
}

func (*EntityGenesisSeal) ExcludedFromSignature() []string { return []string{"proof"} }

func GenesisLinkID(anchorID string) string { return GenesisLinkPrefix + anchorID }

func IsGenesisLink(linkID string) bool { return strings.HasPrefix(linkID, GenesisLinkPrefix) }

func IsImmutableGenesisKeypath(keypath string) bool {
	return keypath == SealKeypath || strings.HasPrefix(keypath, SealKeypath+".")
}

var unsafeRecordKey = regexp.MustCompile(`[^A-Za-z0-9_-]`)

func SafeRecordKey(linkID string) string { return unsafeRecordKey.ReplaceAllString(linkID, "_") }

func RecordKeypath(linkID string) string { return RecordsKeypath + "." + SafeRecordKey(linkID) }

func GenesisRecord(anchorID string, initiator IdentityPublicKeyDescriptor, identityDomain, sealedAt string) IdentityLinkRecord {
	reference := AnchorReference
	return IdentityLinkRecord{
		LinkID:                   GenesisLinkID(anchorID),
		EntityBinding:            EntityBindingDescriptor{Mode: "localEntityAnchor", EntityAnchorReference: &reference},
		LinkedIdentity:           initiator,
		ApprovedDomains:          []string{identityDomain},
		ApprovedIdentityContexts: []string{},
		ApprovedScopes:           []string{SameEntityScope},
		IssuerIdentityUUID:       initiator.UUID,
		IssuerType:               "existingDevice",
		Status:                   "active",
		LinkedAt:                 sealedAt,
	}
}

// SealGenesis is EntityGenesisService.seal. The caller must already have
// proven that initiator owns the anchor.
func SealGenesis(anchorID string, initiator IdentityPublicKeyDescriptor, sign func([]byte) ([]byte, error),
	identityDomain, trigger string, now time.Time) (*EntityGenesisSeal, *IdentityLinkRecord, error) {
	known := false
	for _, t := range GenesisTriggers {
		known = known || t == trigger
	}
	if !known {
		return nil, nil, fail("invalidTrigger", trigger)
	}
	seal := &EntityGenesisSeal{
		Version: 1, AnchorID: anchorID, SealedAt: ISO8601(now), Trigger: trigger,
		LinkID: GenesisLinkID(anchorID), InitiatorIdentityUUID: initiator.UUID,
		Proof: &IdentityEnrollmentApprovalProof{Type: "signature", IssuerIdentityUUID: initiator.UUID, IssuerType: "existingDevice",
			Algorithm: initiator.Algorithm, CurveType: initiator.CurveType},
	}
	payload, err := SignedBytes(seal)
	if err != nil {
		return nil, nil, err
	}
	if seal.Proof.Signature, err = sign(payload); err != nil {
		return nil, nil, err
	}
	record := GenesisRecord(anchorID, initiator, identityDomain, seal.SealedAt)
	return seal, &record, nil
}

// VerifyGenesis is EntityGenesisService.verify: both come from storage, so
// neither is trusted on its own.
func VerifyGenesis(seal *EntityGenesisSeal, record *IdentityLinkRecord) error {
	switch {
	case seal.LinkID != record.LinkID:
		return fail("sealDoesNotMatchRecord", "linkID")
	case seal.InitiatorIdentityUUID != record.LinkedIdentity.UUID || seal.InitiatorIdentityUUID != record.IssuerIdentityUUID:
		return fail("sealDoesNotMatchRecord", "initiator")
	case record.EntityBinding.Mode != "localEntityAnchor":
		return fail("sealDoesNotMatchRecord", "entityBinding")
	case record.IssuerType != "existingDevice" || record.Status != "active":
		return fail("sealDoesNotMatchRecord", "record")
	case seal.Proof == nil || seal.Proof.Signature == nil:
		return fail("sealProofInvalid")
	}
	payload, err := SignedBytes(seal)
	if err != nil || !VerifySignature(seal.Proof.Signature, payload, record.LinkedIdentity) {
		return fail("sealProofInvalid")
	}
	return nil
}
