// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package interop

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// Wire models mirroring CellProtocol Swift (Sources/CellBase):
// Identity/IdentityLinkingModels.swift, Identity/IdentitySigningChallenge.swift,
// Invitation/HavenInviteTicket.swift, Invitation/HavenInvitePublication.swift,
// Invitation/HavenInviteReply.swift, Cells/Chat/ChatInvitationProofUtility.swift.

// IdentityPublicKeyDescriptor carries everything needed to verify offline.
type IdentityPublicKeyDescriptor struct {
	UUID        string  `wire:"uuid"`
	DisplayName *string `wire:"displayName,opt"`
	PublicKey   []byte  `wire:"publicKey"`
	Algorithm   string  `wire:"algorithm"`
	CurveType   string  `wire:"curveType"`
}

// SameKey compares the identity and key, ignoring the display name.
func (d IdentityPublicKeyDescriptor) SameKey(other IdentityPublicKeyDescriptor) bool {
	return d.UUID == other.UUID && string(d.PublicKey) == string(other.PublicKey) &&
		d.Algorithm == other.Algorithm && d.CurveType == other.CurveType
}

// Fingerprint is Identity.signingPublicKeyFingerprint in Swift.
func (d IdentityPublicKeyDescriptor) Fingerprint() string {
	return strings.Join([]string{d.Algorithm, d.CurveType, base64.StdEncoding.EncodeToString(d.PublicKey)}, ":")
}

// SignatureProof is the shape of IdentityEnrollmentRequestProof,
// ChatInvitationArtifactProof and ChatInvitationAcceptanceProof.
type SignatureProof struct {
	Type           string `wire:"type"`
	ByIdentityUUID string `wire:"byIdentityUUID"`
	Algorithm      string `wire:"algorithm"`
	CurveType      string `wire:"curveType"`
	Signature      []byte `wire:"signature,opt"`
}

// HavenSignatureProof is the short-keyed proof every invitation type carries.
type HavenSignatureProof struct {
	Type           string `wire:"ty"`
	ByIdentityUUID string `wire:"by"`
	Algorithm      string `wire:"al"`
	CurveType      string `wire:"cv"`
	Signature      []byte `wire:"sg,opt"`
}

// ---- Entity extension ------------------------------------------------------

type EntityBindingDescriptor struct {
	Mode                  string  `wire:"mode"`
	EntityAnchorReference *string `wire:"entityAnchorReference,opt"`
	BindingID             *string `wire:"bindingID,opt"`
	Audience              *string `wire:"audience,opt"`
}

type IdentityEnrollmentRequest struct {
	Version                   int64                       `wire:"version"`
	RequestID                 string                      `wire:"requestID"`
	Purpose                   string                      `wire:"purpose"`
	EntityBinding             *EntityBindingDescriptor    `wire:"entityBinding,opt"`
	NewIdentity               IdentityPublicKeyDescriptor `wire:"newIdentity"`
	RequestedDomains          []string                    `wire:"requestedDomains"`
	RequestedIdentityContexts []string                    `wire:"requestedIdentityContexts"`
	RequestedScopes           []string                    `wire:"requestedScopes"`
	Audience                  string                      `wire:"audience"`
	Origin                    string                      `wire:"origin"`
	CreatedAt                 string                      `wire:"createdAt"`
	ExpiresAt                 string                      `wire:"expiresAt"`
	Nonce                     []byte                      `wire:"nonce"`
	Platform                  *string                     `wire:"platform,opt"`
	DeviceLabel               *string                     `wire:"deviceLabel,opt"`
	Proof                     *SignatureProof             `wire:"proof,opt"`
}

func (*IdentityEnrollmentRequest) ExcludedFromSignature() []string { return []string{"proof"} }

type IdentityEnrollmentApprovalProof struct {
	Type               string `wire:"type"`
	IssuerIdentityUUID string `wire:"issuerIdentityUUID"`
	IssuerType         string `wire:"issuerType"`
	Algorithm          string `wire:"algorithm"`
	CurveType          string `wire:"curveType"`
	Signature          []byte `wire:"signature,opt"`
}

type IdentityLinkFreshAuthEvidence struct {
	Method            string `wire:"method"`
	Challenge         []byte `wire:"challenge"`
	PerformedAt       string `wire:"performedAt"`
	CredentialID      []byte `wire:"credentialID,opt"`
	AuthenticatorData []byte `wire:"authenticatorData,opt"`
	ClientDataJSON    []byte `wire:"clientDataJSON,opt"`
	Signature         []byte `wire:"signature,opt"`
}

type IdentityEnrollmentApproval struct {
	Version                  int64                            `wire:"version"`
	ApprovalID               string                           `wire:"approvalID"`
	Purpose                  string                           `wire:"purpose"`
	RequestHash              []byte                           `wire:"requestHash"`
	EntityBinding            EntityBindingDescriptor          `wire:"entityBinding"`
	SubjectIdentity          IdentityPublicKeyDescriptor      `wire:"subjectIdentity"`
	ApprovedDomains          []string                         `wire:"approvedDomains"`
	ApprovedIdentityContexts []string                         `wire:"approvedIdentityContexts"`
	ApprovedScopes           []string                         `wire:"approvedScopes"`
	IssuerIdentityUUID       string                           `wire:"issuerIdentityUUID"`
	IssuerType               string                           `wire:"issuerType"`
	Audience                 string                           `wire:"audience"`
	Origin                   string                           `wire:"origin"`
	CreatedAt                string                           `wire:"createdAt"`
	ExpiresAt                string                           `wire:"expiresAt"`
	JTI                      string                           `wire:"jti"`
	FreshAuthRequired        bool                             `wire:"freshAuthRequired"`
	FreshAuthMethod          *string                          `wire:"freshAuthMethod,opt"`
	FreshAuthPerformedAt     *string                          `wire:"freshAuthPerformedAt,opt"`
	FreshAuthEvidence        *IdentityLinkFreshAuthEvidence   `wire:"freshAuthEvidence,opt"`
	Proof                    *IdentityEnrollmentApprovalProof `wire:"proof,opt"`
}

func (*IdentityEnrollmentApproval) ExcludedFromSignature() []string { return []string{"proof"} }

type IdentityLinkRevocation struct {
	Version               int64                            `wire:"version"`
	LinkID                string                           `wire:"linkID"`
	Reason                string                           `wire:"reason"`
	RevokedAt             string                           `wire:"revokedAt"`
	RevokedByIdentityUUID string                           `wire:"revokedByIdentityUUID"`
	IssuerType            string                           `wire:"issuerType"`
	Proof                 *IdentityEnrollmentApprovalProof `wire:"proof,opt"`
}

func (*IdentityLinkRevocation) ExcludedFromSignature() []string { return []string{"proof"} }

// ---- Invitation ------------------------------------------------------------

var DefaultTicketCapabilities = []string{"create_own_entity", "send_contact_request_to_issuer"}

const (
	TicketDefaultTTL = 14 * 86_400
	TicketMaximumTTL = 90 * 86_400
)

type HavenInviteBasisField struct {
	Key    string  `wire:"k"`
	Value  string  `wire:"v"`
	Origin *string `wire:"o,opt"`
}

// HavenInviteTicket uses Swift's short coded keys. Basis, nonce and default
// capabilities are left out of the encoding, as Swift does.
type HavenInviteTicket struct {
	Version               int64                       `wire:"v"`
	TicketID              string                      `wire:"t"`
	Issuer                IdentityPublicKeyDescriptor `wire:"is"`
	IssuerDisplayName     string                      `wire:"n"`
	IssuerContactEndpoint *string                     `wire:"ce,opt"`
	IssuerEntityRef       *string                     `wire:"er,opt"`
	AudienceToken         string                      `wire:"au"`
	AudienceKind          string                      `wire:"ak"`
	HumanCode             string                      `wire:"hc"`
	GreetingName          *string                     `wire:"gn,opt"`
	Note                  *string                     `wire:"no,opt"`
	IdentityDomain        *string                     `wire:"id,opt"`
	Basis                 []HavenInviteBasisField     `wire:"bs,opt"`
	CreatedAt             int64                       `wire:"ca"`
	ExpiresAt             int64                       `wire:"ea"`
	Nonce                 []byte                      `wire:"nc,opt"`
	Capabilities          []string                    `wire:"cp,opt"`
	Proof                 *HavenSignatureProof        `wire:"pf,opt"`
}

func (*HavenInviteTicket) ExcludedFromSignature() []string { return []string{"pf"} }

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (t *HavenInviteTicket) afterEncode(wire map[string]any) {
	if len(t.Basis) == 0 {
		delete(wire, "bs")
	}
	if len(t.Nonce) == 0 {
		delete(wire, "nc")
	}
	if t.Capabilities == nil || sameStrings(t.Capabilities, DefaultTicketCapabilities) {
		delete(wire, "cp")
	}
}

func (t *HavenInviteTicket) beforeDecode(wire map[string]any) {
	if wire["v"] == nil {
		wire["v"] = jsonNumber(1)
	}
	if wire["ak"] == nil {
		wire["ak"] = "email"
	}
	if wire["cp"] == nil {
		items := make([]any, len(DefaultTicketCapabilities))
		for i, item := range DefaultTicketCapabilities {
			items[i] = item
		}
		wire["cp"] = items
	}
}

// IsExpired reports whether the ticket has run out at nowEpoch seconds.
func (t *HavenInviteTicket) IsExpired(nowEpoch float64) bool { return nowEpoch > float64(t.ExpiresAt) }

// ClaimsTooLongALife is true when the ticket promises more than 90 days.
func (t *HavenInviteTicket) ClaimsTooLongALife() bool {
	return t.ExpiresAt-t.CreatedAt > TicketMaximumTTL
}

// Token is the long-link form: base64url of JSONEncoder(.sortedKeys), unpadded.
func (t *HavenInviteTicket) Token() (string, error) {
	data, err := EncodedJSON(t)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// TicketFromToken decodes a long-link token.
func TicketFromToken(token string) (*HavenInviteTicket, error) {
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(token, "="))
	if err != nil {
		return nil, fmt.Errorf("interop: malformed ticket token: %w", err)
	}
	var ticket HavenInviteTicket
	if err := Decode(data, &ticket); err != nil {
		return nil, err
	}
	if ticket.Version != 1 {
		return nil, fmt.Errorf("interop: unsupported ticket version %d", ticket.Version)
	}
	return &ticket, nil
}

type HavenInvitePublication struct {
	Schema             string               `wire:"schema"`
	TicketID           string               `wire:"ticketID"`
	HumanCode          string               `wire:"humanCode"`
	TicketToken        string               `wire:"ticketToken"`
	AudienceToken      string               `wire:"audienceToken"`
	IssuerIdentityUUID string               `wire:"issuerIdentityUUID"`
	ExpiresAt          int64                `wire:"expiresAt"`
	PublishedAt        int64                `wire:"publishedAt"`
	MaxContactRequests int64                `wire:"maxContactRequests"`
	StatusKey          string               `wire:"statusKey"`
	Proof              *HavenSignatureProof `wire:"proof,opt"`
}

func (*HavenInvitePublication) ExcludedFromSignature() []string { return []string{"proof"} }

type HavenInviteRevocationNotice struct {
	Schema             string               `wire:"schema"`
	TicketID           string               `wire:"ticketID"`
	Reason             string               `wire:"reason"`
	RevokedAt          int64                `wire:"revokedAt"`
	IssuerIdentityUUID string               `wire:"issuerIdentityUUID"`
	Proof              *HavenSignatureProof `wire:"proof,opt"`
}

func (*HavenInviteRevocationNotice) ExcludedFromSignature() []string { return []string{"proof"} }

type HavenInviteContactRequest struct {
	Schema                string                      `wire:"schema"`
	RequestID             string                      `wire:"requestID"`
	TicketID              string                      `wire:"ticketID"`
	IssuerEndpointID      string                      `wire:"issuerEndpointID"`
	Sender                IdentityPublicKeyDescriptor `wire:"sender"`
	SenderDisplayName     string                      `wire:"senderDisplayName"`
	SenderEntityRef       *string                     `wire:"senderEntityRef,opt"`
	SenderEndpoint        *string                     `wire:"senderEndpoint,opt"`
	Message               *string                     `wire:"message,opt"`
	SenderKeyAgreementKey []byte                      `wire:"senderKeyAgreementKey,opt"`
	CreatedAt             int64                       `wire:"createdAt"`
	ExpiresAt             int64                       `wire:"expiresAt"`
	Nonce                 []byte                      `wire:"nonce"`
	Proof                 *HavenSignatureProof        `wire:"proof,opt"`
}

func (*HavenInviteContactRequest) ExcludedFromSignature() []string { return []string{"proof"} }

type HavenInviteReply struct {
	Schema                 string                      `wire:"schema"`
	ReplyID                string                      `wire:"replyID"`
	TicketID               string                      `wire:"ticketID"`
	AudienceToken          string                      `wire:"audienceToken"`
	Decision               string                      `wire:"decision"` // yes | notNow | never
	Replier                IdentityPublicKeyDescriptor `wire:"replier"`
	ReplierKeyAgreementKey []byte                      `wire:"replierKeyAgreementKey,opt"`
	CreatedAt              int64                       `wire:"createdAt"`
	Nonce                  []byte                      `wire:"nonce"`
	Proof                  *HavenSignatureProof        `wire:"proof,opt"`
}

func (*HavenInviteReply) ExcludedFromSignature() []string { return []string{"proof"} }

// ---- Chat ------------------------------------------------------------------

type ChatInvitationArtifact struct {
	Version         int64                       `wire:"version"`
	InvitationID    string                      `wire:"invitationID"`
	Purpose         string                      `wire:"purpose"`
	ChatCellUUID    string                      `wire:"chatCellUUID"`
	Topic           string                      `wire:"topic"`
	AudienceMode    string                      `wire:"audienceMode"`
	SuiteID         string                      `wire:"suiteID"`
	PersistenceMode string                      `wire:"persistenceMode"`
	InviterIdentity IdentityPublicKeyDescriptor `wire:"inviterIdentity"`
	InvitedIdentity IdentityPublicKeyDescriptor `wire:"invitedIdentity"`
	CreatedAt       string                      `wire:"createdAt"`
	ExpiresAt       string                      `wire:"expiresAt"`
	Nonce           []byte                      `wire:"nonce"`
	Proof           *SignatureProof             `wire:"proof,opt"`
}

func (*ChatInvitationArtifact) ExcludedFromSignature() []string { return []string{"proof"} }

type ChatInvitationAcceptance struct {
	Version                int64                       `wire:"version"`
	AcceptanceID           string                      `wire:"acceptanceID"`
	Purpose                string                      `wire:"purpose"`
	InvitationID           string                      `wire:"invitationID"`
	InvitationHash         []byte                      `wire:"invitationHash"`
	ChatCellUUID           string                      `wire:"chatCellUUID"`
	InviterIdentityUUID    string                      `wire:"inviterIdentityUUID"`
	InviteeIdentity        IdentityPublicKeyDescriptor `wire:"inviteeIdentity"`
	InviteeKeyAgreementKey []byte                      `wire:"inviteeKeyAgreementKey,opt"`
	CreatedAt              string                      `wire:"createdAt"`
	Nonce                  []byte                      `wire:"nonce"`
	Proof                  *SignatureProof             `wire:"proof,opt"`
}

func (*ChatInvitationAcceptance) ExcludedFromSignature() []string { return []string{"proof"} }

// ---- Bridge identity proof -------------------------------------------------

const (
	SigningChallengeType            = "org.haven.cellprotocol.identity-signing-challenge"
	SigningChallengePurpose         = "identity-origin-proof"
	SigningChallengeDefaultValidity = 60.0
	SigningChallengeClockSkew       = 300.0
	SigningChallengeMaximumBytes    = 8 * 1024
	SigningChallengeMinimumNonce    = 32
	SigningChallengeMaximumNonce    = 128
	SigningChallengeMaximumScope    = 512
)

// IdentitySigningChallenge is signed as its whole JSONEncoder(.sortedKeys)
// output; nothing is excluded.
type IdentitySigningChallenge struct {
	Type                 string  `wire:"type"`
	Version              int64   `wire:"version"`
	Purpose              string  `wire:"purpose"`
	IdentityUUID         string  `wire:"identityUUID"`
	PublicKeyFingerprint *string `wire:"publicKeyFingerprint,opt"`
	Domain               string  `wire:"domain"`
	Resource             string  `wire:"resource"`
	Action               string  `wire:"action"`
	Audience             string  `wire:"audience"`
	Nonce                []byte  `wire:"nonce"`
	IssuedAt             float64 `wire:"issuedAt"`
	ExpiresAt            float64 `wire:"expiresAt"`
}

func (*IdentitySigningChallenge) ExcludedFromSignature() []string { return nil }

// NewModel returns an empty model for a Swift type name.
func NewModel(typeName string) (Model, error) {
	switch typeName {
	case "IdentityEnrollmentRequest":
		return &IdentityEnrollmentRequest{}, nil
	case "IdentityEnrollmentApproval":
		return &IdentityEnrollmentApproval{}, nil
	case "IdentityLinkRevocation":
		return &IdentityLinkRevocation{}, nil
	case "HavenInviteTicket":
		return &HavenInviteTicket{}, nil
	case "HavenInvitePublication":
		return &HavenInvitePublication{}, nil
	case "HavenInviteReply":
		return &HavenInviteReply{}, nil
	case "HavenInviteRevocationNotice":
		return &HavenInviteRevocationNotice{}, nil
	case "HavenInviteContactRequest":
		return &HavenInviteContactRequest{}, nil
	case "ChatInvitationArtifact":
		return &ChatInvitationArtifact{}, nil
	case "ChatInvitationAcceptance":
		return &ChatInvitationAcceptance{}, nil
	case "IdentitySigningChallenge":
		return &IdentitySigningChallenge{}, nil
	}
	return nil, fmt.Errorf("interop: unknown type %s", typeName)
}
