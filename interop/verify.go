// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package interop

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

// Verdict codes are the Swift ones, so Go, Python and Swift nodes can be
// compared case by case against fixtures/interop/v1:
// HavenInviteVerifier and HavenInvitePublicationVerifier.Failure codes for
// invitations, ChatInvitationProofUtilityError case names for chat, and
// IdentitySigningChallengeError case names for the bridge proof.

// Failure is a refusal with the Swift code for the same refusal.
type Failure struct {
	Code   string
	Detail string
}

func (f *Failure) Error() string {
	if f.Detail == "" {
		return f.Code
	}
	return f.Code + ": " + f.Detail
}

func fail(code string, detail ...string) error {
	return &Failure{Code: code, Detail: strings.Join(detail, " ")}
}

// VerdictOf returns "valid" for nil and the Swift code for a Failure.
func VerdictOf(err error) string {
	if err == nil {
		return "valid"
	}
	var failure *Failure
	if errors.As(err, &failure) {
		return failure.Code
	}
	return err.Error()
}

func jsonNumber(i int) json.Number { return json.Number(strconv.Itoa(i)) }

// SHA256 returns the digest as bytes.
func SHA256(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

// VerifySignature is IdentityPublicKeySignatureVerifier.verify for Ed25519.
func VerifySignature(signature, message []byte, descriptor IdentityPublicKeyDescriptor) bool {
	if signature == nil || descriptor.Algorithm != "EdDSA" || descriptor.CurveType != "Curve25519" {
		return false
	}
	if len(descriptor.PublicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(descriptor.PublicKey), message, signature)
}

// Sign signs model's canonical bytes and stores the proof Swift expects.
// Approval and revocation proofs need their issuer type set before signing.
func Sign(model Model, key ed25519.PrivateKey, signerUUID string) error {
	payload, err := SignedBytes(model)
	if err != nil {
		return err
	}
	signature := ed25519.Sign(key, payload)
	haven := &HavenSignatureProof{Type: "signature", ByIdentityUUID: signerUUID, Algorithm: "EdDSA", CurveType: "Curve25519", Signature: signature}
	plain := &SignatureProof{Type: "signature", ByIdentityUUID: signerUUID, Algorithm: "EdDSA", CurveType: "Curve25519", Signature: signature}
	switch m := model.(type) {
	case *HavenInviteTicket:
		m.Proof = haven
	case *HavenInvitePublication:
		m.Proof = haven
	case *HavenInviteReply:
		m.Proof = haven
	case *HavenInviteRevocationNotice:
		m.Proof = haven
	case *HavenInviteContactRequest:
		m.Proof = haven
	case *IdentityEnrollmentRequest:
		m.Proof = plain
	case *ChatInvitationArtifact:
		m.Proof = plain
	case *ChatInvitationAcceptance:
		m.Proof = plain
	case *IdentityEnrollmentApproval:
		if m.Proof == nil {
			return fail("unsigned", "set the approval proof's issuer type before signing")
		}
		m.Proof.Signature = signature
	case *IdentityLinkRevocation:
		if m.Proof == nil {
			return fail("unsigned", "set the revocation proof's issuer type before signing")
		}
		m.Proof.Signature = signature
	default:
		return fail("unsupported", "not a signed envelope")
	}
	return nil
}

func epoch(t time.Time) float64 { return float64(t.UnixNano()) / 1e9 }

func parseISO(value string) (time.Time, bool) {
	for _, layout := range []string{"2006-01-02T15:04:05.999999999Z07:00", time.RFC3339} {
		if parsed, err := time.Parse(layout, strings.TrimSpace(value)); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}

// ---- Entity extension ------------------------------------------------------

// RequestHash is SHA-256 of the request's canonical bytes.
func RequestHash(request *IdentityEnrollmentRequest) ([]byte, error) {
	payload, err := SignedBytes(request)
	if err != nil {
		return nil, err
	}
	return SHA256(payload), nil
}

func VerifyEnrollmentRequest(request *IdentityEnrollmentRequest) error {
	if request.Proof == nil || request.Proof.Signature == nil {
		return fail("unsigned")
	}
	if request.Proof.ByIdentityUUID != request.NewIdentity.UUID {
		return fail("issuer_mismatch")
	}
	payload, err := SignedBytes(request)
	if err != nil {
		return err
	}
	if !VerifySignature(request.Proof.Signature, payload, request.NewIdentity) {
		return fail("bad_signature")
	}
	return nil
}

func VerifyEnrollmentApproval(approval *IdentityEnrollmentApproval, issuer IdentityPublicKeyDescriptor, request *IdentityEnrollmentRequest) error {
	if approval.Proof == nil || approval.Proof.Signature == nil {
		return fail("unsigned")
	}
	if approval.Proof.IssuerIdentityUUID != issuer.UUID || approval.IssuerIdentityUUID != issuer.UUID {
		return fail("issuer_mismatch")
	}
	payload, err := SignedBytes(approval)
	if err != nil {
		return err
	}
	if !VerifySignature(approval.Proof.Signature, payload, issuer) {
		return fail("bad_signature")
	}
	if request != nil {
		hash, err := RequestHash(request)
		if err != nil {
			return err
		}
		if string(hash) != string(approval.RequestHash) {
			return fail("request_hash_mismatch")
		}
		if !approval.SubjectIdentity.SameKey(request.NewIdentity) {
			return fail("subject_mismatch")
		}
	}
	return nil
}

func VerifyLinkRevocation(revocation *IdentityLinkRevocation, issuer IdentityPublicKeyDescriptor) error {
	if revocation.Proof == nil || revocation.Proof.Signature == nil {
		return fail("unsigned")
	}
	if revocation.Proof.IssuerIdentityUUID != issuer.UUID || revocation.RevokedByIdentityUUID != issuer.UUID {
		return fail("issuer_mismatch")
	}
	payload, err := SignedBytes(revocation)
	if err != nil {
		return err
	}
	if !VerifySignature(revocation.Proof.Signature, payload, issuer) {
		return fail("bad_signature")
	}
	return nil
}

// ---- Invitation ------------------------------------------------------------

// TicketOptions narrows VerifyTicket.
type TicketOptions struct {
	RevokedTicketIDs      map[string]bool
	ExpectedAudienceToken *string
}

// VerifyTicket is HavenInviteVerifier.verify(...).code.
func VerifyTicket(ticket *HavenInviteTicket, now time.Time, options TicketOptions) string {
	if ticket.Proof == nil || ticket.Proof.Signature == nil {
		return "unsigned"
	}
	if ticket.Proof.ByIdentityUUID != ticket.Issuer.UUID {
		return "issuer_mismatch"
	}
	payload, err := SignedBytes(ticket)
	if err != nil {
		return "uncanonical"
	}
	if !VerifySignature(ticket.Proof.Signature, payload, ticket.Issuer) {
		return "bad_signature"
	}
	if ticket.ClaimsTooLongALife() {
		return "ttl_too_long"
	}
	if options.RevokedTicketIDs[ticket.TicketID] {
		return "revoked"
	}
	if ticket.IsExpired(epoch(now)) {
		return "expired"
	}
	if options.ExpectedAudienceToken != nil && *options.ExpectedAudienceToken != ticket.AudienceToken {
		return "wrong_audience"
	}
	return "valid"
}

func verifyEnvelope(envelope Model, proof *HavenSignatureProof, descriptor IdentityPublicKeyDescriptor) error {
	if proof == nil || proof.Signature == nil {
		return fail("unsigned")
	}
	if proof.ByIdentityUUID != descriptor.UUID {
		return fail("issuer_mismatch")
	}
	payload, err := SignedBytes(envelope)
	if err != nil {
		return err
	}
	if !VerifySignature(proof.Signature, payload, descriptor) {
		return fail("bad_signature")
	}
	return nil
}

// VerifyPublication is HavenInvitePublicationVerifier.verifyPublication.
func VerifyPublication(publication *HavenInvitePublication, now time.Time) (*HavenInviteTicket, error) {
	ticket, err := TicketFromToken(publication.TicketToken)
	if err != nil {
		return nil, fail("ticket_invalid:malformed_payload", err.Error())
	}
	switch VerifyTicket(ticket, now, TicketOptions{}) {
	case "unsigned", "issuer_mismatch", "bad_signature", "uncanonical":
		return nil, fail("bad_signature")
	}
	if ticket.IsExpired(epoch(now)) {
		return nil, fail("ticket_expired")
	}
	if ticket.ClaimsTooLongALife() {
		return nil, fail("ticket_invalid:ttl_too_long")
	}
	switch {
	case publication.ExpiresAt != ticket.ExpiresAt:
		return nil, fail("ticket_mismatch", "expiresAt")
	case ticket.TicketID != publication.TicketID:
		return nil, fail("ticket_mismatch", "ticketID")
	case ticket.HumanCode != publication.HumanCode:
		return nil, fail("ticket_mismatch", "humanCode")
	case ticket.AudienceToken != publication.AudienceToken:
		return nil, fail("ticket_mismatch", "audienceToken")
	case ticket.Issuer.UUID != publication.IssuerIdentityUUID:
		return nil, fail("issuer_mismatch")
	}
	if err := verifyEnvelope(publication, publication.Proof, ticket.Issuer); err != nil {
		return nil, err
	}
	return ticket, nil
}

func VerifyRevocationNotice(notice *HavenInviteRevocationNotice, ticket *HavenInviteTicket) error {
	if notice.TicketID != ticket.TicketID {
		return fail("ticket_mismatch", "ticketID")
	}
	if notice.IssuerIdentityUUID != ticket.Issuer.UUID {
		return fail("issuer_mismatch")
	}
	return verifyEnvelope(notice, notice.Proof, ticket.Issuer)
}

func VerifyContactRequest(request *HavenInviteContactRequest, ticket *HavenInviteTicket, now time.Time) error {
	if request.TicketID != ticket.TicketID {
		return fail("ticket_mismatch", "ticketID")
	}
	if ticket.IssuerContactEndpoint == nil || request.IssuerEndpointID != *ticket.IssuerContactEndpoint {
		return fail("ticket_mismatch", "issuerEndpointID")
	}
	if epoch(now) > float64(request.ExpiresAt) {
		return fail("expired")
	}
	if ticket.IsExpired(epoch(now)) {
		return fail("ticket_expired")
	}
	if request.Sender.UUID == ticket.Issuer.UUID {
		return fail("issuer_mismatch")
	}
	return verifyEnvelope(request, request.Proof, request.Sender)
}

func VerifyReply(reply *HavenInviteReply, ticket *HavenInviteTicket, now time.Time) error {
	if reply.TicketID != ticket.TicketID {
		return fail("ticket_mismatch", "ticketID")
	}
	if reply.AudienceToken != ticket.AudienceToken {
		return fail("ticket_mismatch", "audienceToken")
	}
	if ticket.IsExpired(epoch(now)) {
		return fail("ticket_expired")
	}
	if reply.Replier.UUID == ticket.Issuer.UUID {
		return fail("issuer_mismatch")
	}
	return verifyEnvelope(reply, reply.Proof, reply.Replier)
}

// ---- Chat ------------------------------------------------------------------

// InvitationHash is SHA-256 of the artifact's canonical bytes.
func InvitationHash(artifact *ChatInvitationArtifact) ([]byte, error) {
	payload, err := SignedBytes(artifact)
	if err != nil {
		return nil, err
	}
	return SHA256(payload), nil
}

func validateNonce(nonce []byte) error {
	if len(nonce) < SigningChallengeMinimumNonce || len(nonce) > SigningChallengeMaximumNonce {
		return fail("invalidNonce")
	}
	return nil
}

func skew() time.Duration { return time.Duration(SigningChallengeClockSkew) * time.Second }

// ChatOptions narrows VerifyChatInvitation.
type ChatOptions struct {
	ExpectedChatCellUUID *string
	ExpectedInviterUUID  *string
}

// VerifyChatInvitation is ChatInvitationProofUtility.verifyInvitationArtifact.
func VerifyChatInvitation(artifact *ChatInvitationArtifact, now time.Time, options ChatOptions) error {
	if artifact.Version != 1 {
		return fail("unsupportedVersion")
	}
	if artifact.Purpose != "chat_invitation" {
		return fail("invalidPurpose")
	}
	if err := validateNonce(artifact.Nonce); err != nil {
		return err
	}
	created, okCreated := parseISO(artifact.CreatedAt)
	expires, okExpires := parseISO(artifact.ExpiresAt)
	if !okCreated || !okExpires || !expires.After(created) || created.After(now.Add(skew())) {
		return fail("invalidTimestamp")
	}
	if expires.Before(now) {
		return fail("expiredArtifact")
	}
	if options.ExpectedChatCellUUID != nil && artifact.ChatCellUUID != *options.ExpectedChatCellUUID {
		return fail("chatCellMismatch")
	}
	if options.ExpectedInviterUUID != nil && artifact.InviterIdentity.UUID != *options.ExpectedInviterUUID {
		return fail("inviterMismatch")
	}
	proof := artifact.Proof
	if proof == nil || proof.Signature == nil {
		return fail("missingSignature")
	}
	if proof.Type != "signature" {
		return fail("invalidProofType")
	}
	if proof.ByIdentityUUID != artifact.InviterIdentity.UUID || proof.Algorithm != artifact.InviterIdentity.Algorithm || proof.CurveType != artifact.InviterIdentity.CurveType {
		return fail("inviterMismatch")
	}
	payload, err := SignedBytes(artifact)
	if err != nil {
		return err
	}
	if !VerifySignature(proof.Signature, payload, artifact.InviterIdentity) {
		return fail("invalidArtifactProof")
	}
	return nil
}

// VerifyChatAcceptance is ChatInvitationProofUtility.verifyAcceptance.
func VerifyChatAcceptance(acceptance *ChatInvitationAcceptance, artifact *ChatInvitationArtifact, now time.Time, expectedChatCellUUID *string) error {
	inviter := acceptance.InviterIdentityUUID
	if err := VerifyChatInvitation(artifact, now, ChatOptions{ExpectedChatCellUUID: expectedChatCellUUID, ExpectedInviterUUID: &inviter}); err != nil {
		return err
	}
	if acceptance.Version != 1 {
		return fail("unsupportedVersion")
	}
	if acceptance.Purpose != "accept_chat_invitation" {
		return fail("invalidPurpose")
	}
	if err := validateNonce(acceptance.Nonce); err != nil {
		return err
	}
	invited, ok1 := parseISO(artifact.CreatedAt)
	expires, ok2 := parseISO(artifact.ExpiresAt)
	accepted, ok3 := parseISO(acceptance.CreatedAt)
	if !ok1 || !ok2 || !ok3 || accepted.Before(invited.Add(-skew())) || accepted.After(expires) || accepted.After(now.Add(skew())) {
		return fail("invalidTimestamp")
	}
	if acceptance.InvitationID != artifact.InvitationID {
		return fail("invitationHashMismatch")
	}
	if acceptance.ChatCellUUID != artifact.ChatCellUUID {
		return fail("chatCellMismatch")
	}
	if !acceptance.InviteeIdentity.SameKey(artifact.InvitedIdentity) {
		return fail("inviteeMismatch")
	}
	hash, err := InvitationHash(artifact)
	if err != nil {
		return err
	}
	if string(hash) != string(acceptance.InvitationHash) {
		return fail("invitationHashMismatch")
	}
	proof := acceptance.Proof
	if proof == nil || proof.Signature == nil {
		return fail("missingSignature")
	}
	if proof.Type != "signature" {
		return fail("invalidProofType")
	}
	if proof.ByIdentityUUID != acceptance.InviteeIdentity.UUID || proof.Algorithm != acceptance.InviteeIdentity.Algorithm || proof.CurveType != acceptance.InviteeIdentity.CurveType {
		return fail("inviteeMismatch")
	}
	payload, err := SignedBytes(acceptance)
	if err != nil {
		return err
	}
	if !VerifySignature(proof.Signature, payload, acceptance.InviteeIdentity) {
		return fail("invalidAcceptanceProof")
	}
	return nil
}

// ---- Bridge identity proof -------------------------------------------------

// ValidateSigningChallenge is IdentitySigningChallenge.validateSigningData.
func ValidateSigningChallenge(data []byte, identity IdentityPublicKeyDescriptor, now time.Time) (*IdentitySigningChallenge, error) {
	if len(data) > SigningChallengeMaximumBytes {
		return nil, fail("payloadTooLarge")
	}
	var challenge IdentitySigningChallenge
	if err := Decode(data, &challenge); err != nil {
		return nil, fail("invalidPayload", err.Error())
	}
	if challenge.Type != SigningChallengeType {
		return nil, fail("wrongType")
	}
	if challenge.Version != 1 {
		return nil, fail("unsupportedVersion")
	}
	if challenge.Purpose != SigningChallengePurpose {
		return nil, fail("wrongPurpose")
	}
	if challenge.IdentityUUID != identity.UUID {
		return nil, fail("identityMismatch")
	}
	expected := ""
	if challenge.PublicKeyFingerprint != nil {
		expected = strings.TrimSpace(*challenge.PublicKeyFingerprint)
	}
	if expected == "" {
		return nil, fail("missingPublicKeyFingerprint")
	}
	if expected != identity.Fingerprint() {
		return nil, fail("publicKeyMismatch")
	}
	if len(challenge.Nonce) < SigningChallengeMinimumNonce {
		return nil, fail("missingNonce")
	}
	if len(challenge.Nonce) > SigningChallengeMaximumNonce {
		return nil, fail("payloadTooLarge")
	}
	scope := []string{challenge.Domain, challenge.Resource, challenge.Action, challenge.Audience}
	for _, item := range scope {
		if strings.TrimSpace(item) == "" {
			return nil, fail("missingChallengeScope")
		}
	}
	for _, item := range scope {
		if len([]rune(item)) > SigningChallengeMaximumScope {
			return nil, fail("payloadTooLarge")
		}
	}
	if !(challenge.ExpiresAt >= challenge.IssuedAt && challenge.ExpiresAt-challenge.IssuedAt <= SigningChallengeDefaultValidity) {
		return nil, fail("invalidValidity")
	}
	moment := epoch(now)
	if !(challenge.IssuedAt <= moment+SigningChallengeClockSkew) {
		return nil, fail("issuedInFuture")
	}
	if !(challenge.ExpiresAt >= moment) {
		return nil, fail("expired")
	}
	return &challenge, nil
}
