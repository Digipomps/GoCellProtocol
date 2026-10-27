// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package interop

// Invitation helpers that give the same bytes and answers as CellBase Swift:
// HavenInviteLink, HavenInviteVerifier.payload, HavenInviteCopy boundary
// lines, HavenInvitePublication.makeStatusKey, HavenInviteStatusReport and
// Binding's disclosureToken, plus builders for the ticket, its publication,
// its revocation notice and the invitee's contact request.
//
// Swift has no builder for the contact request yet (only the scaffold
// receives one). BuildContactRequest follows HavenInviteContactRequest and
// verifyContactRequest exactly, so a Swift scaffold accepts what it builds.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"
)

const (
	InvitePathSegment   = "i"
	InviteCustomScheme  = "haven"
	HumanCodeAlphabet   = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
	HumanCodeLength     = 6
	InviteVerdictSchema = "haven.invite.verdict.v1"
	InviteStatusSchema  = "haven.invite.status.v1"

	InviteBoundaryLine             = "Lenken lar deg opprette din egen entitet i HAVEN og sende meg en kontaktforespørsel tilbake. Den gir ingen tilgang til noe av mitt, og den gir meg ingen tilgang til noe av ditt."
	InviteBoundaryLineWithoutReply = "Lenken lar deg opprette din egen entitet i HAVEN. Den gir ingen tilgang til noe av mitt, og den gir meg ingen tilgang til noe av ditt."
)

// InviteLifecycles are HavenInviteLifecycle's raw values.
var InviteLifecycles = []string{"published", "opened", "accepted", "declined", "expired", "revoked"}

// LinkFailure is HavenInviteLink.Failure with the Swift code.
type LinkFailure struct {
	Code    string
	Message string
}

func (f *LinkFailure) Error() string { return f.Code + ": " + f.Message }

// SignFunc signs bytes with the caller's Ed25519 key.
type SignFunc func([]byte) ([]byte, error)

// ---- HavenInviteLink ---------------------------------------------------------

func SHA256HexString(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

func Base64URLString(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func DataFromBase64URLString(text string) ([]byte, bool) {
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(text, "="))
	return data, err == nil
}

// InviteHumanCode is HavenInviteLink.humanCode(from:).
func InviteHumanCode(seed string) string {
	digest := SHA256HexString(seed)
	var b strings.Builder
	for i := 0; i < HumanCodeLength*2; i += 2 {
		var value byte
		fmt.Sscanf(digest[i:i+2], "%02x", &value)
		b.WriteByte(HumanCodeAlphabet[int(value)%len(HumanCodeAlphabet)])
	}
	return b.String()
}

func LooksLikeHumanCode(candidate string) bool {
	if len(candidate) != HumanCodeLength {
		return false
	}
	for _, r := range candidate {
		if !strings.ContainsRune(HumanCodeAlphabet, r) {
			return false
		}
	}
	return true
}

// DecodeTicketToken is HavenInviteLink.decode with Swift failure codes.
func DecodeTicketToken(token string) (*HavenInviteTicket, error) {
	data, ok := DataFromBase64URLString(token)
	if !ok {
		return nil, &LinkFailure{"malformed_payload", "Lenken inneholder ikke en lesbar invitasjon."}
	}
	var ticket HavenInviteTicket
	if err := Decode(data, &ticket); err != nil {
		return nil, &LinkFailure{"malformed_payload", "Lenken inneholder ikke en lesbar invitasjon."}
	}
	if ticket.Version != 1 {
		return nil, &LinkFailure{"unsupported_version", fmt.Sprintf("Invitasjonen bruker versjon %d, som denne appen ikke kjenner.", ticket.Version)}
	}
	return &ticket, nil
}

func trimBase(base string) string { return strings.Trim(base, " /") }

func UniversalLink(ticket *HavenInviteTicket, landingBase string) string {
	base := trimBase(landingBase)
	token, err := ticket.Token()
	if base == "" || err != nil {
		return ""
	}
	return base + "/" + InvitePathSegment + "/" + token
}

func AppLink(ticket *HavenInviteTicket) string {
	token, _ := ticket.Token()
	return InviteCustomScheme + "://invite/" + token
}

func ShortLink(ticket *HavenInviteTicket, landingBase string) string {
	base := trimBase(landingBase)
	if base == "" {
		return ""
	}
	return base + "/" + InvitePathSegment + "/" + ticket.HumanCode
}

// TokenFromLink is HavenInviteLink.token(fromLink:).
func TokenFromLink(link string) (string, error) {
	trimmed := strings.TrimSpace(link)
	notALink := &LinkFailure{"not_a_haven_link", "Dette ser ikke ut som en HAVEN-invitasjon."}
	if trimmed == "" {
		return "", notALink
	}
	prefix := InviteCustomScheme + "://invite/"
	if strings.HasPrefix(trimmed, prefix) {
		return trimmed[len(prefix):], nil
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return trimmed, nil
	}
	if t := parsed.Query().Get("t"); t != "" {
		return t, nil
	}
	parts := []string{}
	for _, part := range strings.Split(parsed.Path, "/") {
		if part != "" {
			parts = append(parts, part)
		}
	}
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] == InvitePathSegment {
			if i+1 < len(parts) {
				return parts[i+1], nil
			}
			break
		}
	}
	if len(parts) > 0 {
		last := parts[len(parts)-1]
		if len(last) > 16 || LooksLikeHumanCode(last) {
			return last, nil
		}
	}
	return "", notALink
}

// ---- Binding helpers ---------------------------------------------------------

// NormalizeEmail is Binding's HavenRelationNormalizer.normalizeEmail.
func NormalizeEmail(raw string) (string, bool) {
	value := strings.TrimSpace(raw)
	value = strings.TrimPrefix(value, "mailto:")
	if open, close := strings.LastIndex(value, "<"), strings.LastIndex(value, ">"); open >= 0 && close > open {
		value = value[open+1 : close]
	}
	value = strings.Trim(value, " \"'<>,;")
	at := strings.LastIndex(value, "@")
	if at < 0 {
		return "", false
	}
	local, domain := value[:at], strings.ToLower(value[at+1:])
	if local == "" || domain == "" || !strings.Contains(domain, ".") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return "", false
	}
	if strings.Contains(domain, " ") || strings.Contains(local, " ") {
		return "", false
	}
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if label == "" {
			return "", false
		}
	}
	tld := labels[len(labels)-1]
	if len([]rune(tld)) < 2 {
		return "", false
	}
	for _, r := range tld {
		if !unicode.IsLetter(r) {
			return "", false
		}
	}
	return strings.ToLower(local) + "@" + domain, true
}

// DisclosureToken is Binding's 16-hex audience token.
func DisclosureToken(kind, normalized string) string {
	return SHA256HexString("haven.endpoint.v1|" + kind + "|" + normalized)[:16]
}

func MakeStatusKey(random func(int) []byte) string {
	if random == nil {
		random = func(n int) []byte {
			b := make([]byte, n)
			_, _ = rand.Read(b)
			return b
		}
	}
	return Base64URLString(random(32))
}

// StatusKeyDigest is what a scaffold stores in place of the bearer.
func StatusKeyDigest(key string) string { return SHA256HexString(key) }

// CanReceiveContactRequest mirrors the Swift computed property.
func (t *HavenInviteTicket) CanReceiveContactRequest() bool {
	if t.IssuerContactEndpoint == nil || *t.IssuerContactEndpoint == "" {
		return false
	}
	for _, c := range t.Capabilities {
		if c == "send_contact_request_to_issuer" {
			return true
		}
	}
	return false
}

func InviteBoundary(ticket *HavenInviteTicket) string {
	if ticket.CanReceiveContactRequest() {
		return InviteBoundaryLine
	}
	return InviteBoundaryLineWithoutReply
}

// ---- HavenInviteVerifier verdict --------------------------------------------

type InviteVerdict struct {
	IsValid            bool
	SignatureValid     bool
	Expired            bool
	Revoked            bool
	AudienceMatches    *bool
	Reason             string
	Code               string
	TicketID           string
	IssuerDisplayName  string
	IssuerIdentityUUID string
}

func inviteReason(code, name string) string {
	switch code {
	case "unsigned":
		return "Invitasjonen er ikke signert."
	case "issuer_mismatch":
		return "Signaturen tilhører en annen identitet enn avsenderen i invitasjonen."
	case "uncanonical":
		return "Invitasjonen kunne ikke gjøres om til den formen signaturen dekker."
	case "bad_signature":
		return "Signaturen stemmer ikke. Invitasjonen kan være endret underveis."
	case "ttl_too_long":
		return "Invitasjonen påstår å gjelde lenger enn 90 dager."
	case "revoked":
		return name + " har trukket denne invitasjonen tilbake."
	case "expired":
		return "Invitasjonen har gått ut. Be " + name + " om en ny."
	case "wrong_audience":
		return "Invitasjonen var adressert til noen andre."
	}
	return "Gyldig invitasjon fra " + name + "."
}

// VerifyInvite is HavenInviteVerifier.verify, with the Swift reasons.
func VerifyInvite(ticket *HavenInviteTicket, now time.Time, options TicketOptions) InviteVerdict {
	code := VerifyTicket(ticket, now, options)
	var audience *bool
	if code != "unsigned" && code != "issuer_mismatch" && code != "uncanonical" && options.ExpectedAudienceToken != nil {
		match := *options.ExpectedAudienceToken == ticket.AudienceToken
		audience = &match
	}
	signatureValid := code != "unsigned" && code != "issuer_mismatch" && code != "bad_signature" && code != "uncanonical"
	return InviteVerdict{
		IsValid:            code == "valid",
		SignatureValid:     signatureValid,
		Expired:            ticket.IsExpired(epoch(now)),
		Revoked:            options.RevokedTicketIDs[ticket.TicketID],
		AudienceMatches:    audience,
		Reason:             inviteReason(code, ticket.IssuerDisplayName),
		Code:               code,
		TicketID:           ticket.TicketID,
		IssuerDisplayName:  ticket.IssuerDisplayName,
		IssuerIdentityUUID: ticket.Issuer.UUID,
	}
}

// InviteVerdictPayload is HavenInviteVerifier.payload(for:ticket:).
func InviteVerdictPayload(verdict InviteVerdict, ticket *HavenInviteTicket) map[string]any {
	status := "invalid"
	if verdict.IsValid {
		status = "valid"
	}
	var audience any
	if verdict.AudienceMatches != nil {
		audience = *verdict.AudienceMatches
	}
	capabilities := []any{}
	for _, c := range ticket.Capabilities {
		capabilities = append(capabilities, c)
	}
	greeting := ""
	if ticket.GreetingName != nil {
		greeting = *ticket.GreetingName
	}
	return map[string]any{
		"schema":                   InviteVerdictSchema,
		"status":                   status,
		"isValid":                  verdict.IsValid,
		"signatureValid":           verdict.SignatureValid,
		"expired":                  verdict.Expired,
		"revoked":                  verdict.Revoked,
		"audienceMatches":          audience,
		"reason":                   verdict.Reason,
		"code":                     verdict.Code,
		"ticketID":                 verdict.TicketID,
		"issuerDisplayName":        verdict.IssuerDisplayName,
		"issuerIdentityUUID":       verdict.IssuerIdentityUUID,
		"capabilities":             capabilities,
		"canReceiveContactRequest": ticket.CanReceiveContactRequest(),
		"grantsAccess":             false,
		"boundaryStatement":        InviteBoundaryLine,
		"humanCode":                ticket.HumanCode,
		"greetingName":             greeting,
		"expiresAt":                ticket.ExpiresAt,
		"sideEffect":               false,
	}
}

// InviteStatusReport is HavenInviteStatusReport as Swift's JSONEncoder writes it.
func InviteStatusReport(ticketID, state string, respondedAt *int64, contactRequestCount int, resultingEntityRef *string) map[string]any {
	report := map[string]any{
		"schema":              InviteStatusSchema,
		"ticketID":            ticketID,
		"state":               state,
		"openCount":           0,
		"contactRequestCount": contactRequestCount,
	}
	if respondedAt != nil {
		report["respondedAt"] = *respondedAt
	}
	if resultingEntityRef != nil {
		report["resultingEntityRef"] = *resultingEntityRef
	}
	return report
}

// ---- Builders ----------------------------------------------------------------

func signHaven(model Model, sign SignFunc, signerUUID string) (*HavenSignatureProof, error) {
	payload, err := SignedBytes(model)
	if err != nil {
		return nil, err
	}
	signature, err := sign(payload)
	if err != nil {
		return nil, err
	}
	if len(signature) == 0 {
		return nil, fail("unsigned", "empty signature")
	}
	return &HavenSignatureProof{Type: "signature", ByIdentityUUID: signerUUID, Algorithm: "EdDSA", CurveType: "Curve25519", Signature: signature}, nil
}

// TicketInput is what Binding's invite.prepare fills in before signing.
type TicketInput struct {
	IssuerDisplayName string
	AudienceToken     string
	AudienceKind      string
	ContactEndpointID string
	IssuerEntityRef   string
	GreetingName      string
	Note              string
	TTLDays           int
	Now               time.Time
	Random            func(int) []byte
	NewUUID           func() string
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// BuildTicket mints and signs a ticket the way Binding does.
func BuildTicket(issuer IdentityPublicKeyDescriptor, sign SignFunc, in TicketInput) (*HavenInviteTicket, error) {
	if in.Random == nil {
		in.Random = func(n int) []byte { b := make([]byte, n); _, _ = rand.Read(b); return b }
	}
	if in.NewUUID == nil {
		in.NewUUID = randomUUID
	}
	if in.AudienceKind == "" {
		in.AudienceKind = "email"
	}
	days := in.TTLDays
	if days < 1 {
		days = 14
	}
	if days > 90 {
		days = 90
	}
	ticketID := "inv-" + strings.ToLower(in.NewUUID())
	capabilities := []string{"create_own_entity"}
	if in.ContactEndpointID != "" {
		capabilities = append(capabilities, "send_contact_request_to_issuer")
	}
	created := in.Now.Unix()
	ticket := &HavenInviteTicket{
		Version:               1,
		TicketID:              ticketID,
		Issuer:                issuer,
		IssuerDisplayName:     in.IssuerDisplayName,
		IssuerContactEndpoint: optional(in.ContactEndpointID),
		IssuerEntityRef:       optional(in.IssuerEntityRef),
		AudienceToken:         in.AudienceToken,
		AudienceKind:          in.AudienceKind,
		HumanCode:             InviteHumanCode(ticketID + in.AudienceToken),
		GreetingName:          optional(in.GreetingName),
		Note:                  optional(in.Note),
		CreatedAt:             created,
		ExpiresAt:             created + int64(days)*86_400,
		Nonce:                 in.Random(12),
		Capabilities:          capabilities,
	}
	proof, err := signHaven(ticket, sign, issuer.UUID)
	if err != nil {
		return nil, err
	}
	ticket.Proof = proof
	return ticket, nil
}

func BuildPublication(ticket *HavenInviteTicket, sign SignFunc, statusKey string, maxContactRequests int, now time.Time) (*HavenInvitePublication, error) {
	token, err := ticket.Token()
	if err != nil {
		return nil, err
	}
	publication := &HavenInvitePublication{
		Schema:             "haven.invite.publication.v1",
		TicketID:           ticket.TicketID,
		HumanCode:          ticket.HumanCode,
		TicketToken:        token,
		AudienceToken:      ticket.AudienceToken,
		IssuerIdentityUUID: ticket.Issuer.UUID,
		ExpiresAt:          ticket.ExpiresAt,
		PublishedAt:        now.Unix(),
		MaxContactRequests: int64(maxContactRequests),
		StatusKey:          statusKey,
	}
	proof, err := signHaven(publication, sign, ticket.Issuer.UUID)
	if err != nil {
		return nil, err
	}
	publication.Proof = proof
	return publication, nil
}

func BuildRevocation(ticketID string, issuer IdentityPublicKeyDescriptor, sign SignFunc, reason string, now time.Time) (*HavenInviteRevocationNotice, error) {
	if reason == "" {
		reason = "Trukket tilbake av avsender."
	}
	notice := &HavenInviteRevocationNotice{
		Schema:             "haven.invite.revocation.v1",
		TicketID:           ticketID,
		Reason:             reason,
		RevokedAt:          now.Unix(),
		IssuerIdentityUUID: issuer.UUID,
	}
	proof, err := signHaven(notice, sign, issuer.UUID)
	if err != nil {
		return nil, err
	}
	notice.Proof = proof
	return notice, nil
}

// ContactRequestInput is the invitee's side of a reply.
type ContactRequestInput struct {
	SenderDisplayName string
	SenderEntityRef   string
	SenderEndpoint    string
	Message           string
	TTLSeconds        int64
	Now               time.Time
	Random            func(int) []byte
	NewUUID           func() string
}

// BuildContactRequest signs the invitee's "I'd like to connect" for ticket.
func BuildContactRequest(ticket *HavenInviteTicket, sender IdentityPublicKeyDescriptor, sign SignFunc, in ContactRequestInput) (*HavenInviteContactRequest, error) {
	if ticket.IssuerContactEndpoint == nil || *ticket.IssuerContactEndpoint == "" {
		return nil, &LinkFailure{"no_reply_channel", "Invitasjonen har ingen kontaktflate å svare til."}
	}
	if in.Random == nil {
		in.Random = func(n int) []byte { b := make([]byte, n); _, _ = rand.Read(b); return b }
	}
	if in.NewUUID == nil {
		in.NewUUID = randomUUID
	}
	if in.TTLSeconds == 0 {
		in.TTLSeconds = 7 * 86_400
	}
	created := in.Now.Unix()
	expires := created + in.TTLSeconds
	if expires > ticket.ExpiresAt {
		expires = ticket.ExpiresAt
	}
	request := &HavenInviteContactRequest{
		Schema:            "haven.invite.contactRequest.v1",
		RequestID:         "icr-" + strings.ToLower(in.NewUUID()),
		TicketID:          ticket.TicketID,
		IssuerEndpointID:  *ticket.IssuerContactEndpoint,
		Sender:            sender,
		SenderDisplayName: in.SenderDisplayName,
		SenderEntityRef:   optional(in.SenderEntityRef),
		SenderEndpoint:    optional(in.SenderEndpoint),
		Message:           optional(in.Message),
		CreatedAt:         created,
		ExpiresAt:         expires,
		Nonce:             in.Random(16),
	}
	proof, err := signHaven(request, sign, sender.UUID)
	if err != nil {
		return nil, err
	}
	request.Proof = proof
	return request, nil
}

func randomUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// MakeNonce returns n random bytes.
func MakeNonce(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}
