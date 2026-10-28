package cellprotocol

// EntityScaffoldExtensionCell extends my own entity onto a new scaffold or
// device. It is a port of Binding's BindingEntityScaffoldExtensionCell, with the
// same keypaths, payloads and result shapes, so a Go node can ask, approve or
// accept against a Swift or Python node:
//
//  1. the new place asks, signing with its own fresh key (extension.beginRequest)
//  2. a place I already control reviews and approves, signing over a hash of
//     the exact request it saw (extension.reviewRequest, extension.approveRequest)
//  3. the new place accepts, and both sides hold a link record
//     (extension.acceptApproval)
//
// Transport packets are base64url of the model's JSON, as Binding sends them.
//
// The request hash is Binding's: the UTF-8 of the hex SHA-256 of the base64 of
// the canonical request. EntityAnchorCell and the VC completion chain in
// CellBase use the raw SHA-256 instead, so an approval from this flow does not
// complete on an EntityAnchor. That mismatch is in Swift; it is kept here so
// Binding accepts what Go approves.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Digipomps/GoCellProtocol/interop"
)

const EntityExtensionEndpoint = "cell:///EntityScaffoldExtension"

type extensionScope struct {
	ID, Label, Detail string
	DefaultOn         bool
}

var extensionDefaultScopes = []extensionScope{
	{"entity.read", "Lese entiteten min", "Se relasjoner, formål og innstillinger.", true},
	{"entity.write", "Endre entiteten min", "Legge til og endre relasjoner og innstillinger.", true},
	{"invite.issue", "Lage invitasjoner", "Signere invitasjoner i mitt navn.", false},
	{"agreement.sign", "Signere avtaler", "Inngå avtaler i mitt navn. Gi bare dette til noe du stoler helt på.", false},
}

func knownScope(id string) (extensionScope, bool) {
	for _, scope := range extensionDefaultScopes {
		if scope.ID == id {
			return scope, true
		}
	}
	return extensionScope{}, false
}

const humanCodeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// SHA256Hex is HavenInviteLink.sha256Hex.
func SHA256Hex(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// HumanCode is HavenInviteLink.humanCode: six characters with no 0/O or 1/I/L.
func HumanCode(seed string) string {
	digest := SHA256Hex(seed)
	var code strings.Builder
	for i := 0; i < 12; i += 2 {
		b, _ := strconv.ParseUint(digest[i:i+2], 16, 8)
		code.WriteByte(humanCodeAlphabet[int(b)%len(humanCodeAlphabet)])
	}
	return code.String()
}

func Base64URL(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func DataFromBase64URL(text string) ([]byte, bool) {
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(text, "="))
	return data, err == nil
}

// BindingRequestHash is Data(sha256Hex(canonical.base64EncodedString()).utf8) from Binding.
func BindingRequestHash(request *interop.IdentityEnrollmentRequest) ([]byte, error) {
	canonical, err := interop.SignedBytes(request)
	if err != nil {
		return nil, err
	}
	return []byte(SHA256Hex(base64.StdEncoding.EncodeToString(canonical))), nil
}

type outgoingRequest struct {
	request    *interop.IdentityEnrollmentRequest
	humanCode  string
	createdAt  time.Time
	approvedAt *time.Time
	linkID     string
}

// ExtensionOptions configures EntityScaffoldExtensionCell. Clock, Random and
// NewUUID default to the real ones.
type ExtensionOptions struct {
	Descriptor            interop.IdentityPublicKeyDescriptor
	Sign                  func([]byte) ([]byte, error)
	EntityAnchorReference string
	DisplayName           string
	Platform              string
	Clock                 func() time.Time
	Random                func(int) []byte
	NewUUID               func() string
}

type EntityScaffoldExtensionCell struct {
	*GeneralCell
	opts       ExtensionOptions
	stateMu    sync.Mutex
	links      []*interop.IdentityLinkRecord
	outgoing   []*outgoingRequest
	lastResult map[string]any
}

var (
	extensionReadableKeys = []string{"state", "extension.state", "extension.links", "extension.pending", "extension.defaultScopes", "extension.lastResult"}
	extensionWritableKeys = []string{"extension.beginRequest", "extension.reviewRequest", "extension.approveRequest", "extension.acceptApproval", "extension.revokeLink", "extension.clearPending"}
)

func NewEntityScaffoldExtensionCell(owner *Identity, opts ExtensionOptions) *EntityScaffoldExtensionCell {
	if opts.EntityAnchorReference == "" {
		opts.EntityAnchorReference = "cell:///EntityAnchor"
	}
	if opts.DisplayName == "" && opts.Descriptor.DisplayName != nil {
		opts.DisplayName = *opts.Descriptor.DisplayName
	}
	if opts.Platform == "" {
		opts.Platform = "go"
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.Random == nil {
		opts.Random = func(n int) []byte {
			b := make([]byte, n)
			_, _ = rand.Read(b)
			return b
		}
	}
	if opts.NewUUID == nil {
		opts.NewUUID = NewUUID
	}
	cell := &EntityScaffoldExtensionCell{
		GeneralCell: NewGeneralCell(owner, "EntityScaffoldExtension"),
		opts:        opts,
		lastResult:  extOK("Klar til å utvide entiteten til et nytt sted.", false, nil),
	}
	for _, key := range extensionReadableKeys {
		cell.agreementTemplate.AddGrant("r---", key)
		cell.AddGetHandler(key, cell.read)
	}
	for _, key := range extensionWritableKeys {
		cell.agreementTemplate.AddGrant("rw--", key)
		cell.AddSetHandler(key, cell.write)
	}
	return cell
}

func extOK(message string, sideEffect bool, extra map[string]any) map[string]any {
	out := map[string]any{"status": "ok", "message": message, "sideEffect": sideEffect}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func extError(code, message string, extra map[string]any) map[string]any {
	out := map[string]any{"status": "error", "code": code, "message": message, "sideEffect": false}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func extString(value any) string {
	s, _ := value.(string)
	return s
}

func extStrings(value any) []string {
	switch v := value.(type) {
	case string:
		return []string{v}
	case []string:
		return append([]string(nil), v...)
	case []any:
		out := []string{}
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func extInt(value any) (int, bool) {
	switch v := value.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	case string:
		n, err := strconv.Atoi(v)
		return n, err == nil
	}
	return 0, false
}

func ttlMinutes(value any) int {
	n, ok := extInt(value)
	if !ok || n == 0 {
		n = 15
	}
	if n < 2 {
		n = 2
	}
	if n > 1440 {
		n = 1440
	}
	return n
}

func ptr(s string) *string { return &s }

// decodeTransport accepts a base64url string, {"payload": ...}, {key: {...}} or the bare object.
func decodeTransport(value any, key string, model any) bool {
	obj, isObject := ObjectValue(value)
	text := extString(value)
	if isObject {
		text = extString(obj["payload"])
	}
	if text != "" {
		if data, ok := DataFromBase64URL(text); ok && interop.Decode(data, model) == nil {
			return true
		}
	}
	if isObject {
		if embedded, ok := ObjectValue(obj[key]); ok && decodeObject(embedded, model) {
			return true
		}
		return decodeObject(obj, model)
	}
	return false
}

// decodeObject goes through JSON so numbers parse the way wire bytes do.
func decodeObject(obj map[string]any, model any) bool {
	data, err := json.Marshal(obj)
	return err == nil && interop.Decode(data, model) == nil
}

func encodeTransport(model any) string {
	data, err := interop.EncodedJSON(model)
	if err != nil {
		return ""
	}
	return Base64URL(data)
}

func (c *EntityScaffoldExtensionCell) now() time.Time { return c.opts.Clock().UTC() }

func (c *EntityScaffoldExtensionCell) fail(result map[string]any) map[string]any {
	c.lastResult = result
	return result
}

func expiredAt(text string, now time.Time) bool {
	expiry, ok := interop.ParseISO8601(text)
	return !ok || now.After(expiry)
}

func (c *EntityScaffoldExtensionCell) read(ctx context.Context, keypath string, requester *Identity) (any, error) {
	_, _ = ctx, requester
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	switch keypath {
	case "state", "extension.state":
		return c.stateObject(), nil
	case "extension.links":
		return c.linkRows(), nil
	case "extension.pending":
		return c.pendingRows(), nil
	case "extension.defaultScopes":
		out := []any{}
		for _, s := range extensionDefaultScopes {
			out = append(out, map[string]any{"id": s.ID, "label": s.Label, "detail": s.Detail, "defaultOn": s.DefaultOn})
		}
		return out, nil
	case "extension.lastResult":
		return c.lastResult, nil
	}
	return nil, nil
}

func (c *EntityScaffoldExtensionCell) write(ctx context.Context, keypath string, value any, requester *Identity) (any, error) {
	_, _ = ctx, requester
	value = NormalizeJSON(value)
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	switch keypath {
	case "extension.beginRequest":
		return c.beginRequest(value), nil
	case "extension.reviewRequest":
		return c.reviewRequest(value), nil
	case "extension.approveRequest":
		return c.approveRequest(value), nil
	case "extension.acceptApproval":
		return c.acceptApproval(value), nil
	case "extension.revokeLink":
		return c.revokeLink(value), nil
	case "extension.clearPending":
		return c.clearPending(), nil
	}
	return extError("unsupported_keypath", "Ukjent utvidelses-handling.", nil), nil
}

// ---- 1. Ask ------------------------------------------------------------------

func (c *EntityScaffoldExtensionCell) beginRequest(value any) map[string]any {
	payload, _ := ObjectValue(value)
	audience := extString(payload["audience"])
	if audience == "" {
		return c.fail(extError("missing_audience", "Si hvilket scaffold dette gjelder — `audience`, for eksempel https://staging.haven.digipomps.org.", nil))
	}
	now := c.now()
	ttl := ttlMinutes(payload["ttlMinutes"])
	requestID := "enr-" + strings.ToLower(c.opts.NewUUID())
	orDefault := func(values []string, fallback []string) []string {
		if len(values) == 0 {
			return fallback
		}
		return values
	}
	defaultOn := []string{}
	for _, s := range extensionDefaultScopes {
		if s.DefaultOn {
			defaultOn = append(defaultOn, s.ID)
		}
	}
	origin := extString(payload["origin"])
	if origin == "" {
		origin = EntityExtensionEndpoint
	}
	label := extString(payload["deviceLabel"])
	if label == "" {
		label = c.opts.DisplayName
	}
	request := &interop.IdentityEnrollmentRequest{
		Version:   1,
		RequestID: requestID,
		Purpose:   "link_identity",
		EntityBinding: &interop.EntityBindingDescriptor{
			Mode: "localEntityAnchor", EntityAnchorReference: ptr(c.opts.EntityAnchorReference), Audience: ptr(audience),
		},
		NewIdentity:               c.opts.Descriptor,
		RequestedDomains:          orDefault(extStrings(payload["requestedDomains"]), []string{"private"}),
		RequestedIdentityContexts: orDefault(extStrings(payload["requestedIdentityContexts"]), []string{"default"}),
		RequestedScopes:           orDefault(extStrings(payload["requestedScopes"]), defaultOn),
		Audience:                  audience,
		Origin:                    origin,
		CreatedAt:                 interop.ISO8601(now),
		ExpiresAt:                 interop.ISO8601(now.Add(time.Duration(ttl) * time.Minute)),
		Nonce:                     c.opts.Random(16),
		Platform:                  ptr(c.opts.Platform),
	}
	if label != "" {
		request.DeviceLabel = ptr(label)
	}
	canonical, err := interop.SignedBytes(request)
	var signature []byte
	if err == nil {
		signature, err = c.opts.Sign(canonical)
	}
	if err != nil {
		return c.fail(extError("signing_failed", "Kunne ikke signere forespørselen.", nil))
	}
	request.Proof = &interop.SignatureProof{
		Type: "signature", ByIdentityUUID: c.opts.Descriptor.UUID, Algorithm: c.opts.Descriptor.Algorithm,
		CurveType: c.opts.Descriptor.CurveType, Signature: signature,
	}
	code := HumanCode(requestID + audience)
	kept := []*outgoingRequest{{request: request, humanCode: code, createdAt: now}}
	for _, entry := range c.outgoing {
		if entry.request.RequestID != requestID {
			kept = append(kept, entry)
		}
	}
	c.outgoing = kept
	result := extOK(
		fmt.Sprintf("Forespørselen er klar. Vis koden %s eller send pakken til en enhet du allerede bruker, og godkjenn der.", code),
		true,
		map[string]any{
			"requestID":        requestID,
			"humanCode":        code,
			"payload":          encodeTransport(request),
			"expiresAt":        request.ExpiresAt,
			"expiresInMinutes": ttl,
			"requestedScopes":  toAnyStrings(request.RequestedScopes),
			"audience":         audience,
			"nextStep":         "Åpne HAVEN på en enhet du allerede bruker, og send pakken til extension.approveRequest der.",
			"warning":          "Godkjenn aldri en forespørsel du ikke selv startet. Sjekk at koden på denne skjermen er den samme som på den andre.",
		},
	)
	c.lastResult = result
	return result
}

func toAnyStrings(values []string) []any {
	out := make([]any, len(values))
	for i, v := range values {
		out[i] = v
	}
	return out
}

// ---- 2. Review and approve ----------------------------------------------------

func (c *EntityScaffoldExtensionCell) reviewRequest(value any) map[string]any {
	var request interop.IdentityEnrollmentRequest
	if !decodeTransport(value, "request", &request) {
		return extError("bad_payload", "Fant ingen gyldig forespørsel i det du sendte.", nil)
	}
	now := c.now()
	expired := expiredAt(request.ExpiresAt, now)
	signatureValid := false
	if proof := request.Proof; proof != nil && proof.Signature != nil && proof.ByIdentityUUID == request.NewIdentity.UUID {
		if canonical, err := interop.SignedBytes(&request); err == nil {
			signatureValid = interop.VerifySignature(proof.Signature, canonical, request.NewIdentity)
		}
	}
	alreadyLinked := false
	for _, link := range c.links {
		if link.LinkedIdentity.UUID == request.NewIdentity.UUID && link.Status == "active" {
			alreadyLinked = true
		}
	}
	scopes, unknown := []any{}, []any{}
	for _, id := range request.RequestedScopes {
		known, ok := knownScope(id)
		label, detail := id, "Ukjent rettighet — vær ekstra forsiktig."
		if ok {
			label, detail = known.Label, known.Detail
		} else {
			unknown = append(unknown, id)
		}
		scopes = append(scopes, map[string]any{"id": id, "label": label, "detail": detail, "recognised": ok})
	}
	status := "rejected"
	if signatureValid && !expired {
		status = "reviewable"
	}
	deviceLabel, platform := "ukjent enhet", ""
	if request.DeviceLabel != nil {
		deviceLabel = *request.DeviceLabel
	}
	if request.Platform != nil {
		platform = *request.Platform
	}
	code := HumanCode(request.RequestID + request.Audience)
	return map[string]any{
		"schema":               "haven.entityExtension.review.v1",
		"status":               status,
		"requestID":            request.RequestID,
		"signatureValid":       signatureValid,
		"expired":              expired,
		"alreadyLinked":        alreadyLinked,
		"audience":             request.Audience,
		"deviceLabel":          deviceLabel,
		"platform":             platform,
		"requestedScopes":      scopes,
		"unknownScopes":        unknown,
		"requestedDomains":     toAnyStrings(request.RequestedDomains),
		"expiresAt":            request.ExpiresAt,
		"humanCode":            code,
		"summaryText":          reviewSummary(&request, signatureValid, expired, alreadyLinked),
		"confirmationQuestion": fmt.Sprintf("Stemmer koden %s med det som står på den andre skjermen?", code),
		"sideEffect":           false,
	}
}

func reviewSummary(request *interop.IdentityEnrollmentRequest, signatureValid, expired, alreadyLinked bool) string {
	switch {
	case !signatureValid:
		return "Signaturen på forespørselen stemmer ikke. Ikke godkjenn denne."
	case expired:
		return "Forespørselen er utløpt. Start en ny på den andre enheten."
	case alreadyLinked:
		return "Denne identiteten er allerede koblet til entiteten din."
	}
	device := "En ny enhet"
	if request.DeviceLabel != nil {
		device = *request.DeviceLabel
	}
	return fmt.Sprintf("%s ber om å bli en del av entiteten din på %s, med %d rettighet(er).", device, request.Audience, len(request.RequestedScopes))
}

func (c *EntityScaffoldExtensionCell) approveRequest(value any) map[string]any {
	payload, _ := ObjectValue(value)
	var request interop.IdentityEnrollmentRequest
	if !decodeTransport(value, "request", &request) {
		return c.fail(extError("bad_payload", "Fant ingen gyldig forespørsel i det du sendte.", nil))
	}
	review := c.reviewRequest(value)
	if review["status"] != "reviewable" {
		message := extString(review["summaryText"])
		if message == "" {
			message = "Forespørselen kan ikke godkjennes."
		}
		return c.fail(extError("not_approvable", message, map[string]any{"review": review}))
	}
	granted := extStrings(payload["approvedScopes"])
	if len(granted) == 0 {
		for _, id := range request.RequestedScopes {
			if _, ok := knownScope(id); ok {
				granted = append(granted, id)
			}
		}
	}
	grantedSet := map[string]bool{}
	for _, id := range granted {
		grantedSet[id] = true
	}
	refusedSet := map[string]bool{}
	for _, id := range request.RequestedScopes {
		if !grantedSet[id] {
			refusedSet[id] = true
		}
	}
	refused := make([]string, 0, len(refusedSet))
	for id := range refusedSet {
		refused = append(refused, id)
	}
	sort.Strings(refused)
	if len(granted) == 0 {
		return c.fail(extError("no_scopes", "Ingen rettigheter ble godkjent, så det er ikke noe å koble.", nil))
	}
	requestHash, err := BindingRequestHash(&request)
	if err != nil {
		return c.fail(extError("bad_payload", "Forespørselen kunne ikke kanoniseres.", nil))
	}
	now := c.now()
	ttl := ttlMinutes(payload["ttlMinutes"])
	binding := interop.EntityBindingDescriptor{Mode: "localEntityAnchor", Audience: ptr(request.Audience)}
	if request.EntityBinding != nil {
		binding = *request.EntityBinding
	}
	domains := extStrings(payload["approvedDomains"])
	if len(domains) == 0 {
		domains = request.RequestedDomains
	}
	approval := &interop.IdentityEnrollmentApproval{
		Version:                  1,
		ApprovalID:               "apr-" + strings.ToLower(c.opts.NewUUID()),
		Purpose:                  "approve_link_identity",
		RequestHash:              requestHash,
		EntityBinding:            binding,
		SubjectIdentity:          request.NewIdentity,
		ApprovedDomains:          domains,
		ApprovedIdentityContexts: request.RequestedIdentityContexts,
		ApprovedScopes:           granted,
		IssuerIdentityUUID:       c.opts.Descriptor.UUID,
		IssuerType:               "existingDevice",
		Audience:                 request.Audience,
		Origin:                   EntityExtensionEndpoint,
		CreatedAt:                interop.ISO8601(now),
		ExpiresAt:                interop.ISO8601(now.Add(time.Duration(ttl) * time.Minute)),
		JTI:                      strings.ToLower(c.opts.NewUUID()),
		FreshAuthRequired:        true,
	}
	if method := extString(payload["freshAuthMethod"]); method != "" {
		approval.FreshAuthMethod = ptr(method)
		approval.FreshAuthPerformedAt = ptr(interop.ISO8601(now))
	}
	if err := c.signApprovalProof(approval); err != nil {
		return c.fail(extError("signing_failed", "Kunne ikke signere godkjenningen.", nil))
	}
	record := &interop.IdentityLinkRecord{
		LinkID:                   "lnk-" + strings.ToLower(c.opts.NewUUID()),
		EntityBinding:            approval.EntityBinding,
		LinkedIdentity:           request.NewIdentity,
		ApprovedDomains:          approval.ApprovedDomains,
		ApprovedIdentityContexts: approval.ApprovedIdentityContexts,
		ApprovedScopes:           approval.ApprovedScopes,
		IssuerIdentityUUID:       c.opts.Descriptor.UUID,
		IssuerType:               "existingDevice",
		Status:                   "active",
		LinkedAt:                 interop.ISO8601(now),
	}
	c.storeLink(record)
	device := "Den nye enheten"
	if request.DeviceLabel != nil {
		device = *request.DeviceLabel
	}
	message := fmt.Sprintf("Godkjent. %s får %d rettighet(er).", device, len(granted))
	if len(refused) > 0 {
		message += " Jeg holdt tilbake: " + strings.Join(refused, ", ") + "."
	}
	descriptor := c.opts.Descriptor
	issuer, _ := interop.ToWire(&descriptor)
	result := extOK(message, true, map[string]any{
		"approvalID":     approval.ApprovalID,
		"linkID":         record.LinkID,
		"payload":        encodeTransport(approval),
		"approvedScopes": toAnyStrings(granted),
		"refusedScopes":  toAnyStrings(refused),
		"expiresAt":      approval.ExpiresAt,
		"nextStep":       "Send denne pakken tilbake til den nye enheten og kjør extension.acceptApproval der.",
		"links":          c.linkRows(),
		// Not in Binding: lets the new place check the approver's signature.
		"issuerIdentity": issuer,
	})
	c.lastResult = result
	return result
}

func (c *EntityScaffoldExtensionCell) proof() *interop.IdentityEnrollmentApprovalProof {
	return &interop.IdentityEnrollmentApprovalProof{
		Type: "signature", IssuerIdentityUUID: c.opts.Descriptor.UUID, IssuerType: "existingDevice",
		Algorithm: c.opts.Descriptor.Algorithm, CurveType: c.opts.Descriptor.CurveType,
	}
}

func (c *EntityScaffoldExtensionCell) signApprovalProof(approval *interop.IdentityEnrollmentApproval) error {
	approval.Proof = c.proof()
	canonical, err := interop.SignedBytes(approval)
	if err != nil {
		return err
	}
	approval.Proof.Signature, err = c.opts.Sign(canonical)
	return err
}

// ---- 3. Accept -------------------------------------------------------------------

func (c *EntityScaffoldExtensionCell) acceptApproval(value any) map[string]any {
	var approval interop.IdentityEnrollmentApproval
	if !decodeTransport(value, "approval", &approval) {
		return c.fail(extError("bad_payload", "Fant ingen gyldig godkjenning i det du sendte.", nil))
	}
	var pending *outgoingRequest
	for _, entry := range c.outgoing {
		if entry.request.NewIdentity.UUID == approval.SubjectIdentity.UUID {
			pending = entry
			break
		}
	}
	if pending == nil {
		return c.fail(extError("no_matching_request", "Denne godkjenningen hører ikke til noen forespørsel denne enheten har sendt.", nil))
	}
	expected, err := BindingRequestHash(pending.request)
	if err != nil {
		return c.fail(extError("bad_request", "Den lagrede forespørselen kunne ikke kanoniseres.", nil))
	}
	if string(approval.RequestHash) != string(expected) {
		return c.fail(extError("request_hash_mismatch", "Godkjenningen gjelder en annen forespørsel enn den denne enheten sendte. Jeg kobler ingenting.", nil))
	}
	now := c.now()
	if expiry, ok := interop.ParseISO8601(approval.ExpiresAt); ok && now.After(expiry) {
		return c.fail(extError("expired", "Godkjenningen er utløpt. Start forespørselen på nytt.", nil))
	}
	signaturePresent := approval.Proof != nil && approval.Proof.Signature != nil
	// Binding cannot check the approver's signature because it has no key for
	// it. When the caller hands one over, check it and refuse a bad one.
	signatureVerified := false
	if obj, ok := ObjectValue(value); ok {
		if raw, ok := ObjectValue(obj["issuerIdentity"]); ok {
			var issuer interop.IdentityPublicKeyDescriptor
			if decodeObject(raw, &issuer) && approval.Proof != nil && approval.Proof.Signature != nil &&
				issuer.UUID == approval.IssuerIdentityUUID && issuer.UUID == approval.Proof.IssuerIdentityUUID {
				if canonical, err := interop.SignedBytes(&approval); err == nil {
					signatureVerified = interop.VerifySignature(approval.Proof.Signature, canonical, issuer)
				}
			}
			if !signatureVerified {
				return c.fail(extError("bad_signature", "Signaturen på godkjenningen stemmer ikke med godkjennerens nøkkel. Jeg kobler ingenting.", nil))
			}
		}
	}
	record := &interop.IdentityLinkRecord{
		LinkID:                   "lnk-" + strings.ToLower(c.opts.NewUUID()),
		EntityBinding:            approval.EntityBinding,
		LinkedIdentity:           approval.SubjectIdentity,
		ApprovedDomains:          approval.ApprovedDomains,
		ApprovedIdentityContexts: approval.ApprovedIdentityContexts,
		ApprovedScopes:           approval.ApprovedScopes,
		IssuerIdentityUUID:       approval.IssuerIdentityUUID,
		IssuerType:               approval.IssuerType,
		Status:                   "active",
		LinkedAt:                 interop.ISO8601(now),
	}
	c.storeLink(record)
	for _, entry := range c.outgoing {
		if entry.request.RequestID == pending.request.RequestID {
			at := now
			entry.approvedAt = &at
			entry.linkID = record.LinkID
		}
	}
	note := "Forespørselens hash stemmer, og godkjenningen er signert, men denne enheten har ikke godkjennerens offentlige nøkkel og kan derfor ikke sjekke signaturen selv. Bekreft koden muntlig, eller hent nøkkelen fra scaffoldet."
	if signatureVerified {
		note = "Forespørselens hash og godkjennerens signatur stemmer."
	}
	result := extOK(
		fmt.Sprintf("Koblet. Dette stedet er nå en del av entiteten din, med %d rettighet(er).", len(approval.ApprovedScopes)),
		true,
		map[string]any{
			"linkID":             record.LinkID,
			"approvedScopes":     toAnyStrings(approval.ApprovedScopes),
			"issuerIdentityUUID": approval.IssuerIdentityUUID,
			"signaturePresent":   signaturePresent,
			"signatureVerified":  signatureVerified,
			"verificationNote":   note,
			"links":              c.linkRows(),
		},
	)
	c.lastResult = result
	return result
}

// ---- Revocation ------------------------------------------------------------------

func (c *EntityScaffoldExtensionCell) revokeLink(value any) map[string]any {
	payload, _ := ObjectValue(value)
	linkID := extString(payload["linkID"])
	if linkID == "" {
		linkID = extString(value)
	}
	if linkID == "" {
		return c.fail(extError("missing_id", "Mangler `linkID`.", nil))
	}
	var link *interop.IdentityLinkRecord
	for _, item := range c.links {
		if item.LinkID == linkID {
			link = item
			break
		}
	}
	if link == nil {
		return c.fail(extError("not_found", "Fant ingen kobling med id "+linkID+".", nil))
	}
	now := c.now()
	reason := extString(payload["reason"])
	if reason == "" {
		reason = "Trukket tilbake av eier."
	}
	revocation := &interop.IdentityLinkRevocation{
		Version: 1, LinkID: linkID, Reason: reason, RevokedAt: interop.ISO8601(now),
		RevokedByIdentityUUID: c.opts.Descriptor.UUID, IssuerType: "existingDevice", Proof: c.proof(),
	}
	if canonical, err := interop.SignedBytes(revocation); err == nil {
		if signature, err := c.opts.Sign(canonical); err == nil {
			revocation.Proof.Signature = signature
		}
	}
	if revocation.Proof.Signature == nil {
		revocation.Proof = nil
	}
	link.Status = "revoked"
	link.RevokedAt = ptr(interop.ISO8601(now))
	if revocation.Proof != nil {
		link.RevocationReference = ptr(base64.StdEncoding.EncodeToString(revocation.Proof.Signature))
	}
	wire, _ := interop.ToWire(revocation)
	result := extOK(
		"Koblingen er trukket tilbake her. Merk at et scaffold som allerede har koblingen slutter å godta den først når det har sett tilbakekallingen.",
		true,
		map[string]any{
			"linkID":      linkID,
			"revocation":  wire,
			"payload":     encodeTransport(revocation),
			"enforcement": "local_immediately_remote_on_receipt",
			"links":       c.linkRows(),
		},
	)
	c.lastResult = result
	return result
}

func (c *EntityScaffoldExtensionCell) clearPending() map[string]any {
	now := c.now()
	kept := []*outgoingRequest{}
	for _, entry := range c.outgoing {
		if entry.approvedAt == nil && !expiredAt(entry.request.ExpiresAt, now) {
			kept = append(kept, entry)
		}
	}
	removed := len(c.outgoing) - len(kept)
	c.outgoing = kept
	return extOK(fmt.Sprintf("Ryddet %d ferdige eller utløpte forespørsler.", removed), removed > 0, nil)
}

// ---- Presentation ---------------------------------------------------------------

func (c *EntityScaffoldExtensionCell) storeLink(record *interop.IdentityLinkRecord) {
	kept := []*interop.IdentityLinkRecord{record}
	for _, link := range c.links {
		if !(link.LinkedIdentity.UUID == record.LinkedIdentity.UUID && link.Status != "revoked") {
			kept = append(kept, link)
		}
	}
	c.links = kept
}

var norwegianMonths = []string{"jan.", "feb.", "mar.", "apr.", "mai", "jun.", "jul.", "aug.", "sep.", "okt.", "nov.", "des."}

func readableTime(t time.Time) string {
	t = t.UTC()
	return fmt.Sprintf("%d. %s %d, %02d:%02d", t.Day(), norwegianMonths[t.Month()-1], t.Year(), t.Hour(), t.Minute())
}

func linkStatusText(status string) string {
	switch status {
	case "active":
		return "Aktiv"
	case "revoked":
		return "Trukket tilbake"
	case "expired":
		return "Utløpt"
	case "pending":
		return "Venter"
	}
	return status
}

func (c *EntityScaffoldExtensionCell) linkRows() []any {
	rows := []any{}
	for _, link := range c.links {
		name := ""
		if link.LinkedIdentity.DisplayName != nil {
			name = *link.LinkedIdentity.DisplayName
		}
		displayName, summaryName := name, name
		if displayName == "" {
			displayName, summaryName = link.LinkedIdentity.UUID, "Ukjent enhet"
		}
		audience := ""
		if link.EntityBinding.Audience != nil {
			audience = *link.EntityBinding.Audience
		}
		labels := []string{}
		for _, id := range link.ApprovedScopes {
			if known, ok := knownScope(id); ok {
				labels = append(labels, known.Label)
			} else {
				labels = append(labels, id)
			}
		}
		linkedAtText := link.LinkedAt
		if t, ok := interop.ParseISO8601(link.LinkedAt); ok {
			linkedAtText = readableTime(t)
		}
		revokedAtText := ""
		if link.RevokedAt != nil {
			if t, ok := interop.ParseISO8601(*link.RevokedAt); ok {
				revokedAtText = readableTime(t)
			}
		}
		rows = append(rows, map[string]any{
			"linkID":        link.LinkID,
			"identityUUID":  link.LinkedIdentity.UUID,
			"displayName":   displayName,
			"audience":      audience,
			"status":        link.Status,
			"statusText":    linkStatusText(link.Status),
			"scopes":        toAnyStrings(link.ApprovedScopes),
			"scopeSummary":  strings.Join(labels, ", "),
			"linkedAt":      link.LinkedAt,
			"linkedAtText":  linkedAtText,
			"revokedAtText": revokedAtText,
			"summaryLine":   summaryName + " · " + linkStatusText(link.Status),
		})
	}
	return rows
}

func (c *EntityScaffoldExtensionCell) pendingRows() []any {
	now := c.now()
	rows := []any{}
	for _, entry := range c.outgoing {
		expired := expiredAt(entry.request.ExpiresAt, now)
		approved := entry.approvedAt != nil
		status := "Venter på godkjenning · kode " + entry.humanCode
		if approved {
			status = "Godkjent"
		} else if expired {
			status = "Utløpt — start på nytt"
		}
		label := ""
		if entry.request.DeviceLabel != nil {
			label = *entry.request.DeviceLabel
		}
		rows = append(rows, map[string]any{
			"requestID":     entry.request.RequestID,
			"humanCode":     entry.humanCode,
			"audience":      entry.request.Audience,
			"deviceLabel":   label,
			"createdAtText": readableTime(entry.createdAt),
			"expiresAt":     entry.request.ExpiresAt,
			"expired":       expired,
			"approved":      approved,
			"linkID":        entry.linkID,
			"statusLine":    status,
		})
	}
	return rows
}

func (c *EntityScaffoldExtensionCell) stateObject() map[string]any {
	active, waiting := 0, 0
	for _, link := range c.links {
		if link.Status == "active" {
			active++
		}
	}
	for _, entry := range c.outgoing {
		if entry.approvedAt == nil {
			waiting++
		}
	}
	summary := "Entiteten din finnes bare her. Du kan utvide den til et scaffold eller en annen enhet."
	if active > 0 || waiting > 0 {
		summary = fmt.Sprintf("%d aktive koblinger", active)
		if waiting > 0 {
			summary += fmt.Sprintf(", %d venter på godkjenning.", waiting)
		} else {
			summary += "."
		}
	}
	return map[string]any{
		"schema":          "haven.entityExtension.state.v1",
		"summary":         summary,
		"activeLinkCount": active,
		"pendingCount":    waiting,
		"links":           c.linkRows(),
		"pending":         c.pendingRows(),
		"safetyLine":      "Godkjenn bare en forespørsel du selv startet, og bare når koden er den samme på begge skjermene.",
		"lastResult":      c.lastResult,
		"updatedAt":       interop.ISO8601(c.now()),
	}
}
