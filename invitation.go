// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

// InvitationCell invites someone to HAVEN, and answers an invitation, from a
// Go node.
//
// The issuer half is a port of Binding's BindingInvitationCell: the same
// invite.* keypaths, the same signed ticket, publication and revocation
// notice, and the same scaffold calls (/i/api/publish, /i/api/status,
// /i/api/requests, /i/api/revoke). Binding picks the recipient from its
// Relations cell and hands the message to Mail or Messages; here the caller
// names the recipient and gets the link and message text back. Nothing is
// sent to the person by this cell.
//
// The invitee half is new: invite.respond takes a link (long token or short
// code), checks the ticket, signs a HavenInviteContactRequest with this
// node's key and posts it to /i/<token>/reply on the scaffold holding it.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Digipomps/GoCellProtocol/interop"
)

// InviteTransport performs one HTTP call and returns status and parsed JSON
// (nil when the body is not JSON). Status 0 means the host was not reached.
type InviteTransport func(ctx context.Context, method, url string, body any) (int, any)

// HTTPInviteTransport is net/http with Binding's 8 second timeout.
func HTTPInviteTransport(ctx context.Context, method, target string, body any) (int, any) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return 0, map[string]any{"code": "transport", "message": err.Error()}
		}
		reader = bytes.NewReader(data)
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return 0, map[string]any{"code": "transport", "message": err.Error()}
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return 0, map[string]any{"code": "transport", "message": "Fikk ikke kontakt med scaffoldet: " + err.Error()}
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	var parsed any
	if json.Unmarshal(raw, &parsed) != nil {
		parsed = nil
	}
	return response.StatusCode, parsed
}

// InvitationOptions configures InvitationCell.
type InvitationOptions struct {
	Descriptor        interop.IdentityPublicKeyDescriptor
	Sign              func([]byte) ([]byte, error)
	DisplayName       string
	LandingBase       string
	ContactEndpointID string
	Transport         InviteTransport
	Clock             func() time.Time
	Random            func(int) []byte
	NewUUID           func() string
}

type inviteOutboxEntry struct {
	ticket              *interop.HavenInviteTicket
	recipientName       string
	recipient           string
	channel             string
	state               string
	published           bool
	statusKey           string
	landingBase         string
	link, appLink       string
	selfContained       string
	shortLink           string
	subject, body       string
	preparedAt          time.Time
	sentAt              *time.Time
	openCount           int
	contactRequestCount int
	resultingEntityRef  *string
}

type inviteInboxEntry struct {
	request    *interop.HavenInviteContactRequest
	receivedAt time.Time
	accepted   bool
}

type InvitationCell struct {
	*GeneralCell
	opts       InvitationOptions
	stateMu    sync.Mutex
	settings   map[string]any
	outbox     []*inviteOutboxEntry
	inbox      []*inviteInboxEntry
	revoked    map[string]map[string]any
	sentReplys []map[string]any
	lastResult map[string]any
}

var (
	invitationReadableKeys = []string{"state", "invite.state", "invite.outbox", "invite.inbox", "invite.settings", "invite.revoked", "invite.lastResult", "invite.boundaryStatement"}
	invitationWritableKeys = []string{"invite.configure", "invite.prepare", "invite.publish", "invite.markSent", "invite.refreshStatus", "invite.pullContactRequests", "invite.acceptContactRequest", "invite.revoke", "invite.verify", "invite.clearOutbox", "invite.respond"}
)

func NewInvitationCell(owner *Identity, opts InvitationOptions) *InvitationCell {
	if opts.DisplayName == "" && opts.Descriptor.DisplayName != nil {
		opts.DisplayName = *opts.Descriptor.DisplayName
	}
	if opts.Transport == nil {
		opts.Transport = HTTPInviteTransport
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.Random == nil {
		opts.Random = func(n int) []byte { b := make([]byte, n); _, _ = rand.Read(b); return b }
	}
	if opts.NewUUID == nil {
		opts.NewUUID = NewUUID
	}
	cell := &InvitationCell{
		GeneralCell: NewGeneralCell(owner, "Invitation"),
		opts:        opts,
		settings: map[string]any{
			"landingBase":         strings.TrimSpace(opts.LandingBase),
			"fallbackLandingBase": "",
			"issuerDisplayName":   opts.DisplayName,
			"issuerEntityRef":     "",
			"contactEndpointID":   opts.ContactEndpointID,
			"defaultNote":         "",
			"ttlDays":             14,
			"maxContactRequests":  3,
			"autoPublish":         true,
		},
		revoked:    map[string]map[string]any{},
		lastResult: extOK("Klar til å lage en invitasjon.", false, nil),
	}
	for _, key := range invitationReadableKeys {
		cell.agreementTemplate.AddGrant("r---", key)
		cell.AddGetHandler(key, cell.read)
	}
	for _, key := range invitationWritableKeys {
		cell.agreementTemplate.AddGrant("rw--", key)
		cell.AddSetHandler(key, cell.write)
	}
	return cell
}

func (c *InvitationCell) now() time.Time { return c.opts.Clock().UTC() }

func (c *InvitationCell) fail(result map[string]any) map[string]any {
	c.lastResult = result
	return result
}

func (c *InvitationCell) done(result map[string]any) map[string]any {
	c.lastResult = result
	return result
}

func (c *InvitationCell) setting(key string) string { return extString(c.settings[key]) }

func (c *InvitationCell) settingInt(key string) int {
	n, _ := extInt(c.settings[key])
	return n
}

func (c *InvitationCell) bases() []string {
	seen := map[string]bool{}
	out := []string{}
	for _, base := range []string{c.setting("landingBase"), c.setting("fallbackLandingBase")} {
		base = strings.TrimSpace(base)
		if base != "" && !seen[strings.ToLower(base)] {
			seen[strings.ToLower(base)] = true
			out = append(out, base)
		}
	}
	return out
}

func (c *InvitationCell) entry(ticketID string) *inviteOutboxEntry {
	for _, e := range c.outbox {
		if e.ticket.TicketID == ticketID {
			return e
		}
	}
	return nil
}

func (c *InvitationCell) post(ctx context.Context, base, path string, body any) (int, any) {
	return c.opts.Transport(ctx, http.MethodPost, strings.Trim(base, " /")+path, body)
}

func toWireMap(model any) map[string]any {
	wire, err := interop.ToWire(model)
	if err != nil {
		return nil
	}
	// Through JSON, so []byte fields travel as base64 like Swift's.
	data, _ := interop.CanonicalJSON(wire, interop.EncoderOrder)
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	return out
}

func rejectedText(status int, body any) string {
	if obj, ok := body.(map[string]any); ok {
		if message, ok := obj["message"].(string); ok && message != "" {
			return message
		}
	}
	switch status {
	case 401, 403:
		return "ikke autorisert"
	case 404:
		return "billetten finnes ikke der"
	case 409:
		return "billetten er allerede registrert"
	case 0:
		return "fikk ikke kontakt med scaffoldet"
	}
	return fmt.Sprintf("HTTP %d", status)
}

func ok2xx(status int) bool { return status >= 200 && status < 300 }

func payloadObject(value any) map[string]any {
	if obj, ok := ObjectValue(value); ok {
		return obj
	}
	return map[string]any{}
}

func ticketIDOf(value any) string {
	if s := extString(value); s != "" {
		return s
	}
	return extString(payloadObject(value)["ticketID"])
}

func (c *InvitationCell) read(ctx context.Context, keypath string, requester *Identity) (any, error) {
	_, _ = ctx, requester
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	switch keypath {
	case "state", "invite.state":
		return c.stateObject(), nil
	case "invite.outbox":
		return c.outboxRows(), nil
	case "invite.inbox":
		return c.inboxRows(), nil
	case "invite.settings":
		return c.settingsObject(), nil
	case "invite.revoked":
		out := []any{}
		for _, row := range c.revoked {
			out = append(out, row)
		}
		return out, nil
	case "invite.lastResult":
		return c.lastResult, nil
	case "invite.boundaryStatement":
		return interop.InviteBoundaryLine, nil
	}
	return nil, nil
}

func (c *InvitationCell) write(ctx context.Context, keypath string, value any, requester *Identity) (any, error) {
	_ = requester
	value = NormalizeJSON(value)
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	switch keypath {
	case "invite.configure":
		return c.configure(value), nil
	case "invite.prepare":
		return c.prepare(ctx, value), nil
	case "invite.publish":
		return c.publish(ctx, value), nil
	case "invite.markSent":
		return c.markSent(value), nil
	case "invite.refreshStatus":
		return c.refreshStatus(ctx, value), nil
	case "invite.pullContactRequests":
		return c.pullContactRequests(ctx), nil
	case "invite.acceptContactRequest":
		return c.acceptContactRequest(value), nil
	case "invite.revoke":
		return c.revoke(ctx, value), nil
	case "invite.verify":
		return c.verify(ctx, value), nil
	case "invite.clearOutbox":
		return c.clearOutbox(value), nil
	case "invite.respond":
		return c.respond(ctx, value), nil
	}
	return extError("unsupported_keypath", "Ukjent invitasjonshandling.", nil), nil
}

// ---- settings ----------------------------------------------------------------

func normalizeHTTPURL(raw string) (string, bool) {
	value := strings.TrimRight(strings.TrimSpace(raw), "/")
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return "", false
	}
	return value, true
}

func (c *InvitationCell) configure(value any) map[string]any {
	payload := payloadObject(value)
	problems := []string{}
	for _, key := range []string{"landingBase", "fallbackLandingBase"} {
		raw, isString := payload[key].(string)
		if !isString {
			continue
		}
		if raw == "" && key == "fallbackLandingBase" {
			c.settings[key] = ""
		} else if normalized, ok := normalizeHTTPURL(raw); ok {
			c.settings[key] = normalized
		} else {
			problems = append(problems, "«"+raw+"» ser ikke ut som en https-adresse, så jeg lot den stå.")
		}
	}
	for _, key := range []string{"issuerDisplayName", "issuerEntityRef", "contactEndpointID", "defaultNote"} {
		if raw, isString := payload[key].(string); isString {
			c.settings[key] = raw
		}
	}
	if n, ok := extInt(payload["ttlDays"]); ok {
		c.settings["ttlDays"] = min(90, max(1, n))
	}
	if n, ok := extInt(payload["maxContactRequests"]); ok {
		c.settings["maxContactRequests"] = min(20, max(1, n))
	}
	if b, ok := payload["autoPublish"].(bool); ok {
		c.settings["autoPublish"] = b
	}
	message := "Invitasjonsoppsettet er lagret."
	if len(problems) > 0 {
		message = strings.Join(problems, " ")
	}
	return c.done(extOK(message, true, map[string]any{"settings": c.settingsObject()}))
}

func (c *InvitationCell) settingsObject() map[string]any {
	hasScaffold := len(c.bases()) > 0
	auto, _ := c.settings["autoPublish"].(bool)
	mode := "appLinkOnly"
	if hasScaffold && auto {
		mode = "short"
	} else if hasScaffold {
		mode = "selfContained"
	}
	out := map[string]any{"hasScaffold": hasScaffold, "canReceiveReplies": c.setting("contactEndpointID") != "", "linkMode": mode}
	for k, v := range c.settings {
		out[k] = v
	}
	return out
}

// ---- prepare -------------------------------------------------------------------

func normalizePhone(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, trimmed)
	switch {
	case strings.HasPrefix(trimmed, "+") && len(digits) >= 8:
		return "+" + digits, true
	case strings.HasPrefix(trimmed, "00") && len(digits) >= 10:
		return "+" + digits[2:], true
	case len(digits) == 8: // Norwegian national number, as Binding's default region
		return "+47" + digits, true
	}
	return "", false
}

func (c *InvitationCell) prepare(ctx context.Context, value any) map[string]any {
	payload := payloadObject(value)
	if s := extString(value); s != "" {
		payload = map[string]any{"recipient": s}
	}
	force, _ := payload["force"].(bool)
	raw := extString(payload["recipient"])
	if raw == "" {
		raw = extString(payload["endpoint"])
	}
	if raw == "" {
		return c.fail(extError("bad_request", "Si hvem invitasjonen gjelder: `recipient` (e-post eller telefon).", nil))
	}
	requested := strings.ToLower(extString(payload["channel"]))
	kind, normalized := "", ""
	if requested != "sms" && requested != "phone" {
		if email, ok := interop.NormalizeEmail(raw); ok {
			kind, normalized = "email", email
		}
	}
	if kind == "" {
		if phone, ok := normalizePhone(raw); ok {
			kind, normalized = "phone", phone
		}
	}
	if kind == "" {
		return c.fail(extError("no_channel", "«"+raw+"» er verken en e-postadresse eller et telefonnummer jeg kan bruke.", nil))
	}
	channel := "email"
	if kind == "phone" {
		channel = "sms"
	}
	audience := interop.DisclosureToken(kind, normalized)
	display := extString(payload["recipientDisplayName"])
	if display == "" {
		display = extString(payload["displayName"])
	}
	if display == "" {
		display = raw
	}
	now := c.now()
	if !force {
		for _, e := range c.outbox {
			if e.ticket.AudienceToken == audience && !e.ticket.IsExpired(float64(now.Unix())) && (e.state == "prepared" || e.state == "sent" || e.state == "opened") {
				return c.fail(extError("already_invited", display+" har allerede en åpen invitasjon. Send `force: true` hvis du vil lage en ny.", map[string]any{"ticketID": e.ticket.TicketID}))
			}
		}
	}
	bases := c.bases()
	auto, _ := c.settings["autoPublish"].(bool)
	if channel == "sms" && !(auto && len(bases) > 0) {
		return c.fail(extError("sms_requires_publication", "SMS krever kort lenke, og kort lenke krever at billetten registreres hos scaffoldet.", nil))
	}
	given := extString(payload["givenName"])
	if given == "" && !strings.Contains(display, "@") {
		if fields := strings.Fields(display); len(fields) > 0 {
			given = fields[0]
		}
	}
	note := extString(payload["note"])
	if note == "" {
		note = c.setting("defaultNote")
	}
	issuerName := c.setting("issuerDisplayName")
	ticket, err := interop.BuildTicket(c.opts.Descriptor, c.opts.Sign, interop.TicketInput{
		IssuerDisplayName: issuerName,
		AudienceToken:     audience,
		AudienceKind:      kind,
		ContactEndpointID: c.setting("contactEndpointID"),
		IssuerEntityRef:   c.setting("issuerEntityRef"),
		GreetingName:      given,
		Note:              note,
		TTLDays:           c.settingInt("ttlDays"),
		Now:               now,
		Random:            c.opts.Random,
		NewUUID:           c.opts.NewUUID,
	})
	if err != nil {
		return c.fail(extError("signing_failed", "Kunne ikke signere invitasjonen. Uten signatur sender jeg den ikke.", nil))
	}
	entry := &inviteOutboxEntry{ticket: ticket, recipientName: display, recipient: raw, channel: channel, state: "prepared", preparedAt: now}
	warning := ""
	attempted := auto && len(bases) > 0
	if attempted {
		key, base, failure := c.publishTicket(ctx, ticket, bases)
		if failure == "" {
			entry.published, entry.statusKey, entry.landingBase = true, key, base
			if base != c.setting("landingBase") {
				warning = "Registrert hos " + base + ", den primære landingssiden svarte ikke."
			}
		} else {
			warning = failure
			if channel == "sms" {
				return c.fail(extError("publish_failed", "SMS krever kort lenke, og registreringen hos scaffoldet feilet: "+failure, nil))
			}
		}
	}
	base := entry.landingBase
	if base == "" && len(bases) > 0 {
		base = bases[0]
	}
	entry.appLink = interop.AppLink(ticket)
	if base != "" {
		entry.selfContained = interop.UniversalLink(ticket, base)
	}
	if entry.published {
		entry.shortLink = interop.ShortLink(ticket, base)
	}
	switch {
	case entry.published:
		entry.link = firstNonEmpty(entry.shortLink, entry.selfContained, entry.appLink)
	case !attempted:
		entry.link = firstNonEmpty(entry.selfContained, entry.appLink)
	default:
		entry.link = entry.appLink
		warning = "Ingen landingsside svarte (" + warning + "), så invitasjonen fikk en haven://-lenke som bare virker der HAVEN allerede er installert."
	}
	entry.subject, entry.body = composeInvite(ticket, entry.link, channel)
	kept := []*inviteOutboxEntry{entry}
	for _, e := range c.outbox {
		if e.ticket.TicketID != ticket.TicketID {
			kept = append(kept, e)
		}
	}
	c.outbox = kept

	channelText := "e-post"
	if channel == "sms" {
		channelText = "SMS"
	}
	headline := "Invitasjon til " + display + " er klar på " + channelText + "."
	capabilities := []any{}
	for _, capability := range ticket.Capabilities {
		capabilities = append(capabilities, capability)
	}
	extra := map[string]any{
		"ticketID": ticket.TicketID, "displayName": display, "channel": channel, "recipient": raw,
		"humanCode": ticket.HumanCode, "expiresAt": ticket.ExpiresAt, "expiresAtText": readableTime(time.Unix(ticket.ExpiresAt, 0)),
		"link": entry.link, "shortLink": entry.shortLink, "selfContainedLink": entry.selfContained, "appLink": entry.appLink,
		"linkLength": len(entry.link), "published": entry.published, "subject": entry.subject, "body": entry.body,
		"boundaryStatement": interop.InviteBoundary(ticket), "capabilities": capabilities,
		"canReceiveContactRequest": ticket.CanReceiveContactRequest(), "requiresUserToPressSend": true,
		"nextAction": "invite.markSent", "outbox": c.outboxRows(),
	}
	if warning != "" {
		extra["publicationWarning"] = warning
		headline += " " + warning
	}
	return c.done(extOK(headline, true, extra))
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func composeInvite(ticket *interop.HavenInviteTicket, link, channel string) (string, string) {
	greeting := "Hei!"
	if ticket.GreetingName != nil && *ticket.GreetingName != "" {
		greeting = "Hei " + *ticket.GreetingName + "!"
	}
	if channel == "sms" {
		return "", fmt.Sprintf("%s %s inviterer deg til HAVEN: %s (kode %s)", greeting, ticket.IssuerDisplayName, link, ticket.HumanCode)
	}
	note := ""
	if ticket.Note != nil && *ticket.Note != "" {
		note = "\n\n" + *ticket.Note
	}
	subject := ticket.IssuerDisplayName + " inviterer deg til HAVEN"
	body := fmt.Sprintf("%s%s\n\n%s\n\n%s\n\nKoden er %s. Invitasjonen gjelder til %s.", greeting, note, interop.InviteBoundary(ticket), link, ticket.HumanCode, readableTime(time.Unix(ticket.ExpiresAt, 0)))
	return subject, body
}

// publishTicket returns statusKey and landing base from the first host that
// accepts, or the last failure text.
func (c *InvitationCell) publishTicket(ctx context.Context, ticket *interop.HavenInviteTicket, bases []string) (string, string, string) {
	if len(bases) == 0 {
		return "", "", "Ingen landingsside er satt opp, så billetten ble ikke registrert."
	}
	key := interop.MakeStatusKey(c.opts.Random)
	publication, err := interop.BuildPublication(ticket, c.opts.Sign, key, c.settingInt("maxContactRequests"), c.now())
	if err != nil {
		return "", "", "kunne ikke signere registreringen"
	}
	body := toWireMap(publication)
	failure := ""
	for _, base := range bases {
		status, answer := c.post(ctx, base, "/i/api/publish", body)
		if ok2xx(status) {
			return key, base, ""
		}
		failure = "Scaffoldet avviste forespørselen: " + rejectedText(status, answer)
	}
	return "", "", failure
}

func (c *InvitationCell) publish(ctx context.Context, value any) map[string]any {
	ticketID := ticketIDOf(value)
	entry := c.entry(ticketID)
	if entry == nil {
		return c.fail(extError("not_found", "Fant ingen invitasjon med den id-en.", nil))
	}
	if entry.published {
		return extOK("Billetten er allerede registrert.", false, nil)
	}
	key, base, failure := c.publishTicket(ctx, entry.ticket, c.bases())
	if failure != "" {
		return c.fail(extError("publish_failed", failure, nil))
	}
	entry.published, entry.statusKey, entry.landingBase = true, key, base
	entry.shortLink = interop.ShortLink(entry.ticket, base)
	entry.link = firstNonEmpty(entry.shortLink, entry.link)
	return c.done(extOK("Billetten er registrert. Kort lenke: "+entry.shortLink, true, map[string]any{"ticketID": ticketID, "shortLink": entry.shortLink}))
}

func (c *InvitationCell) markSent(value any) map[string]any {
	entry := c.entry(ticketIDOf(value))
	if entry == nil {
		return c.fail(extError("not_found", "Fant ingen invitasjon med den id-en.", nil))
	}
	if entry.state == "prepared" {
		now := c.now()
		entry.state, entry.sentAt = "sent", &now
	}
	return c.done(extOK("Merket som sendt til "+entry.recipientName+".", true, map[string]any{"ticketID": entry.ticket.TicketID}))
}

// ---- status and replies ------------------------------------------------------

func (c *InvitationCell) refreshStatus(ctx context.Context, value any) map[string]any {
	only := extString(payloadObject(value)["ticketID"])
	candidates := []*inviteOutboxEntry{}
	for _, e := range c.outbox {
		if !e.published || e.statusKey == "" {
			continue
		}
		if (only != "" && e.ticket.TicketID == only) || (only == "" && (e.state == "prepared" || e.state == "sent" || e.state == "opened")) {
			candidates = append(candidates, e)
		}
	}
	if len(candidates) == 0 {
		return extOK("Ingen registrerte invitasjoner å hente status for.", false, nil)
	}
	updated, joined := 0, []string{}
	mapping := map[string]string{"opened": "opened", "accepted": "joined", "declined": "declined", "revoked": "blocked"}
	for _, e := range candidates {
		status, answer := c.post(ctx, e.landingBase, "/i/api/status", map[string]any{"ticketID": e.ticket.TicketID, "statusKey": e.statusKey})
		report, isObject := answer.(map[string]any)
		if !ok2xx(status) || !isObject {
			continue
		}
		state := extString(report["state"])
		known := false
		for _, l := range interop.InviteLifecycles {
			known = known || l == state
		}
		if !known {
			continue
		}
		e.openCount, _ = extInt(report["openCount"])
		e.contactRequestCount, _ = extInt(report["contactRequestCount"])
		if ref := extString(report["resultingEntityRef"]); ref != "" {
			e.resultingEntityRef = &ref
		}
		previous := e.state
		if mapped, ok := mapping[state]; ok {
			e.state = mapped
		}
		if e.state != previous {
			updated++
			if e.state == "joined" {
				joined = append(joined, e.recipientName)
			}
		}
	}
	message := "Ingen endring siden sist."
	if updated > 0 && len(joined) == 0 {
		message = fmt.Sprintf("%d invitasjoner har fått ny status.", updated)
	} else if len(joined) > 0 {
		message = strings.Join(joined, ", ") + " er i HAVEN nå."
	}
	return c.done(extOK(message, updated > 0, map[string]any{"updatedCount": updated, "outbox": c.outboxRows()}))
}

func (c *InvitationCell) pullContactRequests(ctx context.Context) map[string]any {
	candidates := []*inviteOutboxEntry{}
	for _, e := range c.outbox {
		if e.published && e.statusKey != "" {
			candidates = append(candidates, e)
		}
	}
	if len(candidates) == 0 {
		return extOK("Ingen registrerte invitasjoner å hente svar for.", false, nil)
	}
	received, rejected, names := 0, 0, []string{}
	for _, e := range candidates {
		status, answer := c.post(ctx, e.landingBase, "/i/api/requests", map[string]any{"ticketID": e.ticket.TicketID, "statusKey": e.statusKey})
		envelope, isObject := answer.(map[string]any)
		if !ok2xx(status) || !isObject {
			continue
		}
		items, _ := envelope["requests"].([]any)
		for _, item := range items {
			obj, isObj := item.(map[string]any)
			var request interop.HavenInviteContactRequest
			// The scaffold only relayed this. Verify it here, against the ticket it answers.
			if !isObj || !decodeObject(obj, &request) || interop.VerifyContactRequest(&request, e.ticket, c.now()) != nil {
				rejected++
				continue
			}
			duplicate := false
			for _, row := range c.inbox {
				duplicate = duplicate || row.request.RequestID == request.RequestID
			}
			if duplicate {
				continue
			}
			copy := request
			c.inbox = append([]*inviteInboxEntry{{request: &copy, receivedAt: c.now()}}, c.inbox...)
			received++
			names = append(names, request.SenderDisplayName)
		}
	}
	message := "Ingen nye svar."
	if received > 0 {
		message = strings.Join(names, ", ") + " har svart på invitasjonen. Se over og godta for å opprette kontakten."
	}
	return c.done(extOK(message, received > 0, map[string]any{"receivedCount": received, "rejectedCount": rejected, "inbox": c.inboxRows()}))
}

func (c *InvitationCell) acceptContactRequest(value any) map[string]any {
	requestID := extString(value)
	if requestID == "" {
		requestID = extString(payloadObject(value)["requestID"])
	}
	for _, row := range c.inbox {
		if row.request.RequestID != requestID {
			continue
		}
		row.accepted = true
		if e := c.entry(row.request.TicketID); e != nil {
			e.state = "joined"
			e.resultingEntityRef = row.request.SenderEntityRef
		}
		return c.done(extOK(row.request.SenderDisplayName+" er lagt til som kontakt.", true, map[string]any{
			"requestID": requestID, "sender": toWireMap(&row.request.Sender),
			"senderEntityRef": deref(row.request.SenderEntityRef), "senderEndpoint": deref(row.request.SenderEndpoint),
		}))
	}
	return c.fail(extError("not_found", "Fant ikke det svaret.", nil))
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ---- revoke and verify -------------------------------------------------------

func (c *InvitationCell) revoke(ctx context.Context, value any) map[string]any {
	ticketID := ticketIDOf(value)
	if ticketID == "" {
		return extError("missing_ticket", "Mangler `ticketID`.", nil)
	}
	reason := extString(payloadObject(value)["reason"])
	if reason == "" {
		reason = "Trukket tilbake av avsender."
	}
	c.revoked[ticketID] = map[string]any{"ticketID": ticketID, "reason": reason, "revokedAtText": readableTime(c.now())}
	entry := c.entry(ticketID)
	if entry != nil {
		entry.state = "declined"
	}
	remote := "Lenken virker fortsatt for den som allerede har den, den ble aldri registrert hos noe scaffold."
	if entry != nil && entry.published {
		notice, err := interop.BuildRevocation(ticketID, c.opts.Descriptor, c.opts.Sign, reason, c.now())
		if err == nil {
			status, answer := c.post(ctx, entry.landingBase, "/i/api/revoke", toWireMap(notice))
			if ok2xx(status) {
				remote = "Lenken slutter å virke med én gang."
			} else {
				remote = "Lokalt trukket tilbake, men scaffoldet svarte ikke: " + rejectedText(status, answer) + " Prøv igjen."
			}
		}
	}
	return c.done(extOK("Invitasjonen er trukket tilbake. "+remote, true, map[string]any{"ticketID": ticketID}))
}

// resolveToken returns the ticket token behind a link and the landing base.
// A short code is looked up at the landing that holds it.
func (c *InvitationCell) resolveToken(ctx context.Context, link string, payload map[string]any) (string, string, map[string]any) {
	token, err := interop.TokenFromLink(link)
	if err != nil {
		failure := err.(*interop.LinkFailure)
		return "", "", extError(failure.Code, failure.Message, nil)
	}
	base := ""
	if parsed, err := url.Parse(strings.TrimSpace(link)); err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != "" {
		base = parsed.Scheme + "://" + parsed.Host
	}
	if base == "" {
		base = extString(payload["landingBase"])
	}
	if base == "" && len(c.bases()) > 0 {
		base = c.bases()[0]
	}
	if interop.LooksLikeHumanCode(token) {
		if base == "" {
			return "", "", extError("not_configured", "En kort kode trenger adressen til scaffoldet som holder invitasjonen.", nil)
		}
		status, answer := c.opts.Transport(ctx, http.MethodGet, strings.Trim(base, " /")+"/i/"+token, nil)
		obj, _ := answer.(map[string]any)
		if !ok2xx(status) || extString(obj["ticketToken"]) == "" {
			return "", "", extError("not_available", rejectedText(status, answer), nil)
		}
		token = extString(obj["ticketToken"])
	}
	return token, base, nil
}

func (c *InvitationCell) verify(ctx context.Context, value any) map[string]any {
	payload := payloadObject(value)
	link := extString(value)
	if link == "" {
		link = extString(payload["link"])
	}
	var ticket *interop.HavenInviteTicket
	if link != "" {
		token, _, problem := c.resolveToken(ctx, link, payload)
		if problem != nil {
			return problem
		}
		var err error
		ticket, err = interop.DecodeTicketToken(token)
		if err != nil {
			failure := err.(*interop.LinkFailure)
			return extError(failure.Code, failure.Message, nil)
		}
	} else if embedded, ok := ObjectValue(payload["ticket"]); ok {
		var decoded interop.HavenInviteTicket
		if !decodeObject(embedded, &decoded) {
			return extError("bad_link", "Invitasjonen kunne ikke leses.", nil)
		}
		ticket = &decoded
	} else {
		return extError("bad_request", "Send `link` eller `ticket`.", nil)
	}
	revoked := map[string]bool{}
	for id := range c.revoked {
		revoked[id] = true
	}
	options := interop.TicketOptions{RevokedTicketIDs: revoked}
	if expected := extString(payload["expectedAudienceToken"]); expected != "" {
		options.ExpectedAudienceToken = &expected
	}
	return interop.InviteVerdictPayload(interop.VerifyInvite(ticket, c.now(), options), ticket)
}

func (c *InvitationCell) clearOutbox(value any) map[string]any {
	onlyResolved := true
	if b, ok := payloadObject(value)["onlyResolved"].(bool); ok {
		onlyResolved = b
	}
	before := len(c.outbox)
	kept := []*inviteOutboxEntry{}
	for _, e := range c.outbox {
		if onlyResolved && e.state != "joined" && e.state != "declined" {
			kept = append(kept, e)
		}
	}
	c.outbox = kept
	removed := before - len(kept)
	return extOK(fmt.Sprintf("Ryddet %d invitasjoner ut av listen.", removed), removed > 0, nil)
}

// ---- the invitee side ----------------------------------------------------------

func (c *InvitationCell) respond(ctx context.Context, value any) map[string]any {
	payload := payloadObject(value)
	link := extString(value)
	if link == "" {
		link = extString(payload["link"])
	}
	if link == "" {
		return c.fail(extError("bad_request", "Send `link`: invitasjonslenken du fikk.", nil))
	}
	token, base, problem := c.resolveToken(ctx, link, payload)
	if problem != nil {
		return c.fail(problem)
	}
	ticket, err := interop.DecodeTicketToken(token)
	if err != nil {
		failure := err.(*interop.LinkFailure)
		return c.fail(extError(failure.Code, failure.Message, nil))
	}
	verdict := interop.VerifyInvite(ticket, c.now(), interop.TicketOptions{})
	if !verdict.IsValid {
		return c.fail(extError(verdict.Code, verdict.Reason, map[string]any{"verdict": interop.InviteVerdictPayload(verdict, ticket)}))
	}
	if !ticket.CanReceiveContactRequest() {
		return c.fail(extError("no_reply_channel", ticket.IssuerDisplayName+" har ikke åpnet for svar på denne invitasjonen.", nil))
	}
	if base == "" {
		return c.fail(extError("not_configured", "Vet ikke hvilket scaffold som holder invitasjonen. Send `landingBase`.", nil))
	}
	name := firstNonEmpty(extString(payload["displayName"]), c.setting("issuerDisplayName"), c.opts.DisplayName)
	// The scaffold reads a reply without an entity ref as "declined".
	entityRef := firstNonEmpty(extString(payload["senderEntityRef"]), c.setting("issuerEntityRef"), "cell:///EntityAnchor")
	request, err := interop.BuildContactRequest(ticket, c.opts.Descriptor, c.opts.Sign, interop.ContactRequestInput{
		SenderDisplayName: name,
		SenderEntityRef:   entityRef,
		SenderEndpoint:    firstNonEmpty(extString(payload["senderEndpoint"]), c.setting("contactEndpointID")),
		Message:           extString(payload["message"]),
		Now:               c.now(),
		Random:            c.opts.Random,
		NewUUID:           c.opts.NewUUID,
	})
	if err != nil {
		return c.fail(extError("signing_failed", "Kunne ikke signere svaret.", nil))
	}
	status, answer := c.opts.Transport(ctx, http.MethodPost, strings.Trim(base, " /")+"/i/"+token+"/reply", toWireMap(request))
	obj, _ := answer.(map[string]any)
	if !ok2xx(status) {
		code := extString(obj["code"])
		if code == "" {
			code = "rejected"
		}
		return c.fail(extError(code, rejectedText(status, answer), map[string]any{"httpStatus": status}))
	}
	c.sentReplys = append([]map[string]any{{"requestID": request.RequestID, "ticketID": ticket.TicketID, "issuer": ticket.IssuerDisplayName}}, c.sentReplys...)
	message := firstNonEmpty(extString(obj["message"]), "Svaret er levert.")
	return c.done(extOK(message, true, map[string]any{
		"requestID": request.RequestID, "ticketID": ticket.TicketID,
		"issuerDisplayName": ticket.IssuerDisplayName, "issuerIdentityUUID": ticket.Issuer.UUID,
	}))
}

// ---- presentation --------------------------------------------------------------

func (c *InvitationCell) outboxRows() []any {
	now := float64(c.now().Unix())
	rows := []any{}
	for _, e := range c.outbox {
		sent := ""
		if e.sentAt != nil {
			sent = readableTime(*e.sentAt)
		}
		_, revoked := c.revoked[e.ticket.TicketID]
		rows = append(rows, map[string]any{
			"ticketID": e.ticket.TicketID, "displayName": e.recipientName, "recipient": e.recipient, "channel": e.channel,
			"state": e.state, "humanCode": e.ticket.HumanCode, "link": e.link, "published": e.published,
			"openCount": e.openCount, "contactRequestCount": e.contactRequestCount,
			"preparedAtText": readableTime(e.preparedAt), "sentAtText": sent,
			"expired": e.ticket.IsExpired(now), "revoked": revoked,
		})
	}
	return rows
}

func (c *InvitationCell) inboxRows() []any {
	rows := []any{}
	for _, row := range c.inbox {
		line := row.request.SenderDisplayName + " vil koble seg til deg"
		if row.accepted {
			line = "Lagt inn som kontakt"
		}
		rows = append(rows, map[string]any{
			"requestID": row.request.RequestID, "ticketID": row.request.TicketID, "displayName": row.request.SenderDisplayName,
			"message": deref(row.request.Message), "endpoint": deref(row.request.SenderEndpoint),
			"senderEntityRef": deref(row.request.SenderEntityRef), "receivedAtText": readableTime(row.receivedAt),
			"delivered": row.accepted, "statusLine": line,
		})
	}
	return rows
}

func (c *InvitationCell) stateObject() map[string]any {
	pending, waiting, sent, joined := 0, 0, 0, 0
	for _, row := range c.inbox {
		if !row.accepted {
			pending++
		}
	}
	for _, e := range c.outbox {
		switch e.state {
		case "prepared":
			waiting++
		case "sent", "opened":
			sent++
		case "joined":
			joined++
		}
	}
	replies := []any{}
	for _, r := range c.sentReplys {
		replies = append(replies, r)
	}
	return map[string]any{
		"schema": "haven.invite.state.v1", "settings": c.settingsObject(), "outbox": c.outboxRows(), "inbox": c.inboxRows(),
		"sentReplies": replies, "pendingReplyCount": pending,
		"counts":            map[string]any{"total": len(c.outbox), "waiting": waiting, "sent": sent, "joined": joined},
		"boundaryStatement": interop.InviteBoundaryLine, "lastResult": c.lastResult,
		"privacyBoundary": "owner_local_ticket_mint_publication_is_opt_in_no_automatic_send",
	}
}
