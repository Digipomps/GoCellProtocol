// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

// InviteLanding is the scaffold end of an invitation, as CellScaffold's
// VaporInviteLanding: same routes, bodies, status codes and
// {"code","message"} answers, so a Swift, Python or Go issuer can publish
// here and a Swift, Python or Go invitee can reply here.
//
//	POST /i/api/publish   signed HavenInvitePublication
//	POST /i/api/revoke    signed HavenInviteRevocationNotice
//	POST /i/api/status    {ticketID, statusKey} -> HavenInviteStatusReport
//	POST /i/api/requests  {ticketID, statusKey} -> {requests: [...]}
//	GET  /i/<token|code>  landing page
//	POST /i/<token|code>/reply  signed HavenInviteContactRequest as JSON
//
// The store is in memory. Like Swift it keeps only a digest of the status
// key, redacts opening telemetry from the status answer, deletes replies once
// collected, and drops expired tickets after a day of grace.
//
// One addition: GET /i/<...> with Accept: application/json answers with the
// verdict payload and the ticket token instead of HTML, so an app can resolve
// a six-character code. Swift serves only HTML there.

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Digipomps/GoCellProtocol/interop"
)

const inviteExpiredGrace = 24 * time.Hour

const inviteUnavailable = "Koden finnes ikke, eller invitasjonen er ikke lenger aktiv. Be den som inviterte deg om en ny."

type inviteTicketRecord struct {
	ticketID, humanCode, ticketToken, audienceToken string
	issuerIdentityUUID, issuerDisplayName           string
	statusKeyDigest                                 string
	expiresAt                                       time.Time
	maxContactRequests                              int
	openCount                                       int
	firstOpenedAt, respondedAt, revokedAt           *time.Time
	resultingEntityRef                              *string
	revocationReason                                string
}

func (r *inviteTicketRecord) lifecycle(now time.Time) string {
	switch {
	case r.revokedAt != nil:
		return "revoked"
	case r.respondedAt != nil && r.resultingEntityRef == nil:
		return "declined"
	case r.respondedAt != nil:
		return "accepted"
	case now.After(r.expiresAt):
		return "expired"
	case r.openCount > 0:
		return "opened"
	}
	return "published"
}

func (r *inviteTicketRecord) matchesStatusKey(candidate string) bool {
	return subtle.ConstantTimeCompare([]byte(interop.StatusKeyDigest(candidate)), []byte(r.statusKeyDigest)) == 1
}

type inviteRequestRecord struct {
	requestID, ticketID, payloadJSON, senderDisplayName string
}

type inviteRateLimiter struct {
	window, block time.Duration
	max           int
	attempts      map[string][]time.Time
	blockedUntil  map[string]time.Time
}

func newInviteRateLimiter(window time.Duration, max int, block time.Duration) *inviteRateLimiter {
	return &inviteRateLimiter{window: window, block: block, max: max, attempts: map[string][]time.Time{}, blockedUntil: map[string]time.Time{}}
}

// record returns seconds to wait when blocked, else 0.
func (l *inviteRateLimiter) record(key string, now time.Time) int {
	if until, ok := l.blockedUntil[key]; ok && until.After(now) {
		return int(until.Sub(now).Seconds()) + 1
	}
	kept := []time.Time{}
	for _, at := range l.attempts[key] {
		if now.Sub(at) < l.window {
			kept = append(kept, at)
		}
	}
	kept = append(kept, now)
	l.attempts[key] = kept
	if len(kept) > l.max {
		l.blockedUntil[key] = now.Add(l.block)
		return int(l.block.Seconds())
	}
	return 0
}

// InviteLanding is an http.Handler for the /i/ prefix.
type InviteLanding struct {
	Clock     func() time.Time
	RateLimit bool

	mu        sync.Mutex
	tickets   map[string]*inviteTicketRecord
	requests  []*inviteRequestRecord
	shortCode *inviteRateLimiter
	replies   *inviteRateLimiter
}

func NewInviteLanding(clock func() time.Time) *InviteLanding {
	if clock == nil {
		clock = time.Now
	}
	return &InviteLanding{
		Clock:     clock,
		RateLimit: true,
		tickets:   map[string]*inviteTicketRecord{},
		shortCode: newInviteRateLimiter(10*time.Minute, 20, 15*time.Minute),
		replies:   newInviteRateLimiter(10*time.Minute, 8, 30*time.Minute),
	}
}

// InviteResponse is one answer: status, content type and body.
type InviteResponse struct {
	Status      int
	ContentType string
	Body        []byte
	Location    string
}

func inviteJSON(status int, payload any) InviteResponse {
	body, _ := json.Marshal(payload)
	return InviteResponse{Status: status, ContentType: "application/json; charset=utf-8", Body: body}
}

func inviteCode(status int, code, message string, extra ...string) InviteResponse {
	payload := map[string]string{"code": code, "message": message}
	for i := 0; i+1 < len(extra); i += 2 {
		payload[extra[i]] = extra[i+1]
	}
	return inviteJSON(status, payload)
}

func inviteFailureMessage(err error) (string, string) {
	code := interop.VerdictOf(err)
	if strings.HasPrefix(code, "ticket_invalid:") {
		return code, fmt.Sprintf("Invitasjonen meldingen viser til gjelder ikke (%s).", strings.TrimPrefix(code, "ticket_invalid:"))
	}
	messages := map[string]string{
		"unsigned":        "Meldingen er ikke signert.",
		"issuer_mismatch": "Signaturen tilhører en annen identitet enn den meldingen oppgir.",
		"bad_signature":   "Signaturen stemmer ikke.",
		"ticket_mismatch": "Meldingen passer ikke billetten.",
		"expired":         "Meldingen er utløpt.",
		"ticket_expired":  "Invitasjonen meldingen viser til er utløpt.",
	}
	if message, ok := messages[code]; ok {
		return code, message
	}
	return code, code
}

func (l *InviteLanding) byCode(code string) *inviteTicketRecord {
	for _, record := range l.tickets {
		if record.humanCode == code {
			return record
		}
	}
	return nil
}

// PurgeExpired drops tickets past a day of grace, with their replies.
func (l *InviteLanding) PurgeExpired() (tickets, requests int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := l.Clock().Add(-inviteExpiredGrace)
	gone := map[string]bool{}
	for id, record := range l.tickets {
		if record.expiresAt.Before(cutoff) {
			gone[id] = true
			delete(l.tickets, id)
		}
	}
	kept := l.requests[:0]
	for _, row := range l.requests {
		if gone[row.ticketID] {
			requests++
			continue
		}
		kept = append(kept, row)
	}
	l.requests = kept
	return len(gone), requests
}

// Publish handles POST /i/api/publish.
func (l *InviteLanding) Publish(body []byte) InviteResponse {
	var publication interop.HavenInvitePublication
	if interop.Decode(body, &publication) != nil {
		return inviteCode(400, "bad_request", "Ugyldig registrering.")
	}
	now := l.Clock()
	ticket, err := interop.VerifyPublication(&publication, now)
	if err != nil {
		code, message := inviteFailureMessage(err)
		return inviteCode(403, code, message)
	}
	if ticket.IsExpired(float64(now.UnixNano()) / 1e9) {
		return inviteCode(400, "expired", "Billetten er allerede utløpt.")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if existing, ok := l.tickets[publication.TicketID]; ok {
		if existing.ticketToken != publication.TicketToken {
			return inviteCode(409, "already_published", "En annen billett er allerede registrert med den id-en.")
		}
		return inviteCode(200, "ok", "Allerede registrert.")
	}
	if l.byCode(publication.HumanCode) != nil {
		return inviteCode(409, "code_taken", "Koden er allerede i bruk. Lag en ny invitasjon.")
	}
	limit := int(publication.MaxContactRequests)
	if limit < 1 {
		limit = 1
	}
	if limit > 20 {
		limit = 20
	}
	l.tickets[publication.TicketID] = &inviteTicketRecord{
		ticketID:           publication.TicketID,
		humanCode:          publication.HumanCode,
		ticketToken:        publication.TicketToken,
		audienceToken:      publication.AudienceToken,
		issuerIdentityUUID: publication.IssuerIdentityUUID,
		issuerDisplayName:  ticket.IssuerDisplayName,
		statusKeyDigest:    interop.StatusKeyDigest(publication.StatusKey),
		expiresAt:          time.Unix(ticket.ExpiresAt, 0),
		maxContactRequests: limit,
	}
	return inviteCode(200, "ok", "Registrert.", "humanCode", publication.HumanCode)
}

// Revoke handles POST /i/api/revoke.
func (l *InviteLanding) Revoke(body []byte) InviteResponse {
	var notice interop.HavenInviteRevocationNotice
	if interop.Decode(body, &notice) != nil {
		return inviteCode(400, "bad_request", "Ugyldig tilbakekalling.")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	record, ok := l.tickets[notice.TicketID]
	if !ok {
		return inviteCode(404, "not_found", "Ukjent billett.")
	}
	ticket, err := interop.DecodeTicketToken(record.ticketToken)
	if err != nil {
		return inviteCode(400, "bad_request", "Ugyldig tilbakekalling.")
	}
	if err := interop.VerifyRevocationNotice(&notice, ticket); err != nil {
		code, message := inviteFailureMessage(err)
		return inviteCode(403, code, message)
	}
	now := l.Clock()
	record.revokedAt = &now
	reason := notice.Reason
	if len([]rune(reason)) > 240 {
		reason = string([]rune(reason)[:240])
	}
	record.revocationReason = reason
	return inviteCode(200, "ok", "Trukket tilbake.")
}

func (l *InviteLanding) authorised(body []byte) (*inviteTicketRecord, bool) {
	var query struct {
		TicketID  *string `json:"ticketID"`
		StatusKey *string `json:"statusKey"`
	}
	if json.Unmarshal(body, &query) != nil || query.TicketID == nil || query.StatusKey == nil {
		return nil, false
	}
	record, ok := l.tickets[*query.TicketID]
	// Same answer for "wrong key" and "no such ticket".
	if !ok || !record.matchesStatusKey(*query.StatusKey) {
		return nil, true
	}
	return record, true
}

func (l *InviteLanding) countRequests(ticketID string) int {
	count := 0
	for _, row := range l.requests {
		if row.ticketID == ticketID {
			count++
		}
	}
	return count
}

// Status handles POST /i/api/status.
func (l *InviteLanding) Status(body []byte) InviteResponse {
	l.mu.Lock()
	defer l.mu.Unlock()
	record, wellFormed := l.authorised(body)
	if !wellFormed {
		return inviteCode(400, "bad_request", "Mangler ticketID eller statusKey.")
	}
	if record == nil {
		return inviteCode(404, "not_found", "Ukjent billett.")
	}
	state := record.lifecycle(l.Clock())
	if state == "opened" {
		state = "published"
	}
	var responded *int64
	if record.respondedAt != nil {
		value := record.respondedAt.Unix()
		responded = &value
	}
	return inviteJSON(200, interop.InviteStatusReport(record.ticketID, state, responded, l.countRequests(record.ticketID), record.resultingEntityRef))
}

// Collect handles POST /i/api/requests and deletes what it hands out.
func (l *InviteLanding) Collect(body []byte) InviteResponse {
	l.mu.Lock()
	defer l.mu.Unlock()
	record, wellFormed := l.authorised(body)
	if !wellFormed {
		return inviteCode(400, "bad_request", "Mangler ticketID eller statusKey.")
	}
	if record == nil {
		return inviteCode(404, "not_found", "Ukjent billett.")
	}
	payloads := []json.RawMessage{}
	kept := []*inviteRequestRecord{}
	for _, row := range l.requests {
		if row.ticketID == record.ticketID {
			payloads = append(payloads, json.RawMessage(row.payloadJSON))
			continue
		}
		kept = append(kept, row)
	}
	l.requests = kept
	return inviteJSON(200, map[string]any{"requests": payloads})
}

// Landing handles GET /i/<token|code>.
func (l *InviteLanding) Landing(raw, remote string, wantsJSON bool) InviteResponse {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 4096 {
		return invitePage(404, "Fant ikke siden", "", wantsJSON, "not_found")
	}
	isCode := interop.LooksLikeHumanCode(raw)
	now := l.Clock()
	l.mu.Lock()
	defer l.mu.Unlock()
	if isCode && l.RateLimit {
		if retry := l.shortCode.record("invite-code:"+remote, now); retry > 0 {
			return invitePage(429, "Vent litt", fmt.Sprintf("For mange forsøk fra denne maskinen. Prøv igjen om %d minutter.", max(1, retry/60)), wantsJSON, "rate_limited")
		}
	}
	var record *inviteTicketRecord
	var ticket *interop.HavenInviteTicket
	if isCode {
		record = l.byCode(strings.ToUpper(raw))
		if record != nil {
			ticket, _ = interop.DecodeTicketToken(record.ticketToken)
		}
		if ticket == nil {
			return invitePage(404, "Invitasjonen er ikke tilgjengelig", inviteUnavailable, wantsJSON, "not_available")
		}
	} else {
		decoded, err := interop.DecodeTicketToken(raw)
		if err != nil {
			failure := err.(*interop.LinkFailure)
			return invitePage(400, "Denne lenken ser ikke riktig ut", failure.Message, wantsJSON, failure.Code)
		}
		ticket = decoded
		record = l.tickets[ticket.TicketID]
	}
	revoked := map[string]bool{}
	if record != nil && record.revokedAt != nil {
		revoked[ticket.TicketID] = true
	}
	verdict := interop.VerifyInvite(ticket, now, interop.TicketOptions{RevokedTicketIDs: revoked})
	if record != nil && verdict.IsValid {
		record.openCount++
		if record.firstOpenedAt == nil {
			opened := now
			record.firstOpenedAt = &opened
		}
	}
	if !verdict.IsValid {
		if isCode {
			return invitePage(410, "Invitasjonen er ikke tilgjengelig", inviteUnavailable, wantsJSON, "not_available")
		}
		return invitePage(410, "Denne invitasjonen kan ikke brukes", verdict.Reason, wantsJSON, verdict.Code)
	}
	if wantsJSON {
		payload := interop.InviteVerdictPayload(verdict, ticket)
		token, _ := ticket.Token()
		payload["ticketToken"] = token
		payload["isPublished"] = record != nil
		payload["boundaryStatement"] = interop.InviteBoundary(ticket)
		return inviteJSON(200, payload)
	}
	return inviteLandingPage(ticket, verdict, record != nil)
}

// Reply handles POST /i/<token|code>/reply.
func (l *InviteLanding) Reply(raw string, body []byte, isJSON bool, remote string) InviteResponse {
	if raw == "" {
		return inviteCode(404, "not_found", "Fant ikke siden.")
	}
	now := l.Clock()
	if l.RateLimit {
		l.mu.Lock()
		retry := l.replies.record("invite-reply:"+remote, now)
		l.mu.Unlock()
		if retry > 0 {
			return inviteCode(429, "rate_limited", fmt.Sprintf("For mange forsøk. Prøv igjen om %d minutter.", max(1, retry/60)))
		}
	}
	var request interop.HavenInviteContactRequest
	if !isJSON || interop.Decode(body, &request) != nil {
		// The browser path needs a signed-in person; this scaffold has no web login.
		return InviteResponse{Status: 303, ContentType: "text/plain", Location: "/login?next=/i/" + raw}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	record, ok := l.tickets[request.TicketID]
	if !ok {
		return inviteCode(404, "not_found", "Ukjent billett.")
	}
	if record.revokedAt != nil || now.After(record.expiresAt) {
		return inviteCode(410, "not_active", "Invitasjonen er ikke lenger aktiv.")
	}
	ticket, err := interop.DecodeTicketToken(record.ticketToken)
	if err != nil {
		return inviteCode(400, "bad_request", "Ugyldig forespørsel.")
	}
	if err := interop.VerifyContactRequest(&request, ticket, now); err != nil {
		code, message := inviteFailureMessage(err)
		return inviteCode(403, code, message)
	}
	if l.countRequests(record.ticketID) >= record.maxContactRequests {
		return inviteCode(409, "inbox_full", "Denne invitasjonen har allerede tatt imot så mange svar som den kan.")
	}
	for _, row := range l.requests {
		if row.requestID == request.RequestID {
			return inviteCode(200, "ok", "Allerede mottatt.")
		}
	}
	payload, err := interop.EncodedJSON(&request)
	if err != nil {
		return inviteCode(400, "bad_request", "Kunne ikke lagre forespørselen.")
	}
	name := request.SenderDisplayName
	if len([]rune(name)) > 120 {
		name = string([]rune(name)[:120])
	}
	l.requests = append(l.requests, &inviteRequestRecord{requestID: request.RequestID, ticketID: record.ticketID, payloadJSON: string(payload), senderDisplayName: name})
	responded := now
	record.respondedAt = &responded
	record.resultingEntityRef = request.SenderEntityRef
	return inviteCode(200, "ok", "Svaret er levert. "+ticket.IssuerDisplayName+" henter det neste gang HAVEN er åpen.")
}

func invitePage(status int, headline, detail string, wantsJSON bool, code string) InviteResponse {
	if wantsJSON {
		message := detail
		if message == "" {
			message = headline
		}
		return inviteCode(status, code, message)
	}
	body := `<!doctype html><html lang="nb"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">` +
		"<title>" + html.EscapeString(headline) + "</title></head><body><main><h1>" + html.EscapeString(headline) + "</h1><p>" +
		html.EscapeString(detail) + "</p></main></body></html>"
	return InviteResponse{Status: status, ContentType: "text/html; charset=utf-8", Body: []byte(body)}
}

func inviteLandingPage(ticket *interop.HavenInviteTicket, verdict interop.InviteVerdict, published bool) InviteResponse {
	greeting := "Hei,"
	if ticket.GreetingName != nil && *ticket.GreetingName != "" {
		greeting = "Hei " + *ticket.GreetingName + ","
	}
	note := ""
	if ticket.Note != nil && *ticket.Note != "" {
		note = "<blockquote>" + html.EscapeString(*ticket.Note) + "</blockquote>"
	}
	reply := "<p>Åpne lenken i HAVEN-appen for å opprette din egen entitet.</p>"
	if ticket.CanReceiveContactRequest() {
		reply = "<p>Åpne lenken i HAVEN-appen for å opprette din egen entitet og svare.</p>"
	}
	suffix := ""
	if !published {
		suffix = " (ikke registrert her)"
	}
	name := html.EscapeString(ticket.IssuerDisplayName)
	body := `<!doctype html><html lang="nb"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">` +
		"<title>Invitasjon fra " + name + "</title></head><body><main><p>" + html.EscapeString(greeting) + "</p><h1>" + name +
		" inviterer deg til HAVEN</h1>" + note + "<p>" + html.EscapeString(interop.InviteBoundary(ticket)) + "</p>" + reply +
		"<p>Kode: <strong>" + html.EscapeString(ticket.HumanCode) + "</strong></p><p><small>" + html.EscapeString(verdict.Reason+suffix) +
		"</small></p></main></body></html>"
	return InviteResponse{Status: 200, ContentType: "text/html; charset=utf-8", Body: []byte(body)}
}

// ServeHTTP routes /i/... requests.
func (l *InviteLanding) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/"+interop.InvitePathSegment+"/")
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	remote, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remote = r.RemoteAddr
	}
	var response InviteResponse
	switch {
	case r.Method == http.MethodPost && path == "api/publish":
		response = l.Publish(body)
	case r.Method == http.MethodPost && path == "api/revoke":
		response = l.Revoke(body)
	case r.Method == http.MethodPost && path == "api/status":
		response = l.Status(body)
	case r.Method == http.MethodPost && path == "api/requests":
		response = l.Collect(body)
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/reply") && !strings.Contains(strings.TrimSuffix(path, "/reply"), "/"):
		contentType := strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])
		response = l.Reply(strings.TrimSuffix(path, "/reply"), body, contentType == "application/json", remote)
	case r.Method == http.MethodGet && path != "" && !strings.Contains(path, "/"):
		response = l.Landing(path, remote, strings.Contains(r.Header.Get("Accept"), "application/json"))
	default:
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if response.Location != "" {
		w.Header().Set("Location", response.Location)
	}
	w.Header().Set("Content-Type", response.ContentType)
	w.WriteHeader(response.Status)
	_, _ = w.Write(response.Body)
}
