// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package interop

// Bridge channel admission, org.haven.bridge-channel.v1, as Swift speaks it.
//
// Before any Cell command a Swift bridgehead requires four messages on the
// WebSocket (CellProtocol BridgeChannelAuthentication, BridgeChannelSession,
// BridgeChannelClientOperation; see Docs/BridgeIdentitySecurity.md):
//
//  1. client -> server channelAuthHello     {profile, identity, clientNonce}
//  2. server -> client channelAuthChallenge {transcript, signingData}
//  3. client -> server channelAuthProof     {sessionID, generation, signature}
//  4. server -> client channelAuthAccepted  {sessionID, generation, transcriptDigest}
//
// Each is a BridgeCommand {"&string": C(body), "cid": 0, "cmd": name} where C
// is JSONEncoder with .sortedKeys and .withoutEscapingSlashes. Bodies are
// decoded strictly: re-encoding must give the same bytes. The client signs an
// IdentitySigningChallenge whose resource binds SHA-256 of the transcript.
//
// Admission proves control of a public key. It grants no Cell permission.
//
// ChannelServer and ChannelClient take bytes and return bytes, so any
// transport can use them.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	ChannelProfile          = "org.haven.bridge-channel.v1"
	ChannelAction           = "openBridgeChannel"
	ChannelMaximumEnvelope  = 16 * 1024
	ChannelChallengeSeconds = 30.0
	ChannelLifetime         = 300 * time.Second
	ChannelPreAuthDeadline  = 10 * time.Second
	ChannelDirection        = "client-to-server"

	// Foundation's Date stores seconds since 2001-01-01. Swift turns
	// milliseconds into a Date and back, and the signed doubles carry that
	// rounding.
	referenceDateOffset = 978307200.0
)

var channelAuthCommands = map[string]bool{
	"channelAuthHello": true, "channelAuthChallenge": true,
	"channelAuthProof": true, "channelAuthAccepted": true,
}

// IsChannelAuthCommand reports whether cmd belongs to the admission handshake.
func IsChannelAuthCommand(cmd string) bool { return channelAuthCommands[cmd] }

// ChannelEncode is BridgeChannelAuthentication.encode.
func ChannelEncode(value any) ([]byte, error) { return UnescapedSlashJSON(value) }

// ChannelDecode is the strict decode: bounded, an object, byte-identical on re-encode.
func ChannelDecode(data []byte) (map[string]any, error) {
	if len(data) > ChannelMaximumEnvelope {
		return nil, fail("malformed", "envelope too large")
	}
	value, err := DecodeJSON(data)
	if err != nil {
		return nil, fail("malformed", "not JSON")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fail("malformed", "not an object")
	}
	again, err := ChannelEncode(object)
	if err != nil || !bytes.Equal(again, data) {
		return nil, fail("malformed", "not canonical")
	}
	return object, nil
}

func hexDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func encodeB64(data []byte) string { return base64.StdEncoding.EncodeToString(data) }

func unb64(value any) ([]byte, error) {
	text, ok := value.(string)
	if !ok {
		return nil, fail("malformed", "expected base64")
	}
	data, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil {
		return nil, fail("malformed", "bad base64")
	}
	return data, nil
}

func exactKeys(object map[string]any, keys ...string) error {
	if len(object) != len(keys) {
		return fail("malformed", "fields "+strings.Join(sortedMapKeys(object), ","))
	}
	for _, key := range keys {
		if _, ok := object[key]; !ok {
			return fail("malformed", "missing "+key)
		}
	}
	return nil
}

func sortedMapKeys(object map[string]any) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func stringField(object map[string]any, key string) (string, error) {
	text, ok := object[key].(string)
	if !ok {
		return "", fail("malformed", key)
	}
	return text, nil
}

// isUUID accepts Swift UUID(uuidString:) form: 8-4-4-4-12 hex digits.
func isUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, r := range value {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
				return false
			}
		}
	}
	return true
}

// ---- Messages ---------------------------------------------------------------

// PublicIdentity is only UUID, algorithm, curve and public key. Never a full Identity.
type PublicIdentity struct {
	UUID      string
	PublicKey []byte
	Algorithm string
	Curve     string
}

// NewEd25519PublicIdentity is the only kind the Go node signs and verifies.
func NewEd25519PublicIdentity(uuid string, publicKey []byte) PublicIdentity {
	return PublicIdentity{UUID: uuid, PublicKey: publicKey, Algorithm: "EdDSA", Curve: "Curve25519"}
}

func (p PublicIdentity) toJSON() map[string]any {
	return map[string]any{"uuid": p.UUID, "algorithm": p.Algorithm, "curve": p.Curve, "publicKey": encodeB64(p.PublicKey)}
}

func publicIdentityFromJSON(value any) (PublicIdentity, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return PublicIdentity{}, fail("malformed", "identity")
	}
	if err := exactKeys(object, "uuid", "algorithm", "curve", "publicKey"); err != nil {
		return PublicIdentity{}, err
	}
	var identity PublicIdentity
	var err error
	if identity.UUID, err = stringField(object, "uuid"); err != nil {
		return PublicIdentity{}, err
	}
	if identity.Algorithm, err = stringField(object, "algorithm"); err != nil {
		return PublicIdentity{}, err
	}
	if identity.Curve, err = stringField(object, "curve"); err != nil {
		return PublicIdentity{}, err
	}
	if identity.PublicKey, err = unb64(object["publicKey"]); err != nil {
		return PublicIdentity{}, err
	}
	return identity, identity.Validate()
}

// Validate refuses anything but a bounded UUID and a 32-byte Ed25519 key.
// Swift also accepts P-256; the Go node signs and verifies Ed25519 only.
func (p PublicIdentity) Validate() error {
	if p.UUID == "" || len(p.UUID) > 512 {
		return fail("malformed", "identity uuid")
	}
	if p.Algorithm != "EdDSA" || p.Curve != "Curve25519" || len(p.PublicKey) != 32 {
		return fail("malformed", "unsupported key")
	}
	return nil
}

// Equal compares every field.
func (p PublicIdentity) Equal(other PublicIdentity) bool {
	return p.UUID == other.UUID && bytes.Equal(p.PublicKey, other.PublicKey) &&
		p.Algorithm == other.Algorithm && p.Curve == other.Curve
}

// Descriptor is the verifier's view of the key.
func (p PublicIdentity) Descriptor() IdentityPublicKeyDescriptor {
	return IdentityPublicKeyDescriptor{UUID: p.UUID, PublicKey: p.PublicKey, Algorithm: p.Algorithm, CurveType: p.Curve}
}

// ChannelEndpoint is built from a locally configured URL, never from Host or
// Forwarded headers.
type ChannelEndpoint struct {
	Origin string
	Route  string
	Domain string
}

// Audience is origin + route: what the client signs for.
func (e ChannelEndpoint) Audience() string { return e.Origin + e.Route }

// ChannelEndpointFromURL applies Swift's URL rules: wss only (ws needs the
// loopback opt-in), no userinfo, query, fragment, dot segments, percent
// escapes or explicit default port.
func ChannelEndpointFromURL(raw, domain string, allowInsecureLoopback bool) (ChannelEndpoint, error) {
	malformed := func(detail string) (ChannelEndpoint, error) {
		return ChannelEndpoint{}, fail("malformed", detail)
	}
	if strings.ContainsAny(raw, "?#") {
		return malformed("endpoint")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return malformed("endpoint")
	}
	scheme := raw[:max(0, strings.Index(raw, ":"))]
	host := u.Hostname()
	if scheme == "" || scheme != strings.ToLower(scheme) || u.Scheme != scheme || u.Opaque != "" ||
		host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		host != strings.ToLower(host) || strings.HasSuffix(host, ".") ||
		!strings.HasPrefix(u.Path, "/") || strings.Contains(u.Path, "//") ||
		strings.Contains(u.EscapedPath(), "%") || u.RawPath != "" ||
		domain == "" || len(domain) > 512 {
		return malformed("endpoint")
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return malformed("endpoint")
		}
	}
	port := 0
	if text := u.Port(); text != "" {
		port, err = strconv.Atoi(text)
		if err != nil || port < 1 || port > 65535 {
			return malformed("port")
		}
	}
	loopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if !(scheme == "wss" || (allowInsecureLoopback && scheme == "ws" && loopback)) {
		return ChannelEndpoint{}, fail("insecureEndpoint")
	}
	if (scheme == "wss" && port == 443) || (scheme == "ws" && port == 80) {
		return malformed("explicit default port")
	}
	origin := scheme + "://" + u.Host
	if len(origin+u.Path) > 512 {
		return malformed("endpoint too long")
	}
	return ChannelEndpoint{Origin: origin, Route: u.Path, Domain: domain}, nil
}

func (e ChannelEndpoint) toJSON() map[string]any {
	return map[string]any{"origin": e.Origin, "route": e.Route, "domain": e.Domain}
}

func channelEndpointFromJSON(value any) (ChannelEndpoint, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return ChannelEndpoint{}, fail("malformed", "endpoint")
	}
	if err := exactKeys(object, "origin", "route", "domain"); err != nil {
		return ChannelEndpoint{}, err
	}
	var e ChannelEndpoint
	var err error
	if e.Origin, err = stringField(object, "origin"); err != nil {
		return e, err
	}
	if e.Route, err = stringField(object, "route"); err != nil {
		return e, err
	}
	e.Domain, err = stringField(object, "domain")
	return e, err
}

// ChannelTranscript is everything both sides agreed on, signed by digest.
type ChannelTranscript struct {
	Profile                   string
	Endpoint                  ChannelEndpoint
	Identity                  PublicIdentity
	ClientNonce               []byte
	ServerNonce               []byte
	SessionID                 string
	Generation                string
	Direction                 string
	IssuedAtMilliseconds      int64
	ChannelExpiresAtMillisecs int64
}

func (t ChannelTranscript) toJSON() map[string]any {
	return map[string]any{
		"profile":                      t.Profile,
		"endpoint":                     t.Endpoint.toJSON(),
		"identity":                     t.Identity.toJSON(),
		"clientNonce":                  encodeB64(t.ClientNonce),
		"serverNonce":                  encodeB64(t.ServerNonce),
		"sessionID":                    t.SessionID,
		"generation":                   t.Generation,
		"direction":                    t.Direction,
		"issuedAtMilliseconds":         t.IssuedAtMilliseconds,
		"channelExpiresAtMilliseconds": t.ChannelExpiresAtMillisecs,
	}
}

// Encoded is C(transcript), the bytes the digest covers.
func (t ChannelTranscript) Encoded() ([]byte, error) { return ChannelEncode(t.toJSON()) }

// Digest is hex SHA-256 of C(transcript).
func (t ChannelTranscript) Digest() string {
	data, err := t.Encoded()
	if err != nil {
		return ""
	}
	return hexDigest(data)
}

func int64Field(object map[string]any, key string) (int64, error) {
	number, ok := object[key].(json.Number)
	if !ok {
		return 0, fail("malformed", key)
	}
	value, err := strconv.ParseInt(number.String(), 10, 64)
	if err != nil {
		return 0, fail("malformed", key)
	}
	return value, nil
}

// DecodeChannelTranscript reads a strictly encoded transcript.
func DecodeChannelTranscript(data []byte) (ChannelTranscript, error) {
	object, err := ChannelDecode(data)
	if err != nil {
		return ChannelTranscript{}, err
	}
	return channelTranscriptFromJSON(object)
}

func channelTranscriptFromJSON(value any) (ChannelTranscript, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return ChannelTranscript{}, fail("malformed", "transcript")
	}
	if err := exactKeys(object, "profile", "endpoint", "identity", "clientNonce", "serverNonce",
		"sessionID", "generation", "direction", "issuedAtMilliseconds", "channelExpiresAtMilliseconds"); err != nil {
		return ChannelTranscript{}, err
	}
	var t ChannelTranscript
	var err error
	for key, target := range map[string]*string{
		"profile": &t.Profile, "sessionID": &t.SessionID, "generation": &t.Generation, "direction": &t.Direction,
	} {
		if *target, err = stringField(object, key); err != nil {
			return t, err
		}
	}
	if t.Endpoint, err = channelEndpointFromJSON(object["endpoint"]); err != nil {
		return t, err
	}
	if t.Identity, err = publicIdentityFromJSON(object["identity"]); err != nil {
		return t, err
	}
	if t.ClientNonce, err = unb64(object["clientNonce"]); err != nil {
		return t, err
	}
	if t.ServerNonce, err = unb64(object["serverNonce"]); err != nil {
		return t, err
	}
	if t.IssuedAtMilliseconds, err = int64Field(object, "issuedAtMilliseconds"); err != nil {
		return t, err
	}
	if t.ChannelExpiresAtMillisecs, err = int64Field(object, "channelExpiresAtMilliseconds"); err != nil {
		return t, err
	}
	return t, nil
}

// ChannelSigningChallenge is what Swift's BridgeChannelAuthentication.signingData builds.
func ChannelSigningChallenge(t ChannelTranscript) *IdentitySigningChallenge {
	reference := float64(t.IssuedAtMilliseconds)/1000 - referenceDateOffset
	fingerprint := t.Identity.Descriptor().Fingerprint()
	return &IdentitySigningChallenge{
		Type:                 SigningChallengeType,
		Version:              1,
		Purpose:              SigningChallengePurpose,
		IdentityUUID:         t.Identity.UUID,
		PublicKeyFingerprint: &fingerprint,
		Domain:               t.Endpoint.Domain,
		Resource:             ChannelProfile + ":" + t.Digest(),
		Action:               ChannelAction,
		Audience:             t.Endpoint.Audience(),
		Nonce:                t.ServerNonce,
		IssuedAt:             reference + referenceDateOffset,
		ExpiresAt:            (reference + ChannelChallengeSeconds) + referenceDateOffset,
	}
}

// ChannelSigningData is the exact bytes the client signs.
func ChannelSigningData(t ChannelTranscript) ([]byte, error) {
	return EncodedJSON(ChannelSigningChallenge(t))
}

// ChannelEnvelope wraps a body as the cid-0 BridgeCommand Swift sends.
func ChannelEnvelope(name string, body map[string]any) ([]byte, error) {
	inner, err := ChannelEncode(body)
	if err != nil {
		return nil, err
	}
	return ChannelEncode(map[string]any{"&string": string(inner), "cid": 0, "cmd": name})
}

// OpenChannelEnvelope validates an auth BridgeCommand and returns its name and body.
func OpenChannelEnvelope(data []byte) (string, map[string]any, error) {
	command, err := ChannelDecode(data)
	if err != nil {
		return "", nil, err
	}
	if err := exactKeys(command, "&string", "cid", "cmd"); err != nil {
		return "", nil, err
	}
	cid, ok := command["cid"].(json.Number)
	name, nameOK := command["cmd"].(string)
	if !ok || cid.String() != "0" || !nameOK || !channelAuthCommands[name] {
		return "", nil, fail("malformed", "auth envelope")
	}
	payload, ok := command["&string"].(string)
	if !ok {
		return "", nil, fail("malformed", "auth payload")
	}
	body, err := ChannelDecode([]byte(payload))
	if err != nil {
		return "", nil, err
	}
	return name, body, nil
}

func helloBody(identity PublicIdentity, clientNonce []byte) map[string]any {
	return map[string]any{"profile": ChannelProfile, "identity": identity.toJSON(), "clientNonce": encodeB64(clientNonce)}
}

func challengeBody(t ChannelTranscript) (map[string]any, error) {
	data, err := ChannelSigningData(t)
	if err != nil {
		return nil, err
	}
	return map[string]any{"transcript": t.toJSON(), "signingData": encodeB64(data)}, nil
}

func proofBody(sessionID, generation string, signature []byte) map[string]any {
	return map[string]any{"sessionID": sessionID, "generation": generation, "signature": encodeB64(signature)}
}

func acceptedBody(t ChannelTranscript) map[string]any {
	return map[string]any{"sessionID": t.SessionID, "generation": t.Generation, "transcriptDigest": t.Digest()}
}

// Envelopes for each step, exposed so tests can compare against Swift.

func ChannelHelloEnvelope(identity PublicIdentity, clientNonce []byte) ([]byte, error) {
	return ChannelEnvelope("channelAuthHello", helloBody(identity, clientNonce))
}

func ChannelChallengeEnvelope(t ChannelTranscript) ([]byte, error) {
	body, err := challengeBody(t)
	if err != nil {
		return nil, err
	}
	return ChannelEnvelope("channelAuthChallenge", body)
}

func ChannelProofEnvelope(sessionID, generation string, signature []byte) ([]byte, error) {
	return ChannelEnvelope("channelAuthProof", proofBody(sessionID, generation, signature))
}

func ChannelAcceptedEnvelope(t ChannelTranscript) ([]byte, error) {
	return ChannelEnvelope("channelAuthAccepted", acceptedBody(t))
}

// ---- Clocks -----------------------------------------------------------------

// ChannelClock lets tests fix time. Wall is the signed clock; Monotonic is the
// pre-auth deadline clock.
type ChannelClock struct {
	Wall      func() time.Time
	Monotonic func() time.Duration
	Random    func(n int) []byte
	NewUUID   func() string
}

var processStart = time.Now()

func (c ChannelClock) withDefaults() ChannelClock {
	if c.Wall == nil {
		c.Wall = time.Now
	}
	if c.Monotonic == nil {
		c.Monotonic = func() time.Duration { return time.Since(processStart) }
	}
	if c.Random == nil {
		c.Random = func(n int) []byte {
			out := make([]byte, n)
			if _, err := rand.Read(out); err != nil {
				panic(err)
			}
			return out
		}
	}
	if c.NewUUID == nil {
		c.NewUUID = func() string {
			b := c.Random(16)
			b[6] = (b[6] & 0x0f) | 0x40
			b[8] = (b[8] & 0x3f) | 0x80
			return strings.ToUpper(fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]))
		}
	}
	return c
}

func millis(t time.Time) int64 { return t.UnixMilli() }

// ---- Server side (inbound bridge) --------------------------------------------

// AdmittedChannel is what a host gets after admission: a proven public key, nothing more.
type AdmittedChannel struct {
	Identity         PublicIdentity
	Endpoint         ChannelEndpoint
	SessionID        string
	Generation       string
	TranscriptDigest string
	ExpiresAt        time.Time
}

// Check refuses once the channel has expired.
func (a *AdmittedChannel) Check(now time.Time) error {
	if !now.Before(a.ExpiresAt) {
		return fail("expired")
	}
	return nil
}

// CheckIdentity is session.check: every later command must carry the same
// public key. A response may omit it; nothing else may.
func (a *AdmittedChannel) CheckIdentity(identity *PublicIdentity, required bool, now time.Time) error {
	if err := a.Check(now); err != nil {
		return err
	}
	if identity == nil {
		if required {
			return fail("identityMismatch")
		}
		return nil
	}
	if !identity.Equal(a.Identity) {
		return fail("identityMismatch")
	}
	return nil
}

// ChannelServer is one connection's admission state: unauthenticated ->
// challengeIssued -> verifying -> authenticated, or closed. Any misstep is
// terminal.
type ChannelServer struct {
	Endpoint   ChannelEndpoint
	Generation string
	State      string
	Admitted   *AdmittedChannel
	// Recheck runs after the signature verifies, for revocation or policy.
	Recheck func(PublicIdentity) error

	clock    ChannelClock
	deadline time.Duration
	pending  *ChannelTranscript
	data     []byte
}

// NewChannelServer starts the pre-auth deadline now. The generation is drawn
// before the session ID, as in Swift.
func NewChannelServer(endpoint ChannelEndpoint, clock ChannelClock) *ChannelServer {
	clock = clock.withDefaults()
	return &ChannelServer{
		Endpoint:   endpoint,
		Generation: clock.NewUUID(),
		State:      "unauthenticated",
		clock:      clock,
		deadline:   clock.Monotonic() + ChannelPreAuthDeadline,
	}
}

func (s *ChannelServer) close(code string, detail ...string) error {
	s.State = "closed"
	s.pending = nil
	s.data = nil
	return fail(code, detail...)
}

// Receive consumes one inbound frame before admission and returns the reply.
func (s *ChannelServer) Receive(data []byte) ([]byte, error) {
	if s.State == "closed" || s.State == "authenticated" {
		return nil, s.close("unexpectedMessage")
	}
	name, body, err := OpenChannelEnvelope(data)
	if err != nil {
		s.State = "closed"
		return nil, err
	}
	if s.clock.Monotonic() >= s.deadline {
		return nil, s.close("expired")
	}
	switch {
	case name == "channelAuthHello" && s.State == "unauthenticated":
		return s.onHello(body)
	case name == "channelAuthProof" && s.State == "challengeIssued":
		return s.onProof(body)
	}
	return nil, s.close("unexpectedMessage", name)
}

func failureCode(err error) string { return VerdictOf(err) }

func (s *ChannelServer) onHello(body map[string]any) ([]byte, error) {
	if err := exactKeys(body, "profile", "identity", "clientNonce"); err != nil {
		return nil, s.close(failureCode(err), err.Error())
	}
	if profile, _ := body["profile"].(string); profile != ChannelProfile {
		return nil, s.close("malformed", "profile")
	}
	identity, err := publicIdentityFromJSON(body["identity"])
	if err != nil {
		return nil, s.close(failureCode(err), err.Error())
	}
	clientNonce, err := unb64(body["clientNonce"])
	if err != nil || len(clientNonce) != 32 {
		return nil, s.close("malformed", "client nonce")
	}
	issued := millis(s.clock.Wall())
	t := ChannelTranscript{
		Profile:                   ChannelProfile,
		Endpoint:                  s.Endpoint,
		Identity:                  identity,
		ClientNonce:               clientNonce,
		ServerNonce:               s.clock.Random(32),
		SessionID:                 s.clock.NewUUID(),
		Generation:                s.Generation,
		Direction:                 ChannelDirection,
		IssuedAtMilliseconds:      issued,
		ChannelExpiresAtMillisecs: issued + ChannelLifetime.Milliseconds(),
	}
	data, err := ChannelSigningData(t)
	if err != nil {
		return nil, s.close("malformed", err.Error())
	}
	reply, err := ChannelChallengeEnvelope(t)
	if err != nil {
		return nil, s.close("malformed", err.Error())
	}
	s.pending, s.data = &t, data
	s.State = "challengeIssued"
	return reply, nil
}

func (s *ChannelServer) onProof(body map[string]any) ([]byte, error) {
	t, data := s.pending, s.data
	s.pending, s.data = nil, nil // consume before verifying
	s.State = "verifying"
	if t == nil {
		return nil, s.close("unexpectedMessage")
	}
	if err := exactKeys(body, "sessionID", "generation", "signature"); err != nil {
		return nil, s.close(failureCode(err), err.Error())
	}
	signature, err := unb64(body["signature"])
	if err != nil {
		return nil, s.close(failureCode(err), err.Error())
	}
	issued := time.UnixMilli(t.IssuedAtMilliseconds)
	if !s.clock.Wall().Before(issued.Add(time.Duration(ChannelChallengeSeconds) * time.Second)) {
		return nil, s.close("expired")
	}
	sessionID, _ := body["sessionID"].(string)
	generation, _ := body["generation"].(string)
	if sessionID != t.SessionID || generation != s.Generation {
		return nil, s.close("staleGeneration")
	}
	if len(signature) > 256 || !VerifySignature(signature, data, t.Identity.Descriptor()) {
		return nil, s.close("invalidProof")
	}
	if s.Recheck != nil {
		if err := s.Recheck(t.Identity); err != nil {
			return nil, s.close("revoked", err.Error())
		}
	}
	expires := time.UnixMilli(t.ChannelExpiresAtMillisecs)
	if s.clock.Monotonic() >= s.deadline || !s.clock.Wall().Before(expires) {
		return nil, s.close("expired")
	}
	reply, err := ChannelAcceptedEnvelope(*t)
	if err != nil {
		return nil, s.close("malformed", err.Error())
	}
	s.Admitted = &AdmittedChannel{
		Identity: t.Identity, Endpoint: s.Endpoint, SessionID: t.SessionID,
		Generation: s.Generation, TranscriptDigest: t.Digest(), ExpiresAt: expires,
	}
	s.State = "authenticated"
	return reply, nil
}

// ---- Client side (outgoing bridge) ---------------------------------------------

// ChannelClient is one locally initiated connect. It signs exactly one
// challenge that matches the endpoint it chose itself; a peer cannot widen
// what gets signed.
type ChannelClient struct {
	Identity    PublicIdentity
	Endpoint    ChannelEndpoint
	ClientNonce []byte
	State       string
	Admitted    *AdmittedChannel

	clock      ChannelClock
	deadline   time.Duration
	transcript *ChannelTranscript
	offered    []byte
}

func NewChannelClient(identity PublicIdentity, endpoint ChannelEndpoint, clock ChannelClock) (*ChannelClient, error) {
	if err := identity.Validate(); err != nil {
		return nil, err
	}
	clock = clock.withDefaults()
	return &ChannelClient{
		Identity:    identity,
		Endpoint:    endpoint,
		ClientNonce: clock.Random(32),
		State:       "new",
		clock:       clock,
		deadline:    clock.Monotonic() + ChannelPreAuthDeadline,
	}, nil
}

func (c *ChannelClient) close(code string, detail ...string) error {
	c.State = "closed"
	c.offered = nil
	return fail(code, detail...)
}

// Hello is the first frame.
func (c *ChannelClient) Hello() ([]byte, error) {
	if c.State != "new" {
		return nil, c.close("unexpectedMessage")
	}
	c.State = "helloSent"
	return ChannelHelloEnvelope(c.Identity, c.ClientNonce)
}

// BeginChallenge validates the challenge completely and returns the exact
// bytes to sign. Only one challenge is ever accepted.
func (c *ChannelClient) BeginChallenge(data []byte) ([]byte, error) {
	name, body, err := OpenChannelEnvelope(data)
	if err != nil {
		c.State = "closed"
		return nil, err
	}
	if c.clock.Monotonic() >= c.deadline {
		return nil, c.close("expired")
	}
	if name != "channelAuthChallenge" || c.State != "helloSent" {
		return nil, c.close("unexpectedMessage", name)
	}
	c.State = "signing" // consumed before signing
	if err := exactKeys(body, "transcript", "signingData"); err != nil {
		return nil, c.close(failureCode(err), err.Error())
	}
	t, err := channelTranscriptFromJSON(body["transcript"])
	if err != nil {
		return nil, c.close(failureCode(err), err.Error())
	}
	offered, err := unb64(body["signingData"])
	if err != nil {
		return nil, c.close(failureCode(err), err.Error())
	}
	expected, err := ChannelSigningData(t)
	if err != nil {
		return nil, c.close("invalidProof", err.Error())
	}
	nowMs := millis(c.clock.Wall())
	const far = int64(9_000_000_000_000_000)
	if !(t.Profile == ChannelProfile &&
		t.Direction == ChannelDirection &&
		t.Endpoint == c.Endpoint &&
		t.Identity.Equal(c.Identity) &&
		bytes.Equal(t.ClientNonce, c.ClientNonce) &&
		len(t.ServerNonce) == 32 &&
		isUUID(t.SessionID) && isUUID(t.Generation) &&
		t.IssuedAtMilliseconds > 0 && t.IssuedAtMilliseconds < far &&
		t.ChannelExpiresAtMillisecs > 0 && t.ChannelExpiresAtMillisecs < far &&
		t.IssuedAtMilliseconds <= nowMs+5_000 &&
		t.IssuedAtMilliseconds > nowMs-30_000 &&
		t.ChannelExpiresAtMillisecs > nowMs &&
		t.ChannelExpiresAtMillisecs-t.IssuedAtMilliseconds == ChannelLifetime.Milliseconds() &&
		bytes.Equal(offered, expected)) {
		return nil, c.close("invalidProof", "challenge does not match this connect")
	}
	if _, err := ValidateSigningChallenge(offered, c.Identity.Descriptor(), time.UnixMilli(nowMs)); err != nil {
		return nil, c.close("invalidProof", failureCode(err))
	}
	c.transcript = &t
	c.offered = offered
	return offered, nil
}

// FinishChallenge checks the signature over the offered bytes and returns the proof frame.
func (c *ChannelClient) FinishChallenge(signature []byte) ([]byte, error) {
	t, offered := c.transcript, c.offered
	if c.State != "signing" || t == nil || offered == nil {
		return nil, c.close("unexpectedMessage")
	}
	c.offered = nil
	if c.clock.Monotonic() >= c.deadline || !VerifySignature(signature, offered, c.Identity.Descriptor()) {
		return nil, c.close("staleGeneration")
	}
	if _, err := ValidateSigningChallenge(offered, c.Identity.Descriptor(), c.clock.Wall()); err != nil {
		return nil, c.close("expired", failureCode(err))
	}
	c.State = "proofSent"
	return ChannelProofEnvelope(t.SessionID, t.Generation, signature)
}

// Accept consumes channelAuthAccepted and admits the channel.
func (c *ChannelClient) Accept(data []byte) error {
	name, body, err := OpenChannelEnvelope(data)
	if err != nil {
		c.State = "closed"
		return err
	}
	if c.clock.Monotonic() >= c.deadline {
		return c.close("expired")
	}
	if name != "channelAuthAccepted" || c.State != "proofSent" {
		return c.close("unexpectedMessage", name)
	}
	if err := exactKeys(body, "sessionID", "generation", "transcriptDigest"); err != nil {
		return c.close(failureCode(err))
	}
	t := c.transcript
	sessionID, _ := body["sessionID"].(string)
	generation, _ := body["generation"].(string)
	digest, _ := body["transcriptDigest"].(string)
	if t == nil || sessionID != t.SessionID || generation != t.Generation || digest != t.Digest() {
		return c.close("invalidProof", "acknowledgement")
	}
	expires := time.UnixMilli(t.ChannelExpiresAtMillisecs)
	if !c.clock.Wall().Before(expires) {
		return c.close("expired")
	}
	c.Admitted = &AdmittedChannel{
		Identity: t.Identity, Endpoint: t.Endpoint, SessionID: t.SessionID,
		Generation: t.Generation, TranscriptDigest: t.Digest(), ExpiresAt: expires,
	}
	c.State = "authenticated"
	return nil
}
