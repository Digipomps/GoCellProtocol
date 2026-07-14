// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	identitySigningChallengeType             = "org.haven.cellprotocol.identity-signing-challenge"
	identitySigningChallengeVersion          = 1
	identitySigningChallengePurpose          = "identity-origin-proof"
	identitySigningChallengeValiditySeconds  = 60.0
	identitySigningChallengeClockSkewSeconds = 300.0
	identitySigningChallengeMaximumBytes     = 8 * 1024
	identitySigningChallengeMinimumNonce     = 32
	identitySigningChallengeMaximumNonce     = 128
	identitySigningChallengeMaximumScope     = 512
	identitySigningChallengeMaximumReplays   = 4096
)

// identitySigningChallenge mirrors the canonical Swift wire model. It is kept
// private until the complete signing API is intentionally exposed by the Go
// port; bridge validation must nevertheless enforce the reference contract.
type identitySigningChallenge struct {
	Type                 string  `json:"type"`
	Version              int     `json:"version"`
	Purpose              string  `json:"purpose"`
	IdentityUUID         string  `json:"identityUUID"`
	PublicKeyFingerprint string  `json:"publicKeyFingerprint"`
	Domain               string  `json:"domain"`
	Resource             string  `json:"resource"`
	Action               string  `json:"action"`
	Audience             string  `json:"audience"`
	Nonce                []byte  `json:"nonce"`
	IssuedAt             float64 `json:"issuedAt"`
	ExpiresAt            float64 `json:"expiresAt"`
}

func validateIdentitySigningChallenge(data []byte, identity *Identity, now time.Time) (identitySigningChallenge, error) {
	var challenge identitySigningChallenge
	if identity == nil {
		return challenge, fmt.Errorf("identity signing challenge requires an identity")
	}
	if len(data) > identitySigningChallengeMaximumBytes {
		return challenge, fmt.Errorf("identity signing challenge exceeds %d bytes", identitySigningChallengeMaximumBytes)
	}
	if err := json.Unmarshal(data, &challenge); err != nil {
		return challenge, fmt.Errorf("invalid identity signing challenge: %w", err)
	}
	if challenge.Type != identitySigningChallengeType {
		return challenge, fmt.Errorf("identity signing challenge has wrong type")
	}
	if challenge.Version != identitySigningChallengeVersion {
		return challenge, fmt.Errorf("identity signing challenge has unsupported version")
	}
	if challenge.Purpose != identitySigningChallengePurpose {
		return challenge, fmt.Errorf("identity signing challenge has wrong purpose")
	}
	if challenge.IdentityUUID != identity.UUID {
		return challenge, fmt.Errorf("identity signing challenge identity mismatch")
	}
	expectedFingerprint, err := signingPublicKeyFingerprint(identity)
	if err != nil {
		return challenge, err
	}
	if strings.TrimSpace(challenge.PublicKeyFingerprint) == "" {
		return challenge, fmt.Errorf("identity signing challenge is missing public key fingerprint")
	}
	if challenge.PublicKeyFingerprint != expectedFingerprint {
		return challenge, fmt.Errorf("identity signing challenge public key mismatch")
	}
	if len(challenge.Nonce) < identitySigningChallengeMinimumNonce {
		return challenge, fmt.Errorf("identity signing challenge nonce is too short")
	}
	if len(challenge.Nonce) > identitySigningChallengeMaximumNonce {
		return challenge, fmt.Errorf("identity signing challenge nonce is too large")
	}
	for _, scoped := range []string{challenge.Domain, challenge.Resource, challenge.Action, challenge.Audience} {
		if strings.TrimSpace(scoped) == "" {
			return challenge, fmt.Errorf("identity signing challenge is missing scope")
		}
		if utf8.RuneCountInString(scoped) > identitySigningChallengeMaximumScope {
			return challenge, fmt.Errorf("identity signing challenge scope is too large")
		}
	}
	if challenge.ExpiresAt < challenge.IssuedAt || challenge.ExpiresAt-challenge.IssuedAt > identitySigningChallengeValiditySeconds {
		return challenge, fmt.Errorf("identity signing challenge has invalid validity")
	}
	nowSeconds := float64(now.UnixNano()) / float64(time.Second)
	if challenge.IssuedAt > nowSeconds+identitySigningChallengeClockSkewSeconds {
		return challenge, fmt.Errorf("identity signing challenge was issued in the future")
	}
	if challenge.ExpiresAt < nowSeconds {
		return challenge, fmt.Errorf("identity signing challenge has expired")
	}
	return challenge, nil
}

func signingPublicKeyFingerprint(identity *Identity) (string, error) {
	if identity == nil || strings.TrimSpace(identity.PublicSecureKey) == "" {
		return "", fmt.Errorf("identity has no signing public key")
	}
	publicKey, err := base64.StdEncoding.DecodeString(identity.PublicSecureKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("identity has an invalid signing public key")
	}
	return "EdDSA:Curve25519:" + base64.StdEncoding.EncodeToString(publicKey), nil
}

func identitiesReferenceSameSigningKey(expected, presented *Identity) bool {
	if expected == nil || presented == nil || expected.UUID == "" || expected.UUID != presented.UUID {
		return false
	}
	expectedFingerprint, expectedErr := signingPublicKeyFingerprint(expected)
	presentedFingerprint, presentedErr := signingPublicKeyFingerprint(presented)
	return expectedErr == nil && presentedErr == nil && expectedFingerprint == presentedFingerprint
}

type signingChallengeReplayStore struct {
	mu       sync.Mutex
	consumed map[string]float64
}

func newSigningChallengeReplayStore() *signingChallengeReplayStore {
	return &signingChallengeReplayStore{consumed: map[string]float64{}}
}

func (s *signingChallengeReplayStore) consume(challenge identitySigningChallenge, now time.Time) error {
	if s == nil {
		return fmt.Errorf("identity signing challenge replay store is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	nowSeconds := float64(now.UnixNano()) / float64(time.Second)
	for key, expiresAt := range s.consumed {
		if expiresAt < nowSeconds {
			delete(s.consumed, key)
		}
	}
	key := challenge.replayKey()
	if _, exists := s.consumed[key]; exists {
		return fmt.Errorf("identity signing challenge replay denied")
	}
	if len(s.consumed) >= identitySigningChallengeMaximumReplays {
		return fmt.Errorf("identity signing challenge replay store is full")
	}
	s.consumed[key] = challenge.ExpiresAt
	return nil
}

func (c identitySigningChallenge) replayKey() string {
	return strings.Join([]string{
		c.IdentityUUID,
		c.PublicKeyFingerprint,
		c.Domain,
		c.Resource,
		c.Action,
		c.Audience,
		base64.StdEncoding.EncodeToString(c.Nonce),
	}, "\x1f")
}
