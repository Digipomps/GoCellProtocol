// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

import (
	"context"
	"encoding/json"
	"testing"
)

func TestIdentityEncodesSwiftSecureKey(t *testing.T) {
	identity, err := NewInMemoryIdentityVault().Identity(context.Background(), "swift-json", true)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	var encoded map[string]any
	if err := DecodeJSON(data, &encoded); err != nil {
		t.Fatal(err)
	}
	publicKey, ok := encoded["publicSecureKey"].(map[string]any)
	if !ok {
		t.Fatalf("expected Swift SecureKey object, got %#v", encoded["publicSecureKey"])
	}
	if publicKey["compressedKey"] != identity.PublicSecureKey {
		t.Fatalf("compressedKey mismatch")
	}
	if publicKey["use"] != "signature" || publicKey["algorithm"] != "EdDSA" || publicKey["curveType"] != "Curve25519" {
		t.Fatalf("unexpected SecureKey: %#v", publicKey)
	}

	var decoded Identity
	if err := DecodeJSON(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.PublicSecureKey != identity.PublicSecureKey {
		t.Fatalf("decoded public key mismatch")
	}
}
