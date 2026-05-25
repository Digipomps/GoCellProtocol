// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
)

type IdentityVault interface {
	Initialize(context.Context) error
	AddIdentity(context.Context, *Identity, string) error
	Identity(context.Context, string, bool) (*Identity, error)
	IdentityForUUID(context.Context, string) (*Identity, error)
	SignMessageForIdentity(context.Context, *Identity, []byte) ([]byte, error)
	VerifySignature(context.Context, []byte, []byte, *Identity) (bool, error)
	RandomBytes64(context.Context) ([]byte, error)
	AcquireKeyForTag(context.Context, string) (string, string, error)
}

type Identity struct {
	UUID                        string         `json:"uuid"`
	DisplayName                 string         `json:"displayName"`
	Domain                      string         `json:"domain,omitempty"`
	PublicSecureKey             string         `json:"publicSecureKey,omitempty"`
	PublicKeyAgreementSecureKey string         `json:"publicKeyAgreementSecureKey,omitempty"`
	Properties                  map[string]any `json:"properties"`
	EntityAnchorReference       string         `json:"-"`
	vault                       IdentityVault
}

func NewIdentity(displayName, domain string) *Identity {
	if displayName == "" {
		displayName = "Identity"
	}
	return &Identity{
		UUID:                  NewUUID(),
		DisplayName:           displayName,
		Domain:                domain,
		Properties:            map[string]any{},
		EntityAnchorReference: "cell:///EntityAnchor",
	}
}

func (i *Identity) SetVault(vault IdentityVault) {
	i.vault = vault
}

func (i *Identity) Vault() IdentityVault {
	return i.vault
}

func (i *Identity) Sign(ctx context.Context, message []byte) ([]byte, error) {
	if i == nil || i.vault == nil {
		return nil, fmt.Errorf("identity has no vault")
	}
	return i.vault.SignMessageForIdentity(ctx, i, message)
}

func (i *Identity) Verify(ctx context.Context, signature, message []byte) (bool, error) {
	if i == nil || i.vault == nil {
		return false, nil
	}
	return i.vault.VerifySignature(ctx, signature, message, i)
}

func (i *Identity) MarshalJSON() ([]byte, error) {
	type alias Identity
	out := map[string]any{}
	raw, err := json.Marshal((*alias)(i))
	if err != nil {
		return nil, err
	}
	if err := DecodeJSON(raw, &out); err != nil {
		return nil, err
	}
	if i.PublicSecureKey != "" {
		out["publicKey"] = i.PublicSecureKey
	}
	return json.Marshal(out)
}

func (i *Identity) UnmarshalJSON(data []byte) error {
	var payload map[string]any
	if err := DecodeJSON(data, &payload); err != nil {
		return err
	}
	if uuid, ok := payload["uuid"].(string); ok && uuid != "" {
		i.UUID = uuid
	} else {
		i.UUID = NewUUID()
	}
	if name, ok := payload["displayName"].(string); ok && name != "" {
		i.DisplayName = name
	} else if name, ok := payload["name"].(string); ok && name != "" {
		i.DisplayName = name
	} else {
		i.DisplayName = "Identity"
	}
	if domain, ok := payload["domain"].(string); ok {
		i.Domain = domain
	}
	if key, ok := payload["publicSecureKey"].(string); ok {
		i.PublicSecureKey = key
	} else if key, ok := payload["publicKey"].(string); ok {
		i.PublicSecureKey = key
	}
	if key, ok := payload["publicKeyAgreementSecureKey"].(string); ok {
		i.PublicKeyAgreementSecureKey = key
	}
	if props, ok := ObjectValue(payload["properties"]); ok {
		i.Properties = props
	} else {
		i.Properties = map[string]any{}
	}
	i.EntityAnchorReference = "cell:///EntityAnchor"
	return nil
}

type InMemoryIdentityVault struct {
	mu         sync.RWMutex
	contexts   map[string]string
	identities map[string]*Identity
	private    map[string]ed25519.PrivateKey
	public     map[string]ed25519.PublicKey
}

func NewInMemoryIdentityVault() *InMemoryIdentityVault {
	return &InMemoryIdentityVault{
		contexts:   map[string]string{},
		identities: map[string]*Identity{},
		private:    map[string]ed25519.PrivateKey{},
		public:     map[string]ed25519.PublicKey{},
	}
}

func (v *InMemoryIdentityVault) Initialize(context.Context) error {
	return nil
}

func (v *InMemoryIdentityVault) AddIdentity(ctx context.Context, identity *Identity, name string) error {
	_ = ctx
	if identity == nil {
		return fmt.Errorf("identity is nil")
	}
	v.mu.Lock()
	defer v.mu.Unlock()

	if _, ok := v.private[identity.UUID]; !ok {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		v.private[identity.UUID] = priv
		v.public[identity.UUID] = pub
		identity.PublicSecureKey = base64.StdEncoding.EncodeToString(pub)
	}
	if identity.PublicSecureKey == "" {
		identity.PublicSecureKey = base64.StdEncoding.EncodeToString(v.public[identity.UUID])
	}
	identity.SetVault(v)
	v.identities[identity.UUID] = identity
	if name != "" {
		v.contexts[name] = identity.UUID
	}
	return nil
}

func (v *InMemoryIdentityVault) Identity(ctx context.Context, name string, makeNew bool) (*Identity, error) {
	_ = ctx
	v.mu.RLock()
	uuid := v.contexts[name]
	if uuid != "" {
		identity := v.identities[uuid]
		v.mu.RUnlock()
		return identity, nil
	}
	v.mu.RUnlock()
	if !makeNew {
		return nil, nil
	}
	identity := NewIdentity(name, "")
	if err := v.AddIdentity(ctx, identity, name); err != nil {
		return nil, err
	}
	return identity, nil
}

func (v *InMemoryIdentityVault) IdentityForUUID(ctx context.Context, uuid string) (*Identity, error) {
	_ = ctx
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.identities[uuid], nil
}

func (v *InMemoryIdentityVault) SignMessageForIdentity(ctx context.Context, identity *Identity, message []byte) ([]byte, error) {
	_ = ctx
	if identity == nil {
		return nil, fmt.Errorf("identity is nil")
	}
	v.mu.RLock()
	priv := v.private[identity.UUID]
	v.mu.RUnlock()
	if priv == nil {
		return nil, fmt.Errorf("unknown identity %s", identity.UUID)
	}
	return ed25519.Sign(priv, message), nil
}

func (v *InMemoryIdentityVault) VerifySignature(ctx context.Context, signature, message []byte, identity *Identity) (bool, error) {
	_ = ctx
	if identity == nil {
		return false, nil
	}
	v.mu.RLock()
	pub := v.public[identity.UUID]
	v.mu.RUnlock()
	if pub == nil && identity.PublicSecureKey != "" {
		decoded, err := base64.StdEncoding.DecodeString(identity.PublicSecureKey)
		if err == nil {
			pub = ed25519.PublicKey(decoded)
		}
	}
	if pub == nil {
		return false, nil
	}
	return ed25519.Verify(pub, message, signature), nil
}

func (v *InMemoryIdentityVault) RandomBytes64(ctx context.Context) ([]byte, error) {
	_ = ctx
	out := make([]byte, 64)
	_, err := rand.Read(out)
	return out, err
}

func (v *InMemoryIdentityVault) AcquireKeyForTag(ctx context.Context, tag string) (string, string, error) {
	_ = ctx
	sum := sha256.Sum256([]byte(tag))
	return base64.StdEncoding.EncodeToString(sum[:16]), base64.StdEncoding.EncodeToString(sum[16:]), nil
}
