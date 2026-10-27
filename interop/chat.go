// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package interop

// Chat invitation builders, as ChatInvitationProofUtility in CellBase Swift:
// BuildChatInvitation is generateInvitationArtifact (signed by the inviter),
// BuildChatAcceptance is generateAcceptance (signed by the invitee).

import (
	"strings"
	"time"
)

const (
	ChatDefaultSuiteID      = "haven.chat.message.v1"
	ChatInvitationLifetime  = 7 * 24 * time.Hour
	ChatInvitationNonceSize = 64
)

// ChatTimestamp is ISO 8601 with milliseconds and Z, as Swift's .withFractionalSeconds.
func ChatTimestamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

func signChat(model Model, sign SignFunc, descriptor IdentityPublicKeyDescriptor) (*SignatureProof, error) {
	proof := &SignatureProof{Type: "signature", ByIdentityUUID: descriptor.UUID, Algorithm: descriptor.Algorithm, CurveType: descriptor.CurveType}
	switch m := model.(type) {
	case *ChatInvitationArtifact:
		m.Proof = proof
	case *ChatInvitationAcceptance:
		m.Proof = proof
	}
	payload, err := SignedBytes(model)
	if err != nil {
		return nil, err
	}
	signature, err := sign(payload)
	if err != nil {
		return nil, err
	}
	proof.Signature = signature
	return proof, nil
}

// ChatInvitationInput is what generateInvitationArtifact takes.
type ChatInvitationInput struct {
	ChatCellUUID    string
	Topic           string
	AudienceMode    string
	PersistenceMode string
	SuiteID         string
	InvitationID    string
	Now             time.Time
	Nonce           []byte
}

func BuildChatInvitation(inviter, invited IdentityPublicKeyDescriptor, sign SignFunc, in ChatInvitationInput) (*ChatInvitationArtifact, error) {
	if in.SuiteID == "" {
		in.SuiteID = ChatDefaultSuiteID
	}
	if in.InvitationID == "" {
		in.InvitationID = strings.ToUpper(randomUUID())
	}
	if in.Nonce == nil {
		in.Nonce = MakeNonce(ChatInvitationNonceSize)
	}
	artifact := &ChatInvitationArtifact{
		Version: 1, InvitationID: in.InvitationID, Purpose: "chat_invitation", ChatCellUUID: in.ChatCellUUID,
		Topic: in.Topic, AudienceMode: in.AudienceMode, SuiteID: in.SuiteID, PersistenceMode: in.PersistenceMode,
		InviterIdentity: inviter, InvitedIdentity: invited,
		CreatedAt: ChatTimestamp(in.Now), ExpiresAt: ChatTimestamp(in.Now.Add(ChatInvitationLifetime)), Nonce: in.Nonce,
	}
	if _, err := signChat(artifact, sign, inviter); err != nil {
		return nil, err
	}
	return artifact, nil
}

// BuildChatAcceptance refuses, with the Swift code, an artifact that is not
// for invitee or does not verify.
func BuildChatAcceptance(artifact *ChatInvitationArtifact, invitee IdentityPublicKeyDescriptor, sign SignFunc, acceptanceID string, now time.Time, nonce []byte) (*ChatInvitationAcceptance, error) {
	if !invitee.SameKey(artifact.InvitedIdentity) {
		return nil, fail("inviteeMismatch")
	}
	if err := VerifyChatInvitation(artifact, now, ChatOptions{}); err != nil {
		return nil, err
	}
	hash, err := InvitationHash(artifact)
	if err != nil {
		return nil, err
	}
	if acceptanceID == "" {
		acceptanceID = strings.ToUpper(randomUUID())
	}
	if nonce == nil {
		nonce = MakeNonce(ChatInvitationNonceSize)
	}
	acceptance := &ChatInvitationAcceptance{
		Version: 1, AcceptanceID: acceptanceID, Purpose: "accept_chat_invitation", InvitationID: artifact.InvitationID,
		InvitationHash: hash, ChatCellUUID: artifact.ChatCellUUID, InviterIdentityUUID: artifact.InviterIdentity.UUID,
		InviteeIdentity: invitee, CreatedAt: ChatTimestamp(now), Nonce: nonce,
	}
	if _, err := signChat(acceptance, sign, invitee); err != nil {
		return nil, err
	}
	return acceptance, nil
}
