// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

import (
	"context"
	"testing"
)

func TestVaultCellContractsCreateListLinkAndState(t *testing.T) {
	ctx := context.Background()
	owner, _ := NewInMemoryIdentityVault().Identity(ctx, "owner", true)
	vault := NewVaultCell(owner)

	created, err := vault.Set(ctx, "vault.note.create", map[string]any{"id": "n1", "title": "One", "content": "Links [[n2]]", "tags": []any{"a"}}, owner)
	if err != nil {
		t.Fatal(err)
	}
	if created.(map[string]any)["status"] != "ok" {
		t.Fatalf("created = %#v", created)
	}
	listed, _ := vault.Set(ctx, "vault.note.list", map[string]any{"tags": []any{"a"}}, owner)
	notes := listed.(map[string]any)["notes"].([]any)
	if notes[0].(VaultNoteRecord).ID != "n1" {
		t.Fatalf("notes = %#v", notes)
	}
	link, _ := vault.Set(ctx, "vault.link.add", map[string]any{"fromNoteID": "n1", "toNoteID": "n2"}, owner)
	if link.(map[string]any)["link"].(map[string]any)["relationship"] != "wiki" {
		t.Fatalf("link = %#v", link)
	}
	forward, _ := vault.Set(ctx, "vault.links.forward", map[string]any{"id": "n1"}, owner)
	ids := forward.(map[string]any)["ids"].([]string)
	if len(ids) != 1 || ids[0] != "n2" {
		t.Fatalf("ids = %#v", ids)
	}
	state, _ := vault.Get(ctx, "vault.state", owner)
	if state.(map[string]any)["schemaVersion"] != "haven.vault.state.v1" {
		t.Fatalf("state = %#v", state)
	}
	if state.(map[string]any)["noteCount"] != 1 || state.(map[string]any)["linkCount"] != 1 {
		t.Fatalf("counts = %#v", state)
	}
}

func TestGraphIndexExtractsWikiLinks(t *testing.T) {
	ctx := context.Background()
	graph := NewGraphIndexCell(nil)
	result, err := graph.Set(ctx, "graph.reindex", map[string]any{"notes": []any{map[string]any{"id": "n1", "content": "See [[n2]] and [[n3]]"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.(map[string]any)["edgeCount"] != 2 {
		t.Fatalf("result = %#v", result)
	}
	outgoing, _ := graph.Set(ctx, "graph.outgoing", map[string]any{"id": "n1"}, nil)
	ids := outgoing.(map[string]any)["ids"].([]string)
	if len(ids) != 2 || ids[0] != "n2" || ids[1] != "n3" {
		t.Fatalf("outgoing = %#v", outgoing)
	}
}

func TestEntityAnchorIdentityLinksAndBatchPersist(t *testing.T) {
	ctx := context.Background()
	owner, _ := NewInMemoryIdentityVault().Identity(ctx, "owner", true)
	entity := NewEntityAnchorCell(owner)

	persisted, err := entity.Set(ctx, "entity.batchPersist", map[string]any{"schema": "test.schema", "mutations": []any{map[string]any{"keypath": "person.displayName", "value": "Ada"}}}, owner)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.(map[string]any)["status"] != "persisted" {
		t.Fatalf("persisted = %#v", persisted)
	}
	name, _ := entity.Get(ctx, "person.displayName", owner)
	if name != "Ada" {
		t.Fatalf("name = %#v", name)
	}
	approval, _ := entity.Set(ctx, "identityLinks.approveEnrollment", map[string]any{"approvalID": "approval/1"}, owner)
	if approval.(map[string]any)["status"] != "approved" {
		t.Fatalf("approval = %#v", approval)
	}
	completed, _ := entity.Set(ctx, "identityLinks.completeEnrollment", map[string]any{"linkID": "link/1", "approvalJTI": "jti-1"}, owner)
	if completed.(map[string]any)["status"] != "completed" {
		t.Fatalf("completed = %#v", completed)
	}
	replay, _ := entity.Set(ctx, "identityLinks.completeEnrollment", map[string]any{"linkID": "link/2", "approvalJTI": "jti-1"}, owner)
	if replay.(map[string]any)["status"] != "error" {
		t.Fatalf("replay = %#v", replay)
	}
	revoked, _ := entity.Set(ctx, "identityLinks.revoke", map[string]any{"linkID": "link/1"}, owner)
	if revoked.(map[string]any)["status"] != "revoked" {
		t.Fatalf("revoked = %#v", revoked)
	}
	state, _ := entity.Get(ctx, "identityLinks.state", owner)
	if state.(map[string]any)["status"] != "ready" {
		t.Fatalf("state = %#v", state)
	}
}

func TestTrustedIssuersProxyFailsClosedWithoutVerifier(t *testing.T) {
	ctx := context.Background()
	cell := NewTrustedIssuersProxyCell(nil, nil)
	result, err := cell.Set(ctx, "trustedIssuers.evaluate", map[string]any{"issuerId": "did:key:test", "candidateVc": map[string]any{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	obj := result.(map[string]any)
	if obj["status"] != "unavailable" || obj["trusted"] != false {
		t.Fatalf("result = %#v", result)
	}
}

func TestResolverRejectsMissingCapabilityAndAllowsSignedGrant(t *testing.T) {
	ctx := context.Background()
	vault := NewInMemoryIdentityVault()
	owner, _ := vault.Identity(ctx, "owner", true)
	guest, _ := vault.Identity(ctx, "guest", true)
	cell := NewGeneralCell(owner, "Secure")

	if _, err := cell.Set(ctx, "state.value", "denied", guest); err == nil {
		t.Fatalf("expected missing contract rejection")
	}
	agreement := NewAgreement(owner)
	agreement.Grants = []Grant{NewGrant("", "state", "rw--")}
	if state, err := cell.AddAgreement(ctx, agreement, guest); err != nil || state != AgreementSigned {
		t.Fatalf("add agreement state=%s err=%v", state, err)
	}
	if _, err := cell.Set(ctx, "state.value", "allowed", guest); err != nil {
		t.Fatalf("set with grant failed: %v", err)
	}
	got, err := cell.Get(ctx, "state.value", guest)
	if err != nil {
		t.Fatal(err)
	}
	if got != "allowed" {
		t.Fatalf("got = %#v", got)
	}
}

func TestReplayDeterminism(t *testing.T) {
	ctx := context.Background()
	cell := NewGeneralCell(nil, "Replay")
	_, _ = cell.Set(ctx, "state.a", "one", nil)
	_, _ = cell.Set(ctx, "state.b", "two", nil)
	history := cell.FlowHistory()
	replayed, err := ReplayFlow(history)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := FlowDigest(history)
	second, _ := FlowDigest(replayed)
	if first != second {
		t.Fatalf("digest mismatch:\n%s\n%s", first, second)
	}
	if history[0].Sequence != 1 || history[1].Sequence != 2 {
		t.Fatalf("sequence = %#v", history)
	}
}
