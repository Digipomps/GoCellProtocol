// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

import (
	"context"
	"encoding/json"
	"testing"
)

func TestBridgeCommandEncodesSwiftKeyValuePayload(t *testing.T) {
	command := BridgeCommand{
		Cmd:     "set",
		CID:     42,
		Payload: TypedValue{Kind: "keyValue", Value: KeyValue{Key: "vault.note.create", Value: map[string]any{"title": "T", "content": "C"}}},
	}

	data, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	var encoded map[string]any
	if err := DecodeJSON(data, &encoded); err != nil {
		t.Fatal(err)
	}
	payload, ok := encoded["&keyValue"].(map[string]any)
	if !ok {
		t.Fatalf("expected &keyValue payload, got %#v", encoded)
	}
	if payload["key"] != "vault.note.create" {
		t.Fatalf("unexpected key: %#v", payload["key"])
	}
	obj, ok := payload["object"].(map[string]any)
	if !ok || obj["title"] != "T" || obj["content"] != "C" {
		t.Fatalf("unexpected object: %#v", payload["object"])
	}

	var decoded BridgeCommand
	if err := DecodeJSON(data, &decoded); err != nil {
		t.Fatal(err)
	}
	typed := decoded.Payload.(TypedValue)
	if typed.Kind != "keyValue" {
		t.Fatalf("kind = %q", typed.Kind)
	}
	kv := typed.Value.(KeyValue)
	if kv.Key != "vault.note.create" {
		t.Fatalf("decoded key = %q", kv.Key)
	}
}

func TestGrantHandlesSwiftPermissionObject(t *testing.T) {
	var grant Grant
	if err := DecodeJSON([]byte(`{"name":"Feed grant","keypath":"feed","permission":{"group":4,"other":0}}`), &grant); err != nil {
		t.Fatal(err)
	}
	if grant.Permission != "r---" {
		t.Fatalf("permission = %q", grant.Permission)
	}

	data, err := json.Marshal(NewGrant("", "feed", "rw--"))
	if err != nil {
		t.Fatal(err)
	}
	var encoded map[string]any
	if err := DecodeJSON(data, &encoded); err != nil {
		t.Fatal(err)
	}
	permission, ok := encoded["permission"].(map[string]any)
	if !ok {
		t.Fatalf("expected Swift Permission object, got %#v", encoded["permission"])
	}
	if permission["group"] != json.Number("6") || permission["other"] != json.Number("0") {
		t.Fatalf("unexpected permission bits: %#v", permission)
	}
}

func TestGrantHandlesSwiftStoragePermissionAndLegacyText(t *testing.T) {
	var storage Grant
	if err := DecodeJSON([]byte(`{"name":"Store","keypath":"shared","permission":{"uuid":"permission-1","group":12,"other":8}}`), &storage); err != nil {
		t.Fatal(err)
	}
	if storage.Permission != "r--s---s" {
		t.Fatalf("storage permission = %q", storage.Permission)
	}
	data, err := json.Marshal(storage)
	if err != nil {
		t.Fatal(err)
	}
	var encoded map[string]any
	if err := DecodeJSON(data, &encoded); err != nil {
		t.Fatal(err)
	}
	permission := encoded["permission"].(map[string]any)
	if permission["group"] != json.Number("12") || permission["other"] != json.Number("8") {
		t.Fatalf("storage permission bits = %#v", permission)
	}

	for _, legacy := range []string{"r--", "rw-r--"} {
		var grant Grant
		payload := []byte(`{"name":"Legacy","keypath":"shared","permission":"` + legacy + `"}`)
		if err := DecodeJSON(payload, &grant); err != nil {
			t.Fatalf("decode legacy %q: %v", legacy, err)
		}
		if grant.Permission != legacy {
			t.Fatalf("legacy permission %q became %q", legacy, grant.Permission)
		}
	}
}

func TestGrantRejectsUnknownSwiftPermissionBits(t *testing.T) {
	var grant Grant
	if err := DecodeJSON([]byte(`{"name":"Unknown","keypath":"shared","permission":{"group":16,"other":0}}`), &grant); err == nil {
		t.Fatalf("expected unknown permission bits to fail closed")
	}
}

func TestBridgeEndpointHandlesGetSetDescription(t *testing.T) {
	ctx := context.Background()
	owner, _ := NewInMemoryIdentityVault().Identity(ctx, "bridge-owner", true)
	cell := NewGeneralCell(owner, "Echo")
	endpoint := NewBridgeEndpoint(cell, owner)

	setResponse := endpoint.Handle(ctx, BridgeCommand{Cmd: "set", Identity: owner, Payload: TypedValue{Kind: "keyValue", Value: KeyValue{Key: "state.value", Value: "ok"}}, CID: 1})
	typed := setResponse[0].Payload.(TypedValue)
	response := typed.Value.(SetValueResponse)
	if response.State != "ok" {
		t.Fatalf("set response = %#v", response)
	}

	getResponse := endpoint.Handle(ctx, BridgeCommand{Cmd: "get", Identity: owner, Payload: TypedValue{Kind: "string", Value: "state.value"}, CID: 2})
	if got := getResponse[0].Payload.(TypedValue).Value; got != "ok" {
		t.Fatalf("get = %#v", got)
	}

	description := endpoint.Handle(ctx, BridgeCommand{Cmd: "description", CID: 3})
	if description[0].Payload.(TypedValue).Kind != "description" {
		t.Fatalf("expected description payload")
	}
	anyCell := description[0].Payload.(TypedValue).Value.(AnyCell)
	if anyCell.Name != "Echo" {
		t.Fatalf("name = %q", anyCell.Name)
	}
}
