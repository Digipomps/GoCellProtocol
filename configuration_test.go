// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

import "testing"

func TestCellConfigurationParsesCurrentSkeletonWrappersAndRefs(t *testing.T) {
	raw := map[string]any{
		"name": "Go parity",
		"discovery": map[string]any{
			"sourceCellEndpoint": "cell:///Vault",
			"purposeRefs":        []any{"beta", "alpha", "alpha", ""},
		},
		"cellReferences": []any{
			map[string]any{
				"endpoint":         "cell:///Vault",
				"label":            "vault",
				"subscribeFeed":    false,
				"setKeysAndValues": []any{map[string]any{"key": "vault.note.list", "target": "notes"}},
			},
		},
		"skeleton": map[string]any{
			"Tabs": map[string]any{
				"activeTabStateKeypath": "ui.activeTab",
				"panels": []any{
					map[string]any{
						"id":      "notes",
						"content": []any{map[string]any{"Text": map[string]any{"text": "Notes", "keypath": "notes"}}},
					},
				},
			},
		},
	}
	data, _ := StableJSON(raw)
	var config CellConfiguration
	if err := DecodeJSON(data, &config); err != nil {
		t.Fatal(err)
	}
	if got := config.Discovery.PurposeRefs; len(got) != 2 || got[0] != "alpha" || got[1] != "beta" {
		t.Fatalf("purpose refs = %#v", got)
	}
	if config.CellReferences[0].SubscribeFeed {
		t.Fatalf("subscribeFeed should be false")
	}
	if config.Skeleton.Kind != "Tabs" {
		t.Fatalf("skeleton kind = %q", config.Skeleton.Kind)
	}
	keypaths := config.SkeletonKeypaths()
	if len(keypaths) != 2 || keypaths[0] != "notes" || keypaths[1] != "ui.activeTab" {
		t.Fatalf("keypaths = %#v", keypaths)
	}
}

func TestSkeletonRejectsUnknownElements(t *testing.T) {
	var element SkeletonElement
	if err := DecodeJSON([]byte(`{"Markdown":{"text":"nope"}}`), &element); err == nil {
		t.Fatalf("expected unsupported element error")
	}
}
