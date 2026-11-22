// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

import (
	"context"
	"fmt"
	"testing"
)

func legacyHistory(count int) map[string]any {
	messages := []any{}
	for i := 0; i < count; i++ {
		author, name := "uuid-sara", "Sara"
		if i%2 == 1 {
			author, name = "uuid-ola", "Ola"
		}
		messages = append(messages, map[string]any{
			"id": fmt.Sprintf("msg-%d", i), "authorUUID": author, "authorDisplayName": name,
			"content": fmt.Sprintf("melding %d", i), "createdAt": fmt.Sprintf("2026-11-01T10:%02d:00Z", i%60),
		})
	}
	return map[string]any{"messages": messages}
}

func asMessages(t *testing.T, value any) []map[string]any {
	t.Helper()
	out := []map[string]any{}
	switch list := value.(type) {
	case []map[string]any:
		return list
	case []any:
		for _, item := range list {
			out = append(out, obj(t, item))
		}
		return out
	}
	t.Fatalf("messages %T", value)
	return nil
}

// test.modellchat.migrering, as CellBase ChatHistoryImportTests.
func TestChatHistoryImportKeepsMessagesAuthorsTimesAndOrder(t *testing.T) {
	m := newModelChat(t, false)
	if got := obj(t, chatSet(t, m.chat, "history.limit", 1000, m.alice)); got["messagesLimit"] != 1000 {
		t.Fatalf("limit %#v", got)
	}
	if got := obj(t, chatSet(t, m.chat, "history.import", legacyHistory(250), m.alice)); got["imported"] != 250 {
		t.Fatalf("import %#v", got)
	}
	messages := asMessages(t, chatGet(t, m.chat, "messages", m.alice))
	if len(messages) != 250 {
		t.Fatalf("count %d", len(messages))
	}
	first := messages[0]
	if first["id"] != "msg-0" || first["ownerUUID"] != "uuid-sara" || first["ownerDisplayName"] != "Sara" ||
		first["createdAt"] != "2026-11-01T10:00:00.000Z" || first["authorKind"] != "person" {
		t.Fatalf("first %#v", first)
	}
	if messages[249]["id"] != "msg-249" {
		t.Fatalf("last %#v", messages[249]["id"])
	}
	again := obj(t, chatSet(t, m.chat, "history.import", legacyHistory(250), m.alice))
	if again["imported"] != 0 || again["messageCount"] != 250 {
		t.Fatalf("again %#v", again)
	}
	chatSet(t, m.chat, "sendMessage", "ny melding", m.alice)
	if code := obj(t, chatSet(t, m.chat, "history.import", legacyHistory(250), m.alice))["code"]; code != "history_not_empty" {
		t.Fatalf("code %v", code)
	}
}

func TestChatHistoryOnlyTheOwnerAndBadInputIsRefused(t *testing.T) {
	m := newModelChat(t, false)
	ctx := context.Background()
	for key, value := range map[string]any{"history.import": legacyHistory(2), "history.limit": 5} {
		if got, err := m.chat.Set(ctx, key, value, m.bob); err == nil && got != "denied" {
			t.Fatalf("%s by member: %v", key, got)
		}
	}
	cases := []struct {
		key   string
		value any
		code  string
	}{
		{"history.import", legacyHistory(201), "over_limit"},
		{"history.limit", 0, "invalid_payload"},
		{"history.import", map[string]any{"messages": []any{map[string]any{"id": "x", "authorUUID": "u", "content": "c", "createdAt": "i går"}}}, "invalid_message"},
		{"history.import", map[string]any{"messages": []any{
			map[string]any{"id": "x", "authorUUID": "u", "content": "a", "createdAt": "2026-11-01T10:00:00Z"},
			map[string]any{"id": "x", "authorUUID": "u", "content": "b", "createdAt": "2026-11-01T10:01:00Z"},
		}}, "duplicate_id"},
	}
	for _, c := range cases {
		if code := obj(t, chatSet(t, m.chat, c.key, c.value, m.alice))["code"]; code != c.code {
			t.Fatalf("%s: code %v, want %s", c.key, code, c.code)
		}
	}
}
