// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

// Owner only: a host moves an earlier conversation into a chat with the same
// messages, authors, times and order (PDD_modell-i-felles-chat, WP8), as
// CellBase Swift's history.import and history.limit.

import (
	"context"
	"fmt"
	"time"

	"github.com/Digipomps/GoCellProtocol/interop"
)

const ChatHistoryLimitMaximum = 100_000

func (c *ChatCell) setHistoryLimit(ctx context.Context, keypath string, value any, requester *Identity) (any, error) {
	_, _ = ctx, keypath
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.ownerPerson == nil || !c.ownerPerson.matches(requester) {
		return "denied", nil
	}
	var limit int64
	switch v := NormalizeJSON(value).(type) {
	case int:
		limit = int64(v)
	case int64:
		limit = v
	case float64:
		if v != float64(int64(v)) {
			limit = 0
		} else {
			limit = int64(v)
		}
	}
	if limit < 1 || limit > ChatHistoryLimitMaximum {
		return chatModelRefusal("invalid_payload", fmt.Sprintf("history.limit needs an integer from 1 to %d", ChatHistoryLimitMaximum)), nil
	}
	c.opts.MessagesLimit = int(limit)
	if over := len(c.messages) - c.opts.MessagesLimit; over > 0 {
		c.messages = c.messages[over:]
	}
	return map[string]any{"status": "ok", "messagesLimit": int(limit)}, nil
}

// setHistoryImport imports in order, only into a chat holding nothing but these
// messages, so running it again changes nothing.
func (c *ChatCell) setHistoryImport(ctx context.Context, keypath string, value any, requester *Identity) (any, error) {
	_, _ = ctx, keypath
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.ownerPerson == nil || !c.ownerPerson.matches(requester) {
		return "denied", nil
	}
	payload, _ := NormalizeJSON(value).(map[string]any)
	items, ok := payload["messages"].([]any)
	if !ok {
		return chatModelRefusal("invalid_payload", "history.import needs {messages: [...]}"), nil
	}
	imported := make([]map[string]any, 0, len(items))
	seen := map[string]bool{}
	for _, item := range items {
		object, _ := item.(map[string]any)
		id, _ := object["id"].(string)
		author, _ := object["authorUUID"].(string)
		content, contentOK := object["content"].(string)
		createdAt, timeOK := normalizedHistoryTimestamp(object["createdAt"])
		if id == "" || author == "" || !contentOK || !timeOK {
			return chatModelRefusal("invalid_message", "Every message needs id, authorUUID, content and an ISO 8601 createdAt."), nil
		}
		if seen[id] {
			return chatModelRefusal("duplicate_id", fmt.Sprintf("The message id %s appears twice.", id)), nil
		}
		seen[id] = true
		name, _ := object["authorDisplayName"].(string)
		rawType, _ := object["contentType"].(string)
		if rawType == "" {
			rawType = "text/plain"
		}
		contentType := normalizedChatContentType(rawType)
		preview := content
		if runes := []rune(content); len(runes) > 140 {
			preview = string(runes[:139]) + "…"
		}
		label := "Plain text"
		if contentType == "text/markdown" {
			label = "Markdown"
		}
		imported = append(imported, map[string]any{
			"id": id, "owner": map[string]any{"uuid": author, "displayName": name}, "ownerUUID": author, "ownerDisplayName": name,
			"ownerInitials": chatInitials(name), "content": content, "contentPreview": preview, "contentType": contentType,
			"formatLabel": label, "isMarkdown": contentType == "text/markdown", "topic": c.opts.Topic, "createdAt": createdAt,
			"cryptoState": "plaintextOnly", "encryptedCompanionAvailable": false, "authorKind": "person",
		})
	}
	if len(c.messages) > 0 {
		same := len(c.messages) == len(imported)
		for i := 0; same && i < len(imported); i++ {
			same = c.messages[i]["id"] == imported[i]["id"]
		}
		if !same {
			return chatModelRefusal("history_not_empty", "The chat already has other messages."), nil
		}
		return map[string]any{"status": "ok", "imported": 0, "messageCount": len(c.messages)}, nil
	}
	if len(imported) > c.opts.MessagesLimit {
		return chatModelRefusal("over_limit", fmt.Sprintf("Raise history.limit to at least %d first.", len(imported))), nil
	}
	c.messages = imported
	return map[string]any{"status": "ok", "imported": len(imported), "messageCount": len(c.messages)}, nil
}

// normalizedHistoryTimestamp: ISO 8601 with or without fractional seconds,
// written the way the chat writes its own times.
func normalizedHistoryTimestamp(raw any) (string, bool) {
	text, ok := raw.(string)
	if !ok {
		return "", false
	}
	moment, err := time.Parse(time.RFC3339Nano, text)
	if err != nil {
		return "", false
	}
	return interop.ChatTimestamp(moment), true
}
