// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

import (
	"fmt"
	"strconv"
	"strings"
)

type KeyPathError struct {
	Path string
	Msg  string
}

func (e KeyPathError) Error() string {
	return fmt.Sprintf("keypath %q: %s", e.Path, e.Msg)
}

type pathToken struct {
	key      string
	selector string
	matchKey string
	matchVal string
	index    int
}

func GetKeyPath(root any, path string) (any, error) {
	tokens, err := parseKeyPath(path)
	if err != nil {
		return nil, err
	}
	var current any = root
	for _, token := range tokens {
		obj, ok := current.(map[string]any)
		if !ok {
			return nil, KeyPathError{Path: path, Msg: "expected object"}
		}
		current, ok = obj[token.key]
		if !ok {
			return nil, KeyPathError{Path: path, Msg: "missing key " + token.key}
		}
		if token.selector == "" {
			continue
		}
		list, ok := current.([]any)
		if !ok {
			return nil, KeyPathError{Path: path, Msg: "expected list at " + token.key}
		}
		switch token.selector {
		case "index":
			if token.index < 0 || token.index >= len(list) {
				return nil, KeyPathError{Path: path, Msg: "index out of range"}
			}
			current = list[token.index]
		case "match":
			found := false
			for _, item := range list {
				if obj, ok := item.(map[string]any); ok {
					if fmt.Sprint(obj[token.matchKey]) == token.matchVal {
						current = item
						found = true
						break
					}
				}
			}
			if !found {
				return nil, KeyPathError{Path: path, Msg: "no matching list item"}
			}
		default:
			return nil, KeyPathError{Path: path, Msg: "cannot read append selector"}
		}
	}
	return current, nil
}

func SetKeyPath(root map[string]any, path string, value any) error {
	tokens, err := parseKeyPath(path)
	if err != nil {
		return err
	}
	if len(tokens) == 0 {
		return KeyPathError{Path: path, Msg: "empty path"}
	}
	current := root
	for i, token := range tokens {
		last := i == len(tokens)-1
		if token.selector == "" {
			if last {
				current[token.key] = NormalizeJSON(value)
				return nil
			}
			next, ok := current[token.key].(map[string]any)
			if !ok {
				next = map[string]any{}
				current[token.key] = next
			}
			current = next
			continue
		}

		list, _ := current[token.key].([]any)
		idx := -1
		switch token.selector {
		case "append":
			idx = len(list)
			list = append(list, map[string]any{})
		case "index":
			idx = token.index
			for len(list) <= idx {
				list = append(list, map[string]any{})
			}
		case "match":
			for j, item := range list {
				if obj, ok := item.(map[string]any); ok && fmt.Sprint(obj[token.matchKey]) == token.matchVal {
					idx = j
					break
				}
			}
			if idx == -1 {
				idx = len(list)
				list = append(list, map[string]any{token.matchKey: token.matchVal})
			}
		}
		if idx < 0 {
			return KeyPathError{Path: path, Msg: "invalid selector"}
		}
		if last {
			list[idx] = NormalizeJSON(value)
			current[token.key] = list
			return nil
		}
		child, ok := list[idx].(map[string]any)
		if !ok {
			child = map[string]any{}
			list[idx] = child
		}
		current[token.key] = list
		current = child
	}
	return nil
}

func parseKeyPath(path string) ([]pathToken, error) {
	if path == "" {
		return nil, KeyPathError{Path: path, Msg: "empty path"}
	}
	parts := splitKeyPath(path)
	tokens := make([]pathToken, 0, len(parts))
	for _, part := range parts {
		token := pathToken{key: part}
		if open := strings.Index(part, "["); open >= 0 && strings.HasSuffix(part, "]") {
			token.key = part[:open]
			raw := part[open+1 : len(part)-1]
			switch {
			case raw == "+":
				token.selector = "append"
			case strings.Contains(raw, "="):
				segments := strings.SplitN(raw, "=", 2)
				token.selector = "match"
				token.matchKey = segments[0]
				token.matchVal = segments[1]
			default:
				idx, err := strconv.Atoi(raw)
				if err != nil {
					return nil, KeyPathError{Path: path, Msg: "invalid index selector"}
				}
				token.selector = "index"
				token.index = idx
			}
		}
		if token.key == "" {
			return nil, KeyPathError{Path: path, Msg: "empty key"}
		}
		tokens = append(tokens, token)
	}
	return tokens, nil
}

func splitKeyPath(path string) []string {
	var out []string
	var b strings.Builder
	depth := 0
	for _, r := range path {
		switch r {
		case '.':
			if depth == 0 {
				out = append(out, b.String())
				b.Reset()
				continue
			}
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		}
		b.WriteRune(r)
	}
	out = append(out, b.String())
	return out
}
