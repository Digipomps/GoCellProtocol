// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

// Package interop holds the cross-language wire contracts for entity
// extension, invitation and chat, byte-compatible with CellProtocol Swift.
//
// Swift signs JSONSerialization.data(withJSONObject:options:[.sortedKeys]) of
// the JSONEncoder output. That differs from encoding/json in three ways:
//
//   - JSONSerialization sorts keys like NSString.compare with numeric and
//     case-insensitive options, so "requestID" sorts after "requestedScopes".
//     JSONEncoder with .sortedKeys (the wire JSON, the ticket token and the
//     signed bridge challenge) uses plain code-point order instead.
//   - "/" is escaped as "\/".
//   - Non-ASCII text is written as raw UTF-8, and <, >, & are not escaped.
//
// The golden fixtures in CellProtocol fixtures/interop/v1 are the authority.
package interop

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// KeyOrder selects how object keys are sorted.
type KeyOrder int

const (
	// FoundationOrder is JSONSerialization .sortedKeys: what signatures cover.
	FoundationOrder KeyOrder = iota
	// EncoderOrder is JSONEncoder .sortedKeys: code-point order.
	EncoderOrder
)

type keyToken struct {
	digits bool
	text   string
}

func tokenize(key string) []keyToken {
	var tokens []keyToken
	for i := 0; i < len(key); {
		r, size := utf8.DecodeRuneInString(key[i:])
		if r >= '0' && r <= '9' {
			j := i
			for j < len(key) && key[j] >= '0' && key[j] <= '9' {
				j++
			}
			tokens = append(tokens, keyToken{digits: true, text: key[i:j]})
			i = j
			continue
		}
		tokens = append(tokens, keyToken{text: string(r)})
		i += size
	}
	return tokens
}

func compareDigits(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

func foldRune(s string) string {
	r, _ := utf8.DecodeRuneInString(s)
	return string(unicode.ToLower(unicode.ToUpper(r)))
}

// CompareFoundationKeys orders keys the way Foundation's JSONSerialization
// does with .sortedKeys: numeric runs compare as numbers, letters compare
// case-insensitively, and ties fall back to code-point order.
func CompareFoundationKeys(left, right string) int {
	lt, rt := tokenize(left), tokenize(right)
	for i := 0; i < len(lt) && i < len(rt); i++ {
		a, b := lt[i], rt[i]
		if a.digits && b.digits {
			if c := compareDigits(a.text, b.text); c != 0 {
				return c
			}
			continue
		}
		fa, fb := foldRune(a.text), foldRune(b.text)
		if a.digits {
			fa = a.text[:1]
		}
		if b.digits {
			fb = b.text[:1]
		}
		if c := strings.Compare(fa, fb); c != 0 {
			return c
		}
		if a.digits != b.digits {
			// Same first character, one side continues as a number.
			if a.digits {
				return 1
			}
			return -1
		}
	}
	if len(lt) != len(rt) {
		if len(lt) < len(rt) {
			return -1
		}
		return 1
	}
	return strings.Compare(left, right)
}

// SortedKeys returns the keys in the requested order.
func SortedKeys(keys []string, order KeyOrder) []string {
	out := append([]string(nil), keys...)
	if order == EncoderOrder {
		sort.Strings(out)
		return out
	}
	sort.SliceStable(out, func(i, j int) bool { return CompareFoundationKeys(out[i], out[j]) < 0 })
	return out
}

func writeString(buf *bytes.Buffer, s string, escapeSlashes bool) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '/':
			if escapeSlashes {
				buf.WriteString(`\/`)
			} else {
				buf.WriteByte('/')
			}
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

func writeFloat(buf *bytes.Buffer, f float64) error {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return fmt.Errorf("interop: Foundation refuses NaN and infinity")
	}
	if f == math.Trunc(f) && math.Abs(f) < 1<<53 {
		buf.WriteString(strconv.FormatInt(int64(f), 10))
		return nil
	}
	// Shortest round-trip digits, positional between 1e-4 and 1e16 like
	// Swift's Double description (1793102399.123, not 1.793102399123e+09).
	if abs := math.Abs(f); abs >= 1e-4 && abs < 1e16 {
		buf.WriteString(strconv.FormatFloat(f, 'f', -1, 64))
		return nil
	}
	buf.WriteString(strconv.FormatFloat(f, 'g', -1, 64))
	return nil
}

func writeValue(buf *bytes.Buffer, value any, order KeyOrder, escapeSlashes bool) error {
	switch v := value.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeString(buf, v, escapeSlashes)
	case int:
		buf.WriteString(strconv.Itoa(v))
	case int64:
		buf.WriteString(strconv.FormatInt(v, 10))
	case float64:
		return writeFloat(buf, v)
	case json.Number:
		if i, err := v.Int64(); err == nil {
			buf.WriteString(strconv.FormatInt(i, 10))
			return nil
		}
		f, err := v.Float64()
		if err != nil {
			return err
		}
		return writeFloat(buf, f)
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		buf.WriteByte('{')
		for i, key := range SortedKeys(keys, order) {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeString(buf, key, escapeSlashes)
			buf.WriteByte(':')
			if err := writeValue(buf, v[key], order, escapeSlashes); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeValue(buf, item, order, escapeSlashes); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case []string:
		items := make([]any, len(v))
		for i, item := range v {
			items[i] = item
		}
		return writeValue(buf, items, order, escapeSlashes)
	default:
		return fmt.Errorf("interop: cannot encode %T", value)
	}
	return nil
}

// CanonicalJSON encodes a JSON value exactly like Foundation with .sortedKeys.
func CanonicalJSON(value any, order KeyOrder) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeValue(&buf, value, order, true); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnescapedSlashJSON is JSONEncoder with .sortedKeys and
// .withoutEscapingSlashes: code-point key order, "/" written as is.
func UnescapedSlashJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeValue(&buf, value, EncoderOrder, false); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// CanonicalPayload is what a Swift CanonicalPayloadSignable signs: the wire
// object minus the excluded top-level keys, in Foundation order.
func CanonicalPayload(wire map[string]any, excluding ...string) ([]byte, error) {
	filtered := make(map[string]any, len(wire))
	for key, value := range wire {
		filtered[key] = value
	}
	for _, key := range excluding {
		delete(filtered, key)
	}
	return CanonicalJSON(filtered, FoundationOrder)
}

// DecodeJSON parses JSON keeping numbers exact.
func DecodeJSON(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if decoder.More() {
		return nil, fmt.Errorf("interop: trailing data after JSON value")
	}
	return value, nil
}
