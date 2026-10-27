// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package interop

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// Field tags: `wire:"key"` or `wire:"key,opt"`. An optional field is left
// out when it is a nil pointer or a nil slice, like Swift's synthesized
// Codable does for Optional. Supported field types: string, *string, int64,
// float64, bool, []byte, []string, struct pointers, slices of structs, and
// `any` for JSON passed through as decoded (DecodeJSON values).

// Model is a wire model that knows which top-level keys its signature skips.
type Model interface {
	ExcludedFromSignature() []string
}

type wireHooks interface {
	afterEncode(wire map[string]any)
	beforeDecode(wire map[string]any)
}

var bytesType = reflect.TypeOf([]byte(nil))

type fieldTag struct {
	key      string
	optional bool
}

func parseTag(tag string) (fieldTag, bool) {
	if tag == "" || tag == "-" {
		return fieldTag{}, false
	}
	parts := strings.Split(tag, ",")
	out := fieldTag{key: parts[0]}
	for _, part := range parts[1:] {
		if part == "opt" {
			out.optional = true
		}
	}
	return out, true
}

// ToWire returns the JSON object Swift's JSONEncoder would produce.
func ToWire(model any) (map[string]any, error) {
	value := reflect.ValueOf(model)
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil, fmt.Errorf("interop: nil model")
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return nil, fmt.Errorf("interop: %T is not a struct", model)
	}
	wire := map[string]any{}
	typ := value.Type()
	for i := 0; i < typ.NumField(); i++ {
		tag, ok := parseTag(typ.Field(i).Tag.Get("wire"))
		if !ok {
			continue
		}
		field := value.Field(i)
		if (field.Kind() == reflect.Pointer || field.Kind() == reflect.Slice || field.Kind() == reflect.Interface) && field.IsNil() {
			if tag.optional {
				continue
			}
			if field.Kind() == reflect.Pointer {
				return nil, fmt.Errorf("interop: %s.%s is required", typ.Name(), tag.key)
			}
		}
		encoded, err := encodeField(field)
		if err != nil {
			return nil, fmt.Errorf("interop: %s.%s: %w", typ.Name(), tag.key, err)
		}
		wire[tag.key] = encoded
	}
	if hooks, ok := value.Addr().Interface().(wireHooks); ok {
		hooks.afterEncode(wire)
	}
	return wire, nil
}

func encodeField(field reflect.Value) (any, error) {
	if field.Type() == bytesType {
		return base64.StdEncoding.EncodeToString(field.Bytes()), nil
	}
	switch field.Kind() {
	case reflect.String:
		return field.String(), nil
	case reflect.Int64, reflect.Int:
		return field.Int(), nil
	case reflect.Float64:
		return field.Float(), nil
	case reflect.Bool:
		return field.Bool(), nil
	case reflect.Pointer:
		if field.IsNil() {
			return nil, nil
		}
		if field.Elem().Kind() == reflect.String {
			return field.Elem().String(), nil
		}
		return ToWire(field.Interface())
	case reflect.Slice:
		items := make([]any, field.Len())
		for i := 0; i < field.Len(); i++ {
			item := field.Index(i)
			if item.Kind() == reflect.String {
				items[i] = item.String()
				continue
			}
			encoded, err := ToWire(item.Addr().Interface())
			if err != nil {
				return nil, err
			}
			items[i] = encoded
		}
		return items, nil
	case reflect.Struct:
		return ToWire(field.Addr().Interface())
	case reflect.Interface:
		return field.Interface(), nil
	}
	return nil, fmt.Errorf("unsupported field type %s", field.Type())
}

// FromWire fills model (a pointer to a struct) from a decoded JSON object.
func FromWire(wire any, model any) error {
	object, ok := wire.(map[string]any)
	if !ok {
		return fmt.Errorf("interop: expected a JSON object for %T", model)
	}
	value := reflect.ValueOf(model)
	if value.Kind() != reflect.Pointer || value.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("interop: FromWire needs a struct pointer, got %T", model)
	}
	if hooks, ok := model.(wireHooks); ok {
		copied := make(map[string]any, len(object))
		for key, item := range object {
			copied[key] = item
		}
		hooks.beforeDecode(copied)
		object = copied
	}
	value = value.Elem()
	typ := value.Type()
	for i := 0; i < typ.NumField(); i++ {
		tag, ok := parseTag(typ.Field(i).Tag.Get("wire"))
		if !ok {
			continue
		}
		raw, present := object[tag.key]
		if !present || raw == nil {
			if tag.optional {
				continue
			}
			return fmt.Errorf("interop: %s: missing %s", typ.Name(), tag.key)
		}
		if err := decodeField(raw, value.Field(i)); err != nil {
			return fmt.Errorf("interop: %s.%s: %w", typ.Name(), tag.key, err)
		}
	}
	return nil
}

func decodeField(raw any, field reflect.Value) error {
	if field.Type() == bytesType {
		text, ok := raw.(string)
		if !ok {
			return fmt.Errorf("expected base64 string")
		}
		data, err := base64.StdEncoding.Strict().DecodeString(text)
		if err != nil {
			return fmt.Errorf("invalid base64: %w", err)
		}
		if data == nil {
			data = []byte{}
		}
		field.SetBytes(data)
		return nil
	}
	switch field.Kind() {
	case reflect.String:
		text, ok := raw.(string)
		if !ok {
			return fmt.Errorf("expected string")
		}
		field.SetString(text)
	case reflect.Int64, reflect.Int:
		number, ok := raw.(json.Number)
		if !ok {
			return fmt.Errorf("expected integer")
		}
		parsed, err := number.Int64()
		if err != nil {
			return fmt.Errorf("expected integer: %w", err)
		}
		field.SetInt(parsed)
	case reflect.Float64:
		number, ok := raw.(json.Number)
		if !ok {
			return fmt.Errorf("expected number")
		}
		parsed, err := number.Float64()
		if err != nil {
			return err
		}
		field.SetFloat(parsed)
	case reflect.Bool:
		flag, ok := raw.(bool)
		if !ok {
			return fmt.Errorf("expected bool")
		}
		field.SetBool(flag)
	case reflect.Pointer:
		target := reflect.New(field.Type().Elem())
		if field.Type().Elem().Kind() == reflect.String {
			text, ok := raw.(string)
			if !ok {
				return fmt.Errorf("expected string")
			}
			target.Elem().SetString(text)
		} else if err := FromWire(raw, target.Interface()); err != nil {
			return err
		}
		field.Set(target)
	case reflect.Slice:
		items, ok := raw.([]any)
		if !ok {
			return fmt.Errorf("expected list")
		}
		out := reflect.MakeSlice(field.Type(), len(items), len(items))
		for i, item := range items {
			element := out.Index(i)
			if element.Kind() == reflect.String {
				text, ok := item.(string)
				if !ok {
					return fmt.Errorf("expected list of strings")
				}
				element.SetString(text)
				continue
			}
			if err := FromWire(item, element.Addr().Interface()); err != nil {
				return err
			}
		}
		field.Set(out)
	case reflect.Struct:
		return FromWire(raw, field.Addr().Interface())
	case reflect.Interface:
		field.Set(reflect.ValueOf(raw))
	default:
		return fmt.Errorf("unsupported field type %s", field.Type())
	}
	return nil
}

// EncodedJSON is what Swift JSONEncoder with .sortedKeys writes for model.
func EncodedJSON(model any) ([]byte, error) {
	wire, err := ToWire(model)
	if err != nil {
		return nil, err
	}
	return CanonicalJSON(wire, EncoderOrder)
}

// SignedBytes is what Swift signs for model.
func SignedBytes(model Model) ([]byte, error) {
	if custom, ok := model.(interface{ signedBytes() ([]byte, error) }); ok {
		return custom.signedBytes()
	}
	if challenge, ok := model.(*IdentitySigningChallenge); ok {
		return EncodedJSON(challenge)
	}
	wire, err := ToWire(model)
	if err != nil {
		return nil, err
	}
	return CanonicalPayload(wire, model.ExcludedFromSignature()...)
}

// Decode parses Swift wire JSON into model.
func Decode(data []byte, model any) error {
	value, err := DecodeJSON(data)
	if err != nil {
		return err
	}
	return FromWire(value, model)
}
