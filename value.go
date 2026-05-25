// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
)

type JSONValue = any

var ErrCodec = errors.New("cellprotocol codec error")

func DecodeJSON(data []byte, target any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return dec.Decode(target)
}

func StableJSON(value any) ([]byte, error) {
	return json.Marshal(NormalizeJSON(value))
}

func StableJSONString(value any) (string, error) {
	data, err := StableJSON(value)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func NormalizeJSON(value any) any {
	switch v := value.(type) {
	case nil, bool, string:
		return v
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return i
		}
		if f, err := v.Float64(); err == nil {
			return f
		}
		return v.String()
	case int:
		return v
	case int8:
		return int(v)
	case int16:
		return int(v)
	case int32:
		return int(v)
	case int64:
		return v
	case uint:
		return v
	case uint8:
		return uint(v)
	case uint16:
		return uint(v)
	case uint32:
		return uint(v)
	case uint64:
		return v
	case float32:
		return float64(v)
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return nil
		}
		return v
	case []byte:
		return base64.StdEncoding.EncodeToString(v)
	case []any:
		out := make([]any, len(v))
		for i := range v {
			out[i] = NormalizeJSON(v[i])
		}
		return out
	case []string:
		out := make([]any, len(v))
		for i := range v {
			out[i] = v[i]
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[key] = NormalizeJSON(item)
		}
		return out
	case map[string]string:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[key] = item
		}
		return out
	case interface{ ToJSON() map[string]any }:
		return NormalizeJSON(v.ToJSON())
	case interface{ JSONValue() any }:
		return NormalizeJSON(v.JSONValue())
	default:
		data, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprint(v)
		}
		var decoded any
		if err := DecodeJSON(data, &decoded); err != nil {
			return fmt.Sprint(v)
		}
		return NormalizeJSON(decoded)
	}
}

func StringValue(value any) (string, bool) {
	s, ok := value.(string)
	return s, ok
}

func ObjectValue(value any) (map[string]any, bool) {
	switch v := NormalizeJSON(value).(type) {
	case map[string]any:
		return v, true
	default:
		return nil, false
	}
}

func ListValue(value any) ([]any, bool) {
	switch v := NormalizeJSON(value).(type) {
	case []any:
		return v, true
	default:
		return nil, false
	}
}

type TypedValue struct {
	Kind  string
	Value any
}

var bridgeKeys = map[string]string{
	"description":          "&description",
	"connectState":         "&connectState",
	"agreementState":       "&agreementState",
	"agreementPayload":     "&agreementPayload",
	"verifiableCredential": "&verifiableCredential",
	"cellConfiguration":    "&cellConfiguration",
	"cellReference":        "&cellReference",
	"connectContext":       "&connectContext",
	"flowElement":          "&flowElement",
	"cell":                 "&cell",
	"keyValue":             "&keyValue",
	"setValueState":        "&setValueState",
	"setValueResponse":     "&setValueResponse",
	"signData":             "sign",
	"signature":            "&signature",
	"object":               "&object",
	"number":               "&number",
	"string":               "&string",
	"list":                 "&list",
	"bool":                 "bool",
	"float":                "float",
	"data":                 "data",
	"integer":              "integer",
}

var decodePriority = []string{
	"&agreementPayload",
	"&description",
	"&connectState",
	"&agreementState",
	"&verifiableCredential",
	"&flowElement",
	"&object",
	"&list",
	"&string",
	"&number",
	"float",
	"data",
	"bool",
	"integer",
	"&cellReference",
	"&cellConfiguration",
	"&cell",
	"&keyValue",
	"&setValueState",
	"&setValueResponse",
	"sign",
	"&signature",
	"connectEmitter",
	"absorbFlow",
	"removeConnecion",
	"dropFlow",
	"disconnectAll",
	"unsubscribeAll",
	"keys",
	"typeForKey",
}

func InferTypedValue(value any) TypedValue {
	if typed, ok := value.(TypedValue); ok {
		return typed
	}
	switch v := value.(type) {
	case nil:
		return TypedValue{Kind: "null"}
	case bool:
		return TypedValue{Kind: "bool", Value: v}
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return TypedValue{Kind: "integer", Value: NormalizeJSON(v)}
	case float32, float64:
		return TypedValue{Kind: "float", Value: NormalizeJSON(v)}
	case string:
		return TypedValue{Kind: "string", Value: v}
	case []byte:
		return TypedValue{Kind: "data", Value: v}
	case []any, []string:
		return TypedValue{Kind: "list", Value: NormalizeJSON(v)}
	case KeyValue:
		return TypedValue{Kind: "keyValue", Value: v}
	case SetValueResponse:
		return TypedValue{Kind: "setValueResponse", Value: v}
	case FlowElement:
		return TypedValue{Kind: "flowElement", Value: v}
	case CellConfiguration:
		return TypedValue{Kind: "cellConfiguration", Value: v}
	case CellReference:
		return TypedValue{Kind: "cellReference", Value: v}
	default:
		if obj, ok := ObjectValue(v); ok {
			return TypedValue{Kind: "object", Value: obj}
		}
		return TypedValue{Kind: "object", Value: NormalizeJSON(v)}
	}
}

func (v TypedValue) BridgeKey() (string, error) {
	if v.Kind == "null" {
		return "", nil
	}
	key, ok := bridgeKeys[v.Kind]
	if !ok {
		return "", fmt.Errorf("%w: unknown typed value kind %q", ErrCodec, v.Kind)
	}
	return key, nil
}

func (v TypedValue) BridgePayloadJSON() any {
	if v.Kind == "data" || v.Kind == "signData" || v.Kind == "signature" {
		if raw, ok := v.Value.([]byte); ok {
			return base64.StdEncoding.EncodeToString(raw)
		}
	}
	return NormalizeJSON(v.Value)
}

func BridgeKeyToKind(key string) string {
	for kind, bridgeKey := range bridgeKeys {
		if bridgeKey == key {
			return kind
		}
	}
	return key
}

func PayloadFromBridgeJSON(key string, value any) (TypedValue, error) {
	kind := BridgeKeyToKind(key)
	switch kind {
	case "keyValue":
		data, _ := StableJSON(value)
		var kv KeyValue
		if err := DecodeJSON(data, &kv); err != nil {
			return TypedValue{}, err
		}
		return TypedValue{Kind: kind, Value: kv}, nil
	case "setValueResponse":
		data, _ := StableJSON(value)
		var response SetValueResponse
		if err := DecodeJSON(data, &response); err != nil {
			return TypedValue{}, err
		}
		return TypedValue{Kind: kind, Value: response}, nil
	case "flowElement":
		data, _ := StableJSON(value)
		var flow FlowElement
		if err := DecodeJSON(data, &flow); err != nil {
			return TypedValue{}, err
		}
		return TypedValue{Kind: kind, Value: flow}, nil
	case "cellConfiguration":
		data, _ := StableJSON(value)
		var configuration CellConfiguration
		if err := DecodeJSON(data, &configuration); err != nil {
			return TypedValue{}, err
		}
		return TypedValue{Kind: kind, Value: configuration}, nil
	case "cellReference":
		data, _ := StableJSON(value)
		var reference CellReference
		if err := DecodeJSON(data, &reference); err != nil {
			return TypedValue{}, err
		}
		return TypedValue{Kind: kind, Value: reference}, nil
	case "data", "signData", "signature":
		s, ok := value.(string)
		if !ok {
			return TypedValue{}, fmt.Errorf("%w: bridge data payload must be base64 string", ErrCodec)
		}
		raw, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return TypedValue{}, err
		}
		return TypedValue{Kind: kind, Value: raw}, nil
	default:
		return TypedValue{Kind: kind, Value: NormalizeJSON(value)}, nil
	}
}

type KeyValue struct {
	Key    string
	Value  any
	Target string
}

func (kv KeyValue) MarshalJSON() ([]byte, error) {
	out := map[string]any{"key": kv.Key}
	if kv.Target != "" {
		out["target"] = kv.Target
	}
	value := NormalizeJSON(kv.Value)
	switch v := value.(type) {
	case nil:
	case string:
		out["string"] = v
	case bool:
		out["bool"] = v
	case int, int64, uint, uint64:
		out["integer"] = v
	case float64:
		out["float"] = v
	case []any:
		out["list"] = v
	case map[string]any:
		out["object"] = v
	default:
		out["value"] = v
	}
	return json.Marshal(out)
}

func (kv *KeyValue) UnmarshalJSON(data []byte) error {
	var payload map[string]any
	if err := DecodeJSON(data, &payload); err != nil {
		return err
	}
	key, ok := payload["key"].(string)
	if !ok || key == "" {
		return fmt.Errorf("%w: KeyValue requires string field 'key'", ErrCodec)
	}
	kv.Key = key
	if target, ok := payload["target"].(string); ok {
		kv.Target = target
	}
	for _, field := range []string{"string", "number", "float", "integer", "object", "list", "bool", "value"} {
		if value, ok := payload[field]; ok {
			kv.Value = NormalizeJSON(value)
			return nil
		}
	}
	return nil
}

type SetValueResponse struct {
	State string `json:"state"`
	Value any    `json:"value,omitempty"`
}

func SetOK(value any) SetValueResponse {
	return SetValueResponse{State: "ok", Value: value}
}

func SetDenied(reason any) SetValueResponse {
	return SetValueResponse{State: "denied", Value: reason}
}

func SetParamErr(reason any) SetValueResponse {
	return SetValueResponse{State: "paramErr", Value: reason}
}

func SetError(reason any) SetValueResponse {
	return SetValueResponse{State: "error", Value: reason}
}

func (r SetValueResponse) MarshalJSON() ([]byte, error) {
	if r.State == "" {
		r.State = "ok"
	}
	switch r.State {
	case "ok", "denied", "paramErr", "error":
	default:
		return nil, fmt.Errorf("%w: invalid SetValueResponse state %q", ErrCodec, r.State)
	}
	out := map[string]any{"state": r.State}
	if r.Value != nil {
		out["value"] = NormalizeJSON(r.Value)
	}
	return json.Marshal(out)
}

func (r *SetValueResponse) UnmarshalJSON(data []byte) error {
	var payload map[string]any
	if err := DecodeJSON(data, &payload); err != nil {
		return err
	}
	state, _ := payload["state"].(string)
	switch state {
	case "ok", "denied", "paramErr", "error":
		r.State = state
	default:
		return fmt.Errorf("%w: invalid SetValueResponse state %q", ErrCodec, state)
	}
	r.Value = NormalizeJSON(payload["value"])
	return nil
}

type AgreementTemplate struct {
	Grants []Grant `json:"grants"`
}

func (t *AgreementTemplate) AddGrant(permission, keypath string) {
	t.Grants = append(t.Grants, NewGrant("", keypath, permission))
}

func SortedStrings(values []string) []string {
	seen := map[string]struct{}{}
	for _, value := range values {
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
