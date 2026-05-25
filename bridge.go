// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

import (
	"context"
	"encoding/json"
	"fmt"
)

var bridgeCommands = map[string]struct{}{
	"ready":              {},
	"description":        {},
	"admit":              {},
	"agreement":          {},
	"feed":               {},
	"state":              {},
	"emitter":            {},
	"valueForKeypath":    {},
	"setValueForKeypath": {},
	"get":                {},
	"set":                {},
	"connectEmitter":     {},
	"absorbFlow":         {},
	"removeConnecion":    {},
	"dropFlow":           {},
	"disconnectAll":      {},
	"unsubscribeAll":     {},
	"attachedStatus":     {},
	"attachedStatuses":   {},
	"keys":               {},
	"typeForKey":         {},
	"sign":               {},
	"response":           {},
	"none":               {},
}

type BridgeCommand struct {
	Cmd      string
	Payload  any
	CID      int
	Identity *Identity
}

func (c BridgeCommand) Command() string {
	if _, ok := bridgeCommands[c.Cmd]; ok {
		return c.Cmd
	}
	return "none"
}

func (c BridgeCommand) MarshalJSON() ([]byte, error) {
	out := map[string]any{"cmd": c.Cmd, "cid": c.CID}
	if c.Identity != nil {
		out["identity"] = c.Identity
	}
	if c.Payload != nil {
		typed := InferTypedValue(c.Payload)
		if typed.Kind != "null" {
			key, err := typed.BridgeKey()
			if err != nil {
				return nil, err
			}
			out[key] = typed.BridgePayloadJSON()
		}
	}
	return json.Marshal(out)
}

func (c *BridgeCommand) UnmarshalJSON(data []byte) error {
	var payload map[string]any
	if err := DecodeJSON(data, &payload); err != nil {
		return err
	}
	cmd, ok := payload["cmd"].(string)
	if !ok {
		return fmt.Errorf("BridgeCommand requires string field 'cmd'")
	}
	c.Cmd = cmd
	switch cid := payload["cid"].(type) {
	case json.Number:
		n, err := cid.Int64()
		if err != nil {
			return err
		}
		c.CID = int(n)
	case int:
		c.CID = cid
	case float64:
		c.CID = int(cid)
	default:
		return fmt.Errorf("BridgeCommand requires integer field 'cid'")
	}
	if raw, ok := payload["identity"]; ok {
		data, _ := StableJSON(raw)
		var identity Identity
		if err := DecodeJSON(data, &identity); err != nil {
			return err
		}
		c.Identity = &identity
	}
	for _, key := range decodePriority {
		if raw, ok := payload[key]; ok {
			typed, err := PayloadFromBridgeJSON(key, raw)
			if err != nil {
				return err
			}
			c.Payload = typed
			break
		}
	}
	return nil
}

func (c BridgeCommand) Dumps() (string, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

type BridgeEndpoint struct {
	Target CellProtocol
	Owner  *Identity
}

func NewBridgeEndpoint(target CellProtocol, owner *Identity) *BridgeEndpoint {
	return &BridgeEndpoint{Target: target, Owner: owner}
}

func (e *BridgeEndpoint) Handle(ctx context.Context, command BridgeCommand) []BridgeCommand {
	requester := command.Identity
	if requester == nil {
		requester = e.Owner
	}
	cid := command.CID
	response := func(value any) []BridgeCommand {
		return []BridgeCommand{{Cmd: "response", CID: cid, Payload: value}}
	}
	fail := func(err error) []BridgeCommand {
		return response(TypedValue{Kind: "setValueResponse", Value: SetError(err.Error())})
	}
	switch command.Command() {
	case "ready":
		return []BridgeCommand{{Cmd: "ready", CID: cid}}
	case "description":
		value, err := e.Target.Advertise(ctx, requester)
		if err != nil {
			return fail(err)
		}
		return response(TypedValue{Kind: "description", Value: value})
	case "admit":
		connect := ConnectContext{}
		if typed, ok := command.Payload.(TypedValue); ok {
			data, _ := StableJSON(typed.Value)
			_ = DecodeJSON(data, &connect)
		}
		state, err := e.Target.Admit(ctx, connect)
		if err != nil {
			return fail(err)
		}
		return response(TypedValue{Kind: "connectState", Value: string(state)})
	case "agreement":
		return response(TypedValue{Kind: "agreementState", Value: string(AgreementSigned)})
	case "get":
		keypath, err := payloadString(command.Payload)
		if err != nil {
			return fail(err)
		}
		value, err := e.Target.Get(ctx, keypath, requester)
		if err != nil {
			return fail(err)
		}
		return response(InferTypedValue(value))
	case "set":
		kv, err := payloadKeyValue(command.Payload)
		if err != nil {
			return fail(err)
		}
		value, err := e.Target.Set(ctx, kv.Key, kv.Value, requester)
		if err != nil {
			return fail(err)
		}
		return response(TypedValue{Kind: "setValueResponse", Value: SetOK(value)})
	case "keys":
		keys, err := e.Target.Keys(ctx, requester)
		if err != nil {
			return fail(err)
		}
		return response(TypedValue{Kind: "list", Value: keys})
	case "typeForKey":
		keypath, err := payloadString(command.Payload)
		if err != nil {
			return fail(err)
		}
		typ, err := e.Target.TypeForKey(ctx, keypath, requester)
		if err != nil {
			return fail(err)
		}
		return response(TypedValue{Kind: "string", Value: typ})
	case "attachedStatus":
		label, err := payloadString(command.Payload)
		if err != nil {
			return fail(err)
		}
		status, err := e.Target.AttachedStatus(ctx, label, requester)
		if err != nil {
			return fail(err)
		}
		return response(TypedValue{Kind: "object", Value: status})
	case "attachedStatuses":
		statuses, err := e.Target.AttachedStatuses(ctx, requester)
		if err != nil {
			return fail(err)
		}
		return response(TypedValue{Kind: "list", Value: statuses})
	case "sign":
		if requester == nil {
			return fail(fmt.Errorf("sign requires identity"))
		}
		message, err := payloadBytes(command.Payload)
		if err != nil {
			return fail(err)
		}
		signature, err := requester.Sign(ctx, message)
		if err != nil {
			return fail(err)
		}
		return response(TypedValue{Kind: "signature", Value: signature})
	default:
		return response(TypedValue{Kind: "string", Value: "unsupported command: " + command.Cmd})
	}
}

type SendCommand func(context.Context, BridgeCommand) (BridgeCommand, error)

type BridgeBase struct {
	send     SendCommand
	identity *Identity
	cid      int
}

func NewBridgeBase(send SendCommand, identity *Identity) *BridgeBase {
	return &BridgeBase{send: send, identity: identity}
}

func (b *BridgeBase) request(ctx context.Context, cmd string, payload any) (any, error) {
	if b.send == nil {
		return nil, fmt.Errorf("BridgeBase has no transport")
	}
	b.cid++
	command := BridgeCommand{Cmd: cmd, Payload: payload, CID: b.cid, Identity: b.identity}
	response, err := b.send(ctx, command)
	if err != nil {
		return nil, err
	}
	if typed, ok := response.Payload.(TypedValue); ok {
		return typed.Value, nil
	}
	return response.Payload, nil
}

func (b *BridgeBase) Get(ctx context.Context, keypath string, requester *Identity) (any, error) {
	_ = requester
	return b.request(ctx, "get", TypedValue{Kind: "string", Value: keypath})
}

func (b *BridgeBase) Set(ctx context.Context, keypath string, value any, requester *Identity) (any, error) {
	_ = requester
	response, err := b.request(ctx, "set", TypedValue{Kind: "keyValue", Value: KeyValue{Key: keypath, Value: value}})
	if err != nil {
		return nil, err
	}
	if setResponse, ok := response.(SetValueResponse); ok {
		if setResponse.State != "ok" {
			return nil, fmt.Errorf("%v", setResponse.Value)
		}
		return setResponse.Value, nil
	}
	return response, nil
}

func (b *BridgeBase) Flow(ctx context.Context, requester *Identity) (<-chan FlowElement, error) {
	_ = ctx
	_ = requester
	return nil, fmt.Errorf("remote flow transport not configured")
}

func (b *BridgeBase) Admit(ctx context.Context, connect ConnectContext) (ConnectState, error) {
	value, err := b.request(ctx, "admit", TypedValue{Kind: "connectContext", Value: connect})
	if err != nil {
		return ConnectDenied, err
	}
	if state, ok := value.(string); ok {
		return ConnectState(state), nil
	}
	return ConnectDenied, nil
}

func (b *BridgeBase) Close(context.Context, *Identity) error { return nil }

func (b *BridgeBase) AddAgreement(ctx context.Context, contract Agreement, identity *Identity) (AgreementState, error) {
	_ = identity
	value, err := b.request(ctx, "agreement", TypedValue{Kind: "agreementPayload", Value: contract})
	if err != nil {
		return AgreementRejected, err
	}
	if state, ok := value.(string); ok {
		return AgreementState(state), nil
	}
	return AgreementSigned, nil
}

func (b *BridgeBase) Advertise(ctx context.Context, requester *Identity) (AnyCell, error) {
	_ = requester
	value, err := b.request(ctx, "description", nil)
	if err != nil {
		return AnyCell{}, err
	}
	data, _ := StableJSON(value)
	var cell AnyCell
	return cell, DecodeJSON(data, &cell)
}

func (b *BridgeBase) State(ctx context.Context, requester *Identity) (any, error) {
	_ = requester
	return b.request(ctx, "state", nil)
}

func (b *BridgeBase) CellUUID() string { return "" }

func (b *BridgeBase) IdentityDomain() string { return "" }

func (b *BridgeBase) GetOwner(context.Context, *Identity) (*Identity, error) { return b.identity, nil }

func (b *BridgeBase) GetEmitterWithUUID(context.Context, string, *Identity) (Emit, error) {
	return nil, nil
}

func (b *BridgeBase) Attach(context.Context, Emit, string, *Identity) (ConnectState, error) {
	return ConnectDenied, fmt.Errorf("remote attach transport not configured")
}

func (b *BridgeBase) AbsorbFlow(context.Context, string, *Identity) error { return nil }
func (b *BridgeBase) Detach(context.Context, string, *Identity) error     { return nil }
func (b *BridgeBase) DropFlow(context.Context, string, *Identity) error   { return nil }
func (b *BridgeBase) DropAllFlows(context.Context, *Identity) error       { return nil }
func (b *BridgeBase) DetachAll(context.Context, *Identity) error          { return nil }

func (b *BridgeBase) AttachedStatus(context.Context, string, *Identity) (ConnectionStatus, error) {
	return ConnectionStatus{State: ConnectNotConnected}, nil
}

func (b *BridgeBase) AttachedStatuses(context.Context, *Identity) ([]ConnectionStatus, error) {
	return nil, nil
}

func (b *BridgeBase) Keys(ctx context.Context, requester *Identity) ([]string, error) {
	_ = requester
	value, err := b.request(ctx, "keys", nil)
	if err != nil {
		return nil, err
	}
	list, ok := ListValue(value)
	if !ok {
		return nil, nil
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out, nil
}

func (b *BridgeBase) TypeForKey(ctx context.Context, keypath string, requester *Identity) (string, error) {
	_ = requester
	value, err := b.request(ctx, "typeForKey", TypedValue{Kind: "string", Value: keypath})
	if err != nil {
		return "", err
	}
	s, _ := value.(string)
	return s, nil
}

func (b *BridgeBase) IsMember(context.Context, *Identity, *Identity) (bool, error) { return false, nil }

func payloadString(payload any) (string, error) {
	if typed, ok := payload.(TypedValue); ok {
		payload = typed.Value
	}
	s, ok := payload.(string)
	if !ok {
		return "", fmt.Errorf("expected string payload")
	}
	return s, nil
}

func payloadKeyValue(payload any) (KeyValue, error) {
	if typed, ok := payload.(TypedValue); ok {
		payload = typed.Value
	}
	if kv, ok := payload.(KeyValue); ok {
		return kv, nil
	}
	data, _ := StableJSON(payload)
	var kv KeyValue
	if err := DecodeJSON(data, &kv); err != nil {
		return KeyValue{}, err
	}
	return kv, nil
}

func payloadBytes(payload any) ([]byte, error) {
	if typed, ok := payload.(TypedValue); ok {
		payload = typed.Value
	}
	switch v := payload.(type) {
	case []byte:
		return v, nil
	case string:
		return []byte(v), nil
	default:
		data, err := StableJSON(v)
		return data, err
	}
}
