// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

type CloudBridgeOptions struct {
	HandshakeTimeout       time.Duration
	RequestTimeout         time.Duration
	MaxMessageBytes        int64
	Headers                map[string]string
	AllowInsecureWebSocket bool
	InsecureSkipVerify     bool
}

func DefaultCloudBridgeOptions() CloudBridgeOptions {
	return CloudBridgeOptions{
		HandshakeTimeout: 10 * time.Second,
		RequestTimeout:   15 * time.Second,
		MaxMessageBytes:  defaultWebSocketMaxMessageBytes,
	}
}

type pendingBridgeResponse struct {
	command string
	ch      chan bridgeResponseResult
}

type bridgeResponseResult struct {
	response BridgeCommand
	err      error
}

type CloudBridge struct {
	endpoint string
	identity *Identity
	options  CloudBridgeOptions
	base     *BridgeBase

	mu           sync.Mutex
	socket       *webSocketClient
	connecting   bool
	connected    bool
	closed       bool
	readErr      error
	pending      map[int]pendingBridgeResponse
	feedCID      int
	feedSinks    map[int]chan FlowElement
	nextFeedSink int
	ready        chan struct{}
	readyOnce    sync.Once
	closeOnce    sync.Once

	cachedDescription *AnyCell
}

func NewCloudBridge(endpoint string, identity *Identity, options CloudBridgeOptions) *CloudBridge {
	defaults := DefaultCloudBridgeOptions()
	if options.HandshakeTimeout == 0 {
		options.HandshakeTimeout = defaults.HandshakeTimeout
	}
	if options.RequestTimeout == 0 {
		options.RequestTimeout = defaults.RequestTimeout
	}
	if options.MaxMessageBytes == 0 {
		options.MaxMessageBytes = defaults.MaxMessageBytes
	}
	bridge := &CloudBridge{
		endpoint:  endpoint,
		identity:  identity,
		options:   options,
		pending:   map[int]pendingBridgeResponse{},
		feedSinks: map[int]chan FlowElement{},
		ready:     make(chan struct{}),
	}
	bridge.base = NewBridgeBase(bridge.SendCommand, identity)
	return bridge
}

func (b *CloudBridge) Endpoint() string {
	return b.endpoint
}

func (b *CloudBridge) Connect(ctx context.Context) error {
	b.mu.Lock()
	if b.connected {
		b.mu.Unlock()
		return nil
	}
	if b.connecting {
		b.mu.Unlock()
		for {
			b.mu.Lock()
			done := b.connected || !b.connecting || b.readErr != nil
			err := b.readErr
			b.mu.Unlock()
			if done {
				if err != nil {
					return err
				}
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	b.connecting = true
	b.mu.Unlock()

	socket, err := dialWebSocket(ctx, b.endpoint, webSocketDialOptions{
		HandshakeTimeout:       b.options.HandshakeTimeout,
		InsecureSkipVerify:     b.options.InsecureSkipVerify,
		Headers:                b.options.Headers,
		MaxMessageBytes:        b.options.MaxMessageBytes,
		AllowInsecureWebSocket: b.options.AllowInsecureWebSocket,
	})

	b.mu.Lock()
	defer b.mu.Unlock()
	b.connecting = false
	if err != nil {
		b.readErr = err
		return err
	}
	b.socket = socket
	b.connected = true
	b.readErr = nil
	go b.readLoop()
	return nil
}

func (b *CloudBridge) Ready(ctx context.Context) error {
	if err := b.Connect(ctx); err != nil {
		return err
	}
	select {
	case <-b.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *CloudBridge) SendCommand(ctx context.Context, command BridgeCommand) (BridgeCommand, error) {
	if err := b.Connect(ctx); err != nil {
		return BridgeCommand{}, err
	}
	if command.CID == 0 {
		b.mu.Lock()
		b.base.cid++
		command.CID = b.base.cid
		b.mu.Unlock()
	}
	if command.Identity == nil {
		command.Identity = b.identity
	}
	data, err := json.Marshal(command)
	if err != nil {
		return BridgeCommand{}, err
	}
	timeoutCtx := ctx
	cancel := func() {}
	if _, ok := ctx.Deadline(); !ok && b.options.RequestTimeout > 0 {
		timeoutCtx, cancel = context.WithTimeout(ctx, b.options.RequestTimeout)
	}
	defer cancel()

	pending := pendingBridgeResponse{command: command.Cmd, ch: make(chan bridgeResponseResult, 1)}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return BridgeCommand{}, fmt.Errorf("cloud bridge is closed")
	}
	b.pending[command.CID] = pending
	socket := b.socket
	b.mu.Unlock()

	if err := socket.SendText(timeoutCtx, data); err != nil {
		b.removePending(command.CID)
		return BridgeCommand{}, err
	}
	select {
	case result := <-pending.ch:
		if result.err != nil {
			return BridgeCommand{}, result.err
		}
		return result.response, nil
	case <-timeoutCtx.Done():
		b.removePending(command.CID)
		return BridgeCommand{}, timeoutCtx.Err()
	}
}

func (b *CloudBridge) Flow(ctx context.Context, requester *Identity) (<-chan FlowElement, error) {
	if err := b.Connect(ctx); err != nil {
		return nil, err
	}
	ch := make(chan FlowElement, 64)
	b.mu.Lock()
	b.nextFeedSink++
	sinkID := b.nextFeedSink
	b.feedSinks[sinkID] = ch
	needsSubscribe := b.feedCID == 0
	var cid int
	if needsSubscribe {
		b.base.cid++
		cid = b.base.cid
		b.feedCID = cid
	} else {
		cid = b.feedCID
	}
	socket := b.socket
	b.mu.Unlock()

	if needsSubscribe {
		identity := requester
		if identity == nil {
			identity = b.identity
		}
		command := BridgeCommand{Cmd: "feed", CID: cid, Identity: identity}
		data, err := json.Marshal(command)
		if err != nil {
			b.removeFeedSink(sinkID)
			return nil, err
		}
		sendCtx := ctx
		cancel := func() {}
		if _, ok := ctx.Deadline(); !ok && b.options.RequestTimeout > 0 {
			sendCtx, cancel = context.WithTimeout(ctx, b.options.RequestTimeout)
		}
		defer cancel()
		if err := socket.SendText(sendCtx, data); err != nil {
			b.removeFeedSink(sinkID)
			return nil, err
		}
	}
	go func() {
		<-ctx.Done()
		b.removeFeedSink(sinkID)
	}()
	return ch, nil
}

func (b *CloudBridge) CloseConnection() error {
	var err error
	b.closeOnce.Do(func() {
		b.mu.Lock()
		b.closed = true
		socket := b.socket
		b.socket = nil
		b.connected = false
		b.failPendingLocked(fmt.Errorf("cloud bridge closed"))
		b.closeFeedSinksLocked()
		b.mu.Unlock()
		if socket != nil {
			err = socket.Close()
		}
	})
	return err
}

func (b *CloudBridge) Get(ctx context.Context, keypath string, requester *Identity) (any, error) {
	return b.base.Get(ctx, keypath, requester)
}

func (b *CloudBridge) Set(ctx context.Context, keypath string, value any, requester *Identity) (any, error) {
	return b.base.Set(ctx, keypath, value, requester)
}

func (b *CloudBridge) Admit(ctx context.Context, connect ConnectContext) (ConnectState, error) {
	return b.base.Admit(ctx, connect)
}

func (b *CloudBridge) Close(ctx context.Context, requester *Identity) error {
	_ = requester
	return b.CloseConnection()
}

func (b *CloudBridge) AddAgreement(ctx context.Context, contract Agreement, identity *Identity) (AgreementState, error) {
	return b.base.AddAgreement(ctx, contract, identity)
}

func (b *CloudBridge) Advertise(ctx context.Context, requester *Identity) (AnyCell, error) {
	description, err := b.base.Advertise(ctx, requester)
	if err == nil {
		b.mu.Lock()
		b.cachedDescription = &description
		b.mu.Unlock()
	}
	return description, err
}

func (b *CloudBridge) State(ctx context.Context, requester *Identity) (any, error) {
	return b.base.State(ctx, requester)
}

func (b *CloudBridge) CellUUID() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cachedDescription != nil {
		return b.cachedDescription.UUID
	}
	return ""
}

func (b *CloudBridge) IdentityDomain() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cachedDescription != nil {
		return b.cachedDescription.IdentityDomain
	}
	return ""
}

func (b *CloudBridge) GetOwner(ctx context.Context, requester *Identity) (*Identity, error) {
	return b.base.GetOwner(ctx, requester)
}

func (b *CloudBridge) GetEmitterWithUUID(ctx context.Context, uuid string, requester *Identity) (Emit, error) {
	return b.base.GetEmitterWithUUID(ctx, uuid, requester)
}

func (b *CloudBridge) Attach(ctx context.Context, emitter Emit, label string, requester *Identity) (ConnectState, error) {
	return b.base.Attach(ctx, emitter, label, requester)
}

func (b *CloudBridge) AbsorbFlow(ctx context.Context, label string, requester *Identity) error {
	return b.base.AbsorbFlow(ctx, label, requester)
}

func (b *CloudBridge) Detach(ctx context.Context, label string, requester *Identity) error {
	return b.base.Detach(ctx, label, requester)
}

func (b *CloudBridge) DropFlow(ctx context.Context, label string, requester *Identity) error {
	return b.base.DropFlow(ctx, label, requester)
}

func (b *CloudBridge) DropAllFlows(ctx context.Context, requester *Identity) error {
	return b.base.DropAllFlows(ctx, requester)
}

func (b *CloudBridge) DetachAll(ctx context.Context, requester *Identity) error {
	return b.base.DetachAll(ctx, requester)
}

func (b *CloudBridge) AttachedStatus(ctx context.Context, label string, requester *Identity) (ConnectionStatus, error) {
	return b.base.AttachedStatus(ctx, label, requester)
}

func (b *CloudBridge) AttachedStatuses(ctx context.Context, requester *Identity) ([]ConnectionStatus, error) {
	return b.base.AttachedStatuses(ctx, requester)
}

func (b *CloudBridge) Keys(ctx context.Context, requester *Identity) ([]string, error) {
	return b.base.Keys(ctx, requester)
}

func (b *CloudBridge) TypeForKey(ctx context.Context, keypath string, requester *Identity) (string, error) {
	return b.base.TypeForKey(ctx, keypath, requester)
}

func (b *CloudBridge) IsMember(ctx context.Context, identity *Identity, requester *Identity) (bool, error) {
	return b.base.IsMember(ctx, identity, requester)
}

func (b *CloudBridge) readLoop() {
	for {
		b.mu.Lock()
		socket := b.socket
		b.mu.Unlock()
		if socket == nil {
			return
		}
		message, err := socket.ReadMessage()
		if err != nil {
			b.handleReadError(err)
			return
		}
		var command BridgeCommand
		if err := DecodeJSON(message, &command); err != nil {
			continue
		}
		b.handleIncoming(command)
	}
}

func (b *CloudBridge) handleIncoming(command BridgeCommand) {
	switch command.Command() {
	case "ready":
		b.markReady()
	case "response":
		if b.handleFeedResponse(command) {
			return
		}
		b.mu.Lock()
		pending := b.pending[command.CID]
		if pending.ch != nil {
			delete(b.pending, command.CID)
		}
		b.mu.Unlock()
		if pending.ch != nil {
			pending.ch <- bridgeResponseResult{response: command}
		}
	case "sign":
		b.handleSignCommand(command)
	default:
		b.sendUnsupported(command)
	}
}

func (b *CloudBridge) handleFeedResponse(command BridgeCommand) bool {
	typed, ok := command.Payload.(TypedValue)
	if !ok || typed.Kind != "flowElement" {
		return false
	}
	b.mu.Lock()
	isFeed := command.CID == b.feedCID && b.feedCID != 0
	sinks := make([]chan FlowElement, 0, len(b.feedSinks))
	if isFeed {
		for _, ch := range b.feedSinks {
			sinks = append(sinks, ch)
		}
	}
	b.mu.Unlock()
	if !isFeed {
		return false
	}
	flow, ok := typed.Value.(FlowElement)
	if !ok {
		data, _ := StableJSON(typed.Value)
		_ = DecodeJSON(data, &flow)
	}
	for _, sink := range sinks {
		select {
		case sink <- flow:
		default:
		}
	}
	return true
}

func (b *CloudBridge) handleSignCommand(command BridgeCommand) {
	if b.identity == nil || command.Identity == nil || command.Identity.UUID != b.identity.UUID {
		b.sendResponse(command.CID, TypedValue{Kind: "string", Value: "signing denied: identity mismatch"})
		return
	}
	typed, ok := command.Payload.(TypedValue)
	if !ok || typed.Kind != "signData" {
		b.sendResponse(command.CID, TypedValue{Kind: "string", Value: "signing denied: missing sign payload"})
		return
	}
	message, ok := typed.Value.([]byte)
	if !ok {
		b.sendResponse(command.CID, TypedValue{Kind: "string", Value: "signing denied: invalid sign payload"})
		return
	}
	signature, err := b.identity.Sign(context.Background(), message)
	if err != nil {
		b.sendResponse(command.CID, TypedValue{Kind: "string", Value: "signing denied: " + err.Error()})
		return
	}
	b.sendResponse(command.CID, TypedValue{Kind: "signature", Value: signature})
}

func (b *CloudBridge) sendUnsupported(command BridgeCommand) {
	if command.CID == 0 {
		return
	}
	b.sendResponse(command.CID, TypedValue{Kind: "string", Value: "unsupported command: " + command.Cmd})
}

func (b *CloudBridge) sendResponse(cid int, payload any) {
	b.mu.Lock()
	socket := b.socket
	b.mu.Unlock()
	if socket == nil {
		return
	}
	data, err := json.Marshal(BridgeCommand{Cmd: "response", CID: cid, Payload: payload, Identity: b.identity})
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), b.options.RequestTimeout)
	defer cancel()
	_ = socket.SendText(ctx, data)
}

func (b *CloudBridge) markReady() {
	b.readyOnce.Do(func() {
		close(b.ready)
	})
}

func (b *CloudBridge) handleReadError(err error) {
	b.mu.Lock()
	b.readErr = err
	b.connected = false
	b.socket = nil
	b.failPendingLocked(err)
	b.closeFeedSinksLocked()
	b.mu.Unlock()
}

func (b *CloudBridge) removePending(cid int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.pending, cid)
}

func (b *CloudBridge) removeFeedSink(id int) {
	b.mu.Lock()
	ch := b.feedSinks[id]
	delete(b.feedSinks, id)
	if len(b.feedSinks) == 0 {
		b.feedCID = 0
	}
	b.mu.Unlock()
	if ch != nil {
		close(ch)
	}
}

func (b *CloudBridge) failPendingLocked(err error) {
	for cid, pending := range b.pending {
		delete(b.pending, cid)
		pending.ch <- bridgeResponseResult{err: err}
	}
}

func (b *CloudBridge) closeFeedSinksLocked() {
	for id, ch := range b.feedSinks {
		delete(b.feedSinks, id)
		close(ch)
	}
	b.feedCID = 0
}
