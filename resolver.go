// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
)

type ResolverError string

func (e ResolverError) Error() string { return string(e) }

type RemoteCellHostRoute struct {
	WebSocketEndpoint string `json:"websocketEndpoint"`
	SchemePreference  string `json:"schemePreference"`
	PathLayout        string `json:"pathLayout"`
}

func NewRemoteCellHostRoute() RemoteCellHostRoute {
	return RemoteCellHostRoute{
		WebSocketEndpoint: "bridgehead",
		SchemePreference:  "automatic",
		PathLayout:        "publisherUUIDThenEndpoint",
	}
}

func (r RemoteCellHostRoute) websocketScheme(allowsInsecure bool) (string, error) {
	switch r.SchemePreference {
	case "", "automatic":
		if allowsInsecure {
			return "ws", nil
		}
		return "wss", nil
	case "ws":
		if !allowsInsecure {
			return "", ResolverError("insecure ws transport is disabled")
		}
		return "ws", nil
	case "wss":
		return "wss", nil
	default:
		return "", ResolverError("unsupported websocket scheme: " + r.SchemePreference)
	}
}

func (r RemoteCellHostRoute) BridgePath(endpoint, publisherUUID string) string {
	prefix := strings.Trim(r.WebSocketEndpoint, "/")
	if prefix == "" {
		prefix = "bridgehead"
	}
	endpoint = strings.Trim(endpoint, "/")
	if r.PathLayout == "" || r.PathLayout == "publisherUUIDThenEndpoint" {
		return "/" + prefix + "/" + publisherUUID + "/" + endpoint
	}
	return "/" + prefix + "/" + endpoint + "/" + publisherUUID
}

func (r RemoteCellHostRoute) BridgeURL(host, endpoint, publisherUUID string, allowsInsecure bool) (string, error) {
	scheme, err := r.websocketScheme(allowsInsecure)
	if err != nil {
		return "", err
	}
	return scheme + "://" + host + r.BridgePath(endpoint, publisherUUID), nil
}

type CellFactory func(context.Context, *Identity) (CellProtocol, error)

type CellResolve struct {
	Name        string
	EmitCell    CellProtocol
	Factory     CellFactory
	Scope       CellUsageScope
	Identity    *Identity
	Persistancy Persistancy

	scaffoldInstance  CellProtocol
	identityInstances map[string]CellProtocol
}

func (r *CellResolve) Resolve(ctx context.Context, requester *Identity) (CellProtocol, error) {
	switch r.Scope {
	case ScopeTemplate:
		return r.newInstance(ctx, requester)
	case ScopeIdentityUnique:
		key := "anonymous"
		if requester != nil {
			key = requester.UUID
		} else if r.Identity != nil {
			key = r.Identity.UUID
		}
		if r.identityInstances == nil {
			r.identityInstances = map[string]CellProtocol{}
		}
		if r.identityInstances[key] == nil {
			cell, err := r.newInstance(ctx, requester)
			if err != nil {
				return nil, err
			}
			r.identityInstances[key] = cell
		}
		return r.identityInstances[key], nil
	default:
		if r.scaffoldInstance == nil {
			if r.EmitCell != nil {
				r.scaffoldInstance = r.EmitCell
			} else {
				cell, err := r.newInstance(ctx, requester)
				if err != nil {
					return nil, err
				}
				r.scaffoldInstance = cell
			}
		}
		return r.scaffoldInstance, nil
	}
}

func (r *CellResolve) newInstance(ctx context.Context, requester *Identity) (CellProtocol, error) {
	if r.Factory == nil {
		if r.EmitCell != nil {
			return r.EmitCell, nil
		}
		return nil, fmt.Errorf("no cell factory registered for %s", r.Name)
	}
	owner := requester
	if owner == nil {
		owner = r.Identity
	}
	return r.Factory(ctx, owner)
}

type CellResolver struct {
	mu                       sync.RWMutex
	allowsInsecureWebSockets bool
	named                    map[string]*CellResolve
	byUUID                   map[string]CellProtocol
	remoteHosts              map[string]RemoteCellHostRoute
	remoteCache              map[string]*CloudBridge
}

func NewCellResolver() *CellResolver {
	return &CellResolver{
		named:       map[string]*CellResolve{},
		byUUID:      map[string]CellProtocol{},
		remoteHosts: map[string]RemoteCellHostRoute{},
		remoteCache: map[string]*CloudBridge{},
	}
}

func (r *CellResolver) AllowInsecureWebSockets(allow bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.allowsInsecureWebSockets = allow
}

type RegisterOptions struct {
	Scope       CellUsageScope
	Identity    *Identity
	Factory     CellFactory
	Persistancy Persistancy
}

func (r *CellResolver) RegisterNamedEmitCell(ctx context.Context, name string, cell CellProtocol, opts RegisterOptions) error {
	_ = ctx
	if name == "" {
		return ResolverError("cell name is required")
	}
	if opts.Scope == "" {
		opts.Scope = ScopeScaffoldUnique
	}
	if opts.Persistancy == "" {
		opts.Persistancy = Ephemeral
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.named[name]; exists {
		return fmt.Errorf("cell name already registered: %s", name)
	}
	resolve := &CellResolve{
		Name:        name,
		EmitCell:    cell,
		Factory:     opts.Factory,
		Scope:       opts.Scope,
		Identity:    opts.Identity,
		Persistancy: opts.Persistancy,
	}
	r.named[name] = resolve
	if cell != nil && cell.CellUUID() != "" {
		r.byUUID[cell.CellUUID()] = cell
	}
	return nil
}

func (r *CellResolver) UnregisterEmitCell(ctx context.Context, uuid string) error {
	_ = ctx
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.byUUID, uuid)
	for name, resolve := range r.named {
		if resolve.EmitCell != nil && resolve.EmitCell.CellUUID() == uuid {
			delete(r.named, name)
		}
	}
	return nil
}

func (r *CellResolver) RegisterRemoteHost(host string, route RemoteCellHostRoute) {
	if route.WebSocketEndpoint == "" {
		route = NewRemoteCellHostRoute()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.remoteHosts[host] = route
}

func (r *CellResolver) UnregisterRemoteHost(host string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.remoteHosts, host)
}

func (r *CellResolver) RemoteHostSnapshot() map[string]RemoteCellHostRoute {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := map[string]RemoteCellHostRoute{}
	for host, route := range r.remoteHosts {
		out[host] = route
	}
	return out
}

func (r *CellResolver) CellAtEndpoint(ctx context.Context, endpoint string, requester *Identity) (CellProtocol, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	switch parsed.Scheme {
	case "ws", "wss":
		return r.remoteBridge(endpoint, requester), nil
	case "cell":
		if parsed.Host != "" {
			r.mu.RLock()
			route, ok := r.remoteHosts[parsed.Host]
			allows := r.allowsInsecureWebSockets
			r.mu.RUnlock()
			if !ok {
				return nil, fmt.Errorf("no remote host route registered for %s", parsed.Host)
			}
			publisher := "anonymous"
			if requester != nil {
				publisher = requester.UUID
			}
			bridgeURL, err := route.BridgeURL(parsed.Host, strings.Trim(parsed.Path, "/"), publisher, allows)
			if err != nil {
				return nil, err
			}
			return r.remoteBridge(bridgeURL, requester), nil
		}
	case "":
	default:
		return nil, fmt.Errorf("unsupported endpoint scheme: %s", parsed.Scheme)
	}
	name := localName(endpoint)
	r.mu.RLock()
	resolve := r.named[name]
	byUUID := r.byUUID[name]
	r.mu.RUnlock()
	if resolve != nil {
		cell, err := resolve.Resolve(ctx, requester)
		if err != nil {
			return nil, err
		}
		if cell != nil && cell.CellUUID() != "" {
			r.mu.Lock()
			r.byUUID[cell.CellUUID()] = cell
			r.mu.Unlock()
		}
		return cell, nil
	}
	if byUUID != nil {
		return byUUID, nil
	}
	return nil, fmt.Errorf("no cell registered for endpoint: %s", endpoint)
}

func (r *CellResolver) NamedCells(ctx context.Context, requester *Identity) (map[string]CellProtocol, error) {
	r.mu.RLock()
	resolves := make(map[string]*CellResolve, len(r.named))
	for name, resolve := range r.named {
		resolves[name] = resolve
	}
	r.mu.RUnlock()
	out := map[string]CellProtocol{}
	for name, resolve := range resolves {
		cell, err := resolve.Resolve(ctx, requester)
		if err != nil {
			return nil, err
		}
		out[name] = cell
	}
	return out, nil
}

func (r *CellResolver) LoadCell(ctx context.Context, configuration CellConfiguration, into Absorb, requester *Identity) ([]CellProtocol, error) {
	loaded := []CellProtocol{}
	for _, ref := range configuration.CellReferences {
		cell, err := r.loadReference(ctx, ref, into, requester)
		if err != nil {
			return loaded, err
		}
		loaded = append(loaded, cell)
	}
	return loaded, nil
}

func (r *CellResolver) GetFromURL(ctx context.Context, cellURL string, requester *Identity) (any, error) {
	endpoint, keypath, err := splitCellURL(cellURL)
	if err != nil {
		return nil, err
	}
	cell, err := r.CellAtEndpoint(ctx, endpoint, requester)
	if err != nil {
		return nil, err
	}
	return cell.Get(ctx, keypath, requester)
}

func (r *CellResolver) SetIntoURL(ctx context.Context, value any, cellURL string, requester *Identity) (any, error) {
	endpoint, keypath, err := splitCellURL(cellURL)
	if err != nil {
		return nil, err
	}
	cell, err := r.CellAtEndpoint(ctx, endpoint, requester)
	if err != nil {
		return nil, err
	}
	return cell.Set(ctx, keypath, value, requester)
}

func (r *CellResolver) loadReference(ctx context.Context, ref CellReference, into Absorb, requester *Identity) (CellProtocol, error) {
	target, err := r.CellAtEndpoint(ctx, ref.Endpoint, requester)
	if err != nil {
		return nil, err
	}
	label := ref.Label
	if label == "" {
		label = localName(ref.Endpoint)
	}
	if into != nil {
		if _, err := into.Attach(ctx, target, label, requester); err != nil {
			return nil, err
		}
		if ref.SubscribeFeed {
			if err := into.AbsorbFlow(ctx, label, requester); err != nil {
				return nil, err
			}
		}
	}
	for _, kv := range ref.SetKeysAndValues {
		if kv.Value != nil {
			if _, err := target.Set(ctx, kv.Key, kv.Value, requester); err != nil {
				return nil, err
			}
			continue
		}
		value, err := target.Get(ctx, kv.Key, requester)
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(kv.Target, "cell://") {
			if _, err := r.SetIntoURL(ctx, value, kv.Target, requester); err != nil {
				return nil, err
			}
		} else if kv.Target != "" {
			if _, err := target.Set(ctx, kv.Target, value, requester); err != nil {
				return nil, err
			}
		}
	}
	for _, sub := range ref.Subscriptions {
		if _, err := r.loadReference(ctx, sub, target, requester); err != nil {
			return nil, err
		}
	}
	return target, nil
}

func (r *CellResolver) remoteBridge(bridgeURL string, requester *Identity) CellProtocol {
	key := bridgeURL + "|anonymous"
	if requester != nil {
		key = bridgeURL + "|" + requester.UUID
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.remoteCache[key] == nil {
		r.remoteCache[key] = NewCloudBridge(bridgeURL, requester, CloudBridgeOptions{
			AllowInsecureWebSocket: r.allowsInsecureWebSockets,
		})
	}
	return r.remoteCache[key]
}

func splitCellURL(cellURL string) (string, string, error) {
	parsed, err := url.Parse(cellURL)
	if err != nil {
		return "", "", err
	}
	if parsed.Scheme != "cell" {
		return "", "", fmt.Errorf("expected cell URL, got %s", cellURL)
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("cell URL must include cell and keypath: %s", cellURL)
	}
	keypath := parts[len(parts)-1]
	cellPath := strings.Join(parts[:len(parts)-1], "/")
	if parsed.Host != "" {
		return "cell://" + parsed.Host + "/" + cellPath, keypath, nil
	}
	return "cell:///" + cellPath, keypath, nil
}

func localName(endpoint string) string {
	parsed, err := url.Parse(endpoint)
	if err == nil && parsed.Scheme == "cell" {
		if parsed.Host != "" {
			return parsed.Host
		}
		return strings.Split(strings.Trim(parsed.Path, "/"), "/")[0]
	}
	return strings.Split(strings.Trim(endpoint, "/"), "/")[0]
}
