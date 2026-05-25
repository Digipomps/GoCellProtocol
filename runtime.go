// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

import (
	"context"
	"fmt"
	"sync"
)

type LifecycleState string

const (
	LifecycleInstantiated LifecycleState = "instantiated"
	LifecycleActive       LifecycleState = "active"
	LifecycleRunning      LifecycleState = "running"
	LifecycleSuspended    LifecycleState = "suspended"
	LifecycleTerminated   LifecycleState = "terminated"
)

type InMemoryStore struct {
	mu     sync.RWMutex
	states map[string]any
	flows  map[string][]FlowElement
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{states: map[string]any{}, flows: map[string][]FlowElement{}}
}

func (s *InMemoryStore) SaveState(cellUUID string, state any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[cellUUID] = NormalizeJSON(state)
}

func (s *InMemoryStore) State(cellUUID string) any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return NormalizeJSON(s.states[cellUUID])
}

func (s *InMemoryStore) AppendFlow(cellUUID string, element FlowElement) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flows[cellUUID] = append(s.flows[cellUUID], element)
}

func (s *InMemoryStore) Flow(cellUUID string) []FlowElement {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]FlowElement, len(s.flows[cellUUID]))
	copy(out, s.flows[cellUUID])
	return out
}

type Scaffold struct {
	Resolver *CellResolver
	Store    *InMemoryStore
	mu       sync.RWMutex
	cells    map[string]CellProtocol
	life     map[string]LifecycleState
}

func NewScaffold() *Scaffold {
	return &Scaffold{
		Resolver: NewCellResolver(),
		Store:    NewInMemoryStore(),
		cells:    map[string]CellProtocol{},
		life:     map[string]LifecycleState{},
	}
}

func (s *Scaffold) RegisterCell(ctx context.Context, name string, cell CellProtocol, opts RegisterOptions) error {
	if err := s.Resolver.RegisterNamedEmitCell(ctx, name, cell, opts); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cells[cell.CellUUID()] = cell
	s.life[cell.CellUUID()] = LifecycleActive
	return nil
}

func (s *Scaffold) InvokeGet(ctx context.Context, endpoint, keypath string, requester *Identity) (any, error) {
	cell, err := s.Resolver.CellAtEndpoint(ctx, endpoint, requester)
	if err != nil {
		return nil, err
	}
	s.setLifecycle(cell.CellUUID(), LifecycleRunning)
	return cell.Get(ctx, keypath, requester)
}

func (s *Scaffold) InvokeSet(ctx context.Context, endpoint, keypath string, value any, requester *Identity) (any, error) {
	cell, err := s.Resolver.CellAtEndpoint(ctx, endpoint, requester)
	if err != nil {
		return nil, err
	}
	s.setLifecycle(cell.CellUUID(), LifecycleRunning)
	result, err := cell.Set(ctx, keypath, value, requester)
	if err != nil {
		s.setLifecycle(cell.CellUUID(), LifecycleSuspended)
		return nil, err
	}
	if state, err := cell.State(ctx, requester); err == nil {
		s.Store.SaveState(cell.CellUUID(), state)
	}
	if historyAware, ok := cell.(interface{ FlowHistory() []FlowElement }); ok {
		for _, element := range historyAware.FlowHistory() {
			s.Store.AppendFlow(cell.CellUUID(), element)
		}
	}
	return result, nil
}

func (s *Scaffold) Lifecycle(cellUUID string) LifecycleState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.life[cellUUID]
}

func (s *Scaffold) Terminate(ctx context.Context, cellUUID string, requester *Identity) error {
	s.mu.RLock()
	cell := s.cells[cellUUID]
	s.mu.RUnlock()
	if cell == nil {
		return fmt.Errorf("unknown cell %s", cellUUID)
	}
	if err := cell.Close(ctx, requester); err != nil {
		return err
	}
	s.setLifecycle(cellUUID, LifecycleTerminated)
	return nil
}

func (s *Scaffold) setLifecycle(cellUUID string, state LifecycleState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.life[cellUUID] = state
}

func ReplayFlow(history []FlowElement) ([]FlowElement, error) {
	out := make([]FlowElement, len(history))
	var previous uint64
	for i, element := range history {
		if element.Sequence == 0 {
			return nil, fmt.Errorf("flow element %d has no sequence", i)
		}
		if previous != 0 && element.Sequence != previous+1 {
			return nil, fmt.Errorf("flow sequence gap: got %d after %d", element.Sequence, previous)
		}
		out[i] = element
		previous = element.Sequence
	}
	return out, nil
}

func FlowDigest(history []FlowElement) (string, error) {
	normalized := make([]any, len(history))
	for i, element := range history {
		normalized[i] = element
	}
	return StableJSONString(normalized)
}
