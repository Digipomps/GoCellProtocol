// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

import "context"

type Absorb interface {
	Attach(ctx context.Context, emitter Emit, label string, requester *Identity) (ConnectState, error)
	AbsorbFlow(ctx context.Context, label string, requester *Identity) error
	Detach(ctx context.Context, label string, requester *Identity) error
	DropFlow(ctx context.Context, label string, requester *Identity) error
	DropAllFlows(ctx context.Context, requester *Identity) error
	DetachAll(ctx context.Context, requester *Identity) error
	AttachedStatus(ctx context.Context, label string, requester *Identity) (ConnectionStatus, error)
	AttachedStatuses(ctx context.Context, requester *Identity) ([]ConnectionStatus, error)
}

type Emit interface {
	Flow(ctx context.Context, requester *Identity) (<-chan FlowElement, error)
	Admit(ctx context.Context, connect ConnectContext) (ConnectState, error)
	Close(ctx context.Context, requester *Identity) error
	AddAgreement(ctx context.Context, contract Agreement, identity *Identity) (AgreementState, error)
	Advertise(ctx context.Context, requester *Identity) (AnyCell, error)
	State(ctx context.Context, requester *Identity) (any, error)
	CellUUID() string
	IdentityDomain() string
	GetOwner(ctx context.Context, requester *Identity) (*Identity, error)
	GetEmitterWithUUID(ctx context.Context, uuid string, requester *Identity) (Emit, error)
}

type Meddle interface {
	Get(ctx context.Context, keypath string, requester *Identity) (any, error)
	Set(ctx context.Context, keypath string, value any, requester *Identity) (any, error)
}

type Explore interface {
	Keys(ctx context.Context, requester *Identity) ([]string, error)
	TypeForKey(ctx context.Context, keypath string, requester *Identity) (string, error)
}

type GroupProtocol interface {
	IsMember(ctx context.Context, identity *Identity, requester *Identity) (bool, error)
}

type CellProtocol interface {
	Absorb
	Emit
	Meddle
	Explore
	GroupProtocol
}
