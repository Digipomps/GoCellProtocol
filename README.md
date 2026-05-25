# GoCellProtocol

Go v1 implementation of the HAVEN CellProtocol core contracts.

This port follows the current Swift reference model and the existing Python port
where useful, with emphasis on protocol semantics rather than Swift-shaped class
names:

- domain-scoped identities backed by OS CSPRNG and Ed25519 signing
- `Emit`, `Absorb`, `Meddle`, `Explore`, and optional `GroupProtocol`
- resolver-mediated cell lookup, scopes, remote `cell://host/...` bridge routing
- append-only ordered flows, replay checks, and an in-memory scaffold runtime
- capability grants, agreements, conditions, and explicit access rejection
- Swift/Python-compatible bridge commands and typed payload keys
- `CellConfiguration`, `CellReference`, and Skeleton wrapper JSON parsing
- pragmatic built-in cells: Vault, GraphIndex, EntityAnchor, TrustedIssuers proxy,
  and FunctionCell

## Quick Check

```bash
go test ./...
```

## Compatibility Scope

The package is transport-neutral. WebSocket/QUIC/WebRTC sessions can wrap
`BridgeCommand` and `BridgeEndpoint`, but this repository does not bind the core
protocol to a network stack.

The Skeleton model is parsed and round-tripped as portable JSON. Go does not ship
a UI renderer in this repository.

## Reference Sources Used

Local reference material used while building this port:

- `/Users/kjetil/Build/Digipomps/HAVEN/CellProtocolDocuments/Book/01_CellProtocol_Core.md`
- `/Users/kjetil/Build/Digipomps/HAVEN/CellProtocolDocuments/Book/02_Cell_Interfaces.md`
- `/Users/kjetil/Build/Digipomps/HAVEN/CellProtocolDocuments/Book/03_Identity_Model.md`
- `/Users/kjetil/Build/Digipomps/HAVEN/CellProtocolDocuments/Book/04_Agreements_Contracts.md`
- `/Users/kjetil/Build/Digipomps/HAVEN/CellProtocolDocuments/Book/05_Flows_Lifecycle.md`
- `/Users/kjetil/Build/Digipomps/HAVEN/CellProtocolDocuments/Book/06_CellResolver.md`
- `/Users/kjetil/Build/Digipomps/HAVEN/CellProtocolDocuments/Book/07_Scaffold_Runtime.md`
- `/Users/kjetil/Build/Digipomps/HAVEN/CellProtocolDocuments/Book/12_Skeleton_Spec.md`
- `/Users/kjetil/Build/Digipomps/HAVEN/CellProtocol/Sources/CellBase`
- `/Users/kjetil/Build/Digipomps/HAVEN/PyCellProtocol`
