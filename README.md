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
- `CloudBridge` WebSocket client for Swift/Vapor bridgeheads and staging probes
- `CellConfiguration`, `CellReference`, and Skeleton wrapper JSON parsing
- pragmatic built-in cells: Vault, GraphIndex, EntityAnchor, TrustedIssuers proxy,
  and FunctionCell

## Quick Check

```bash
go test ./...
```

## Compatibility Scope

The package is transport-neutral at the protocol level. `CloudBridge` provides a
WebSocket client for the current Swift/Vapor bridgehead contract:

```go
bridge := cellprotocol.NewCloudBridge(
    "wss://staging.example.org/bridgehead/client-uuid/ConfigurationCatalog",
    identity,
    cellprotocol.DefaultCloudBridgeOptions(),
)
value, err := bridge.Get(ctx, "state", identity)
```

`ws://` is rejected by default. Enable `AllowInsecureWebSocket` only for local
development.

Live Swift/Vapor bridgehead smoke test:

```bash
CELLPROTOCOL_STAGING_BRIDGE_URL=wss://staging.haven.digipomps.org/bridgehead/<client-uuid>/ConfigurationCatalog \
  go test ./... -run TestCloudBridgeStagingSmoke -count=1
```

## Cross-language contracts (`interop`)

Package `github.com/Digipomps/GoCellProtocol/interop` holds wire models,
canonical encoding and verifiers for the three flows that must work between
Swift, Python and Go scaffolds: entity extension, invitation and chat, plus the
identity proof a bridge asks for. They reproduce Swift byte for byte and are
tested against the golden fixtures Swift generates (`interop/testdata/v1`,
copied from CellProtocol `fixtures/interop/v1`):

```bash
go test ./interop
```

These are contracts only. The cells that run the flows, and a bridgehead
server for a Go scaffold, are not here yet.

## Upstream Monitoring

The `CellProtocol Upstream Monitor` GitHub Actions workflow checks
`Digipomps/CellProtocol` daily. If the Swift upstream default branch moves past
the recorded SHA in `.github/upstream/cellprotocol.json`, it opens an issue in
this repository with the new commit and update checklist. After the Go port has
been updated, update that baseline file in the same commit.

The Skeleton model is parsed and round-tripped as portable JSON. Go does not ship
a UI renderer in this repository.

### Current security boundary

- Local `GeneralCell.AddAgreement` admission is fail-closed. The Go port does
  not yet implement Swift's owner-proof, template-derived, signed `Contract`
  admission model, so caller-supplied Agreements cannot install grants.
- Protected local `GeneralCell` access requires a fresh signing-key
  proof-of-possession for the stored owner reference. UUID or public-key
  equality alone is not authority, and an ownerless Cell is not implicitly
  public-readable or public-writable.
- Inbound `BridgeEndpoint` access never substitutes a missing requester with the
  owner. A decoded wire identity has no local vault proof and is therefore
  denied protected `get`, `set`, state, flow, and lifecycle access. A portable
  signed request envelope for Swift/Go remote owner or Contract access is not
  implemented yet; those inbound paths intentionally remain fail-closed.
- Identity-scoped Cell instances and cached remote bridges are separated by the
  proof-bearing runtime principal. A UUID collision cannot borrow an existing
  owner-bound instance or bridge.
- Bridge signing accepts only the canonical, short-lived
  `IdentitySigningChallenge` wire shape for the bound identity and rejects
  replay. Arbitrary remote byte signing is not supported.
- Permission objects decode and encode Swift's current `rwxs` storage bit while
  continuing to accept legacy three/six-character permission text.

`CloudBridge` can exercise the current Swift-shaped wire contract, but live
Swift protected-access proof parity, stale-proof rejection, process restart,
and owner-published public read remain **NOT PROVEN** by the local suite or the
opt-in advertise-only staging smoke.

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
