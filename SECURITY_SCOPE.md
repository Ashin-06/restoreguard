# Security scope and local operation

RestoreGuard creates and restores its own fictional SQLite stores and, optionally, its own disposable OpenBao service. It does not scan accounts, attach to existing services, restore production databases or call cloud services.

## Current boundary

- Component stores and snapshots are created in fresh temporary fixture directories.
- The current policy journal and effect log are outside the component restore selection.
- Users, documents, sessions, and key fingerprints are synthetic.
- The SQLite core performs no network operations. Native requests use only the owned loopback OpenBao service.
- The browser interface is a local development interface, not a deployed service.
- Generated reports and fixture exports are written only to the selected output location.

The local interface should remain bound to loopback. Do not expose it as a shared or internet-facing service; authentication, multi-user isolation, and production hosting are outside its scope.

## Data handling

No production credential is needed or accepted. SQLite hashes are demonstration values. The native adapter creates real short-lived tokens for its disposable synthetic fixture; root credentials and the unseal share are held transiently and omitted from text evidence.

Reports can still contain local paths and experiment details. Inspect them before sharing. Do not replace fixture contents with production snapshots, customer records, passwords, unseal keys, or live sessions.

## Temporary files and exports

Each experiment creates its own temporary fixture and removes it after use. Saved evidence is intentionally retained in the output directory. Preserve any reports you want before manually cleaning up their specific run folders.

An exported reference fixture is synthetic supporting material. It must not be represented as a complete capture of every transient matrix trial. Hashes reveal changes relative to a manifest, but do not establish truthful collection or protect against an operator rewriting both files and manifest.

## Trust assumptions

The oracle trusts the fixture's independent expected-policy table and effect observer. Protected enforcement uses separate current revocation/key records. They are logically separate roles in a local process and database arrangement, not independently administered or tamper-resistant infrastructure.

Losing current policy produces an inconclusive experiment. A restored system cannot prove that its old policy is still current merely by agreeing with its own snapshot.

## What the experiment deliberately does not prove

In SQLite, sessions are opaque under a fixed clock and keys are synthetic fingerprints. The native adapter evaluates actual OpenBao service-token authorization across Raft restores. It does not test JWTs, encryption correctness, expiry, partitions, distributed consistency or production systems.

SQLite fixture stores use memory journals and disabled durability syncing. This choice makes temporary tests faster and excludes crash-durability claims.

## Future adapter boundary

Real restored services may contact old consumers or scheduled tasks. The delivered adapter creates a new service containing only synthetic KV state and tokens, uses loopback listeners, rejects foreign snapshots/endpoints and stops only its own process. It is not an OS sandbox or firewall. Extensions with consumers need additional isolation; see [INTEGRATION_ROADMAP.md](INTEGRATION_ROADMAP.md).

Native `*.snap` evidence contains encrypted synthetic authentication state and should stay private. Credentials and unseal material are not exported; snapshots and local runs are ignored by Git. Share the sanitized result rather than raw snapshots. Clearing Python references is not secure memory erasure. The binary runs as the current OS user, so verify its official checksum before use. See [OPENBAO_INTEGRATION.md](OPENBAO_INTEGRATION.md).

## Claims and use

A result supports only its tested fixture, mode, checkpoint selection, probes, and limitations. The tool does not certify a backup, guarantee universal recovery safety, establish legal compliance, or authorize a production recovery.
