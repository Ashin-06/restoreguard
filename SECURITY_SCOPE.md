# Security scope and local operation

RestoreGuard is an implemented defensive reference lab. It creates and restores its own fictional SQLite stores. It does not scan your accounts, restore production databases, or call identity/cloud services.

## Current boundary

- Component stores and snapshots are created in fresh temporary fixture directories.
- The current policy journal and effect log are outside the component restore selection.
- Users, documents, sessions, and key fingerprints are synthetic.
- The experiment core performs no external network operations.
- The browser interface is a local development interface, not a deployed service.
- Generated reports and fixture exports are written only to the selected output location.

The local interface should remain bound to loopback. Do not expose it as a shared or internet-facing service; authentication, multi-user isolation, and production hosting are outside its scope.

## Data handling

No real credential is needed or accepted by the core's supported experiment inputs. The synthetic hashes in the fixture are demonstration values and are not a secure secret-management design.

Reports can still contain local paths and experiment details. Inspect them before sharing. Do not replace fixture contents with production snapshots, customer records, passwords, unseal keys, or live sessions.

## Temporary files and exports

Each experiment creates its own temporary fixture and removes it after use. Saved evidence is intentionally retained in the output directory. Preserve any reports you want before manually cleaning up their specific run folders.

An exported reference fixture is synthetic supporting material. It must not be represented as a complete capture of every transient matrix trial. Hashes reveal changes relative to a manifest, but do not establish truthful collection or protect against an operator rewriting both files and manifest.

## Trust assumptions

The oracle trusts the fixture's independent expected-policy table and effect observer. Protected enforcement uses separate current revocation/key records. They are logically separate roles in a local process and database arrangement, not independently administered or tamper-resistant infrastructure.

Losing current policy produces an inconclusive experiment. A restored system cannot prove that its old policy is still current merely by agreeing with its own snapshot.

## What the experiment deliberately does not prove

Sessions are opaque references under a fixed fixture clock. Key values are synthetic fingerprints. No JWT, encryption, production token expiry, network partition, distributed consistency, or external authorization server is evaluated.

SQLite fixture stores use memory journals and disabled durability syncing. This choice makes temporary tests faster and excludes crash-durability claims.

## Future adapter boundary

Real restored services may contact old credential consumers, webhooks, or scheduled tasks immediately after startup. That risk is relevant to future integrations, which require explicit isolation before restoring them. No such adapter is implemented in this prototype. See [INTEGRATION_ROADMAP.md](INTEGRATION_ROADMAP.md).

## Claims and use

A result supports only its tested fixture, mode, checkpoint selection, probes, and limitations. The tool does not certify a backup, guarantee universal recovery safety, establish legal compliance, or authorize a production recovery.
