# IRL Proof Bundle Specification — v1

**Status: frozen.** Backward-incompatible changes will increment `bundle_version`.

**Revision 1.1 (2026-10):** adds the optional v2 fields in §7, which IRL
engines emit from 1.3.0 on. They do not change any v1 construction, so
`bundle_version` stays `1`; a bundle without them verifies exactly as before.
A verifier MUST honour `merkle_algo` (§7.1): reading a v2 anchor with the
§3.3 construction yields a false root failure.

This document fully defines the IRL proof bundle format and its verification
algorithm. A correct implementation of §4 against this document — in any
language — is a complete verifier. No access to the IRL Engine codebase or
to any IRL server is required.

## 1. Purpose

An IRL proof bundle is a self-contained evidence file proving that a set of
autonomous-agent trading decisions:

1. existed in exactly their recorded form at sealing time (**existence**),
2. were never altered afterward (**integrity**),
3. were sealed *before* their exchange executions (**temporal order**),
4. are each cryptographically bound to a specific exchange transaction (**binding**), and
5. are committed to the Bitcoin blockchain via OpenTimestamps, so that not
   even the bundle's producer can rewrite history (**independence**).

A bundle does **not** prove the agent's self-reported reasoning snapshot was
honest at sealing time. It proves nothing was changed after.

## 2. Bundle format

A bundle is a single JSON object, UTF-8 encoded.

| Field | Type | Description |
|---|---|---|
| `bundle_version` | int | This spec: `1` |
| `generated_at` | RFC 3339 | Export time |
| `engine_version` | string | Producing engine version |
| `period_from` | RFC 3339 | Start of covered period (exclusive) |
| `period_to` | RFC 3339 | End of covered period (inclusive) |
| `agent_id` | string \| null | Set when filtered to one agent |
| `spec` | object | Human-readable restatement of §3 (informational) |
| `traces` | array | See §2.1 |
| `anchors` | array | See §2.2 |

### 2.1 Trace

| Field | Type | Description |
|---|---|---|
| `trace_id` | string | Unique trace identifier (UUID) |
| `agent_id` | string \| null | Agent identifier |
| `reasoning_hash` | string | Lower-hex SHA-256 seal of the decision snapshot (§3.1) |
| `exchange_tx_id` | string \| null | Exchange transaction id; null while unbound |
| `final_proof` | string \| null | Binding hash (§3.2); null while unbound |
| `verification_status` | string | `PENDING` \| `MATCHED` \| `DIVERGENT` \| `EXPIRED` \| `SHADOW_HALTED` |
| `valid_time` | RFC 3339 | When the market state the agent acted on was valid |
| `txn_time` | RFC 3339 | When the engine sealed the snapshot |
| `snapshot_version` | int, optional | Seal format: absent or `1` = §3.1, `2` = §7.3 |
| `public_view` | object, optional | v2 only: the public field view the seal is recomputed from (§7.3) |
| `audit_path` | array, optional | v2 only: Merkle audit path to the covering anchor's root (§7.2) |

### 2.2 Anchor

| Field | Type | Description |
|---|---|---|
| `period_start` | RFC 3339 | Anchor period start (exclusive) |
| `period_end` | RFC 3339 | Anchor period end (inclusive) |
| `leaf_count` | int | Number of leaves in the period |
| `merkle_root` | string | Lower-hex 32-byte Merkle root (§3.3) |
| `leaves` | array of string | All `reasoning_hash` values in the period, ordered by `txn_time` ascending |
| `ots_receipt_base64` | string \| null | Raw OpenTimestamps receipt, base64 (§5) |
| `merkle_algo` | string, optional | Root construction: absent = §3.3, `"rfc6962-sha256-v2"` = §7.1 |

## 3. Hash constructions

All hashes are SHA-256. All hex is lowercase.

### 3.1 `reasoning_hash`

`reasoning_hash = hex(SHA-256(RFC 8785 canonical JSON of the CognitiveSnapshot))`

The snapshot itself is not included in a bundle (it may contain proprietary
strategy state). The hash alone supports every check in §4. A party holding
the original snapshot can additionally recompute the seal via RFC 8785.

### 3.2 `final_proof`

```
final_proof = hex(SHA-256(ASCII(reasoning_hash) || "||" || ASCII(exchange_tx_id)))
```

The two ASCII strings are concatenated with the two-byte separator `||`
(0x7C 0x7C) between them.

### 3.3 Merkle root

Binary SHA-256 Merkle tree:

1. Each leaf is the 32-byte decoding of a `reasoning_hash` hex string.
   If a leaf string does not decode to exactly 32 bytes, the SHA-256 of its
   UTF-8 bytes is used instead.
2. Leaves are taken in the order supplied (`txn_time` ascending).
3. At each level, if the node count is odd, the last node is duplicated
   (Bitcoin convention).
4. Parent = `SHA-256(left_32_bytes || right_32_bytes)`.
5. An empty leaf list yields a root of 32 zero bytes.

## 4. Verification algorithm

A verifier MUST perform all three checks, plus the §7.4 checks whenever
their fields are present. The bundle **fails** if any check
in §4.1 or §4.2 fails, or if any inclusion check in §4.3 fails.

### 4.1 Binding

For every trace with non-null `exchange_tx_id` and `final_proof`:
recompute §3.2 and compare with the claimed `final_proof`. Any mismatch is
a failure.

### 4.2 Anchor roots

For every anchor: assert `len(leaves) == leaf_count`, recompute §3.3 over
`leaves`, and compare with the claimed `merkle_root`. Any mismatch is a
failure.

### 4.3 Inclusion

For every trace: find the anchor with
`period_start < txn_time <= period_end`.

- If found and `reasoning_hash` ∈ that anchor's `leaves`: anchored. Pass.
- If found and `reasoning_hash` ∉ `leaves`: **failure** (evidence of
  insertion or deletion after anchoring).
- If no covering anchor exists in the bundle: **warning**, not failure
  (the trace may post-date the most recent anchor cycle).

## 5. Bitcoin anchoring

Each `ots_receipt_base64` decodes to a serialized OpenTimestamps
*timestamp* whose input message is the 32-byte `merkle_root` — the bytes a
calendar returns, without the `.ots` file header. To use it with the
standard client (https://opentimestamps.org), wrap it as a detached `.ots`
file:

```
header magic  00 4f 70 65 6e 54 69 6d 65 73 74 61 6d 70 73 00 00 50 72 6f 6f 66 00
              bf 89 e2 e8 84 e8 92 94   ("\0OpenTimestamps\0\0Proof\0" + 8 bytes)
version       01
hash op       08                        (SHA-256)
digest        merkle_root, 32 bytes
timestamp     decoded ots_receipt_base64
```

`irl-verify --dump-ots <dir>` writes exactly this. Then:

```
ots upgrade anchor-0.ots                    # fetch the Bitcoin path from the calendar
ots verify -d <merkle_root> anchor-0.ots    # needs a local Bitcoin node
```

Without a node, `ots info anchor-0.ots` names the attesting block height;
the final commitment it prints must equal that block header's Merkle root
on any block explorer.

A receipt may initially carry only a calendar (pending) attestation;
`ots upgrade` completes it once the calendar's transaction confirms. Receipts
can also be re-obtained by submitting the root to any OTS calendar.

## 6. Threat model summary

| Adversary action | Detected by |
|---|---|
| Edit a sealed field after the fact | §4.1 (binding) and §4.3 (hash absent from leaves) |
| Delete a trace after anchoring | §4.2 (root mismatch when leaf removed) |
| Insert a back-dated trace | §4.2 / §4.3 (anchored root cannot change) + §5 (Bitcoin timestamp) |
| Producer rewrites both traces and anchors | §5 — the Bitcoin-committed root cannot be reproduced for altered data |
| Fabricate snapshot content *before* sealing | **Out of scope** — see §1. Mitigated operationally by pre-registration of model hashes and post-trade divergence detection |

## 7. Revision 1.1 additions (optional fields)

### 7.1 `merkle_algo = "rfc6962-sha256-v2"`

The §3.3 tree uses one hash for leaves and internal nodes, so a set of
internal nodes can pose as the leaves of a smaller tree with the same root
(the CVE-2012-2459 class). v2 separates the two domains:

```
leaf(h)    = SHA-256(0x00 || leaf_bytes(h))      leaf_bytes as in §3.3 step 1
node(l, r) = SHA-256(0x01 || l || r)
```

Leaves are taken in the order supplied; an odd level duplicates its last
node; an empty leaf list yields 32 zero bytes. A single leaf's root is
`leaf(h)`, not `h`. An anchor with any other `merkle_algo` value is a
failure (unsupported construction).

### 7.2 `audit_path`

An array of steps `{ "sibling": <lower-hex 32 bytes>, "sibling_is_left": bool }`
from the trace's leaf to the root. Fold from `acc = leaf(reasoning_hash)`:
`acc = node(sibling, acc)` when `sibling_is_left`, else `node(acc, sibling)`.
The result must equal the covering anchor's `merkle_root`. Paths are only
checked against v2 anchors.

### 7.3 `snapshot_version = 2` and `public_view`

A v2 seal commits to a public field view instead of the whole snapshot:

```
reasoning_hash = hex(SHA-256(canonical JSON of the public view))
```

The view has exactly these fields: `trace_id` (string), `latent_fingerprint`
(string), `direction` (string), `quantity` (float), `notional` (float),
`asset` (string), `mta_hash` (string), `mta_regime_id` (int 0–255),
`valid_time` (int, ms), `txn_time` (int, ms), `private_commitment`
(lower-hex SHA-256 of the canonical private field group, which is not
disclosed). Canonical JSON: keys sorted, no whitespace, strings JSON-escaped,
floats in shortest round-trip form with a `.0` for integral values (`1.0`,
`940.2`), integers as integers. Use exactly these eleven fields; ignore
anything else in `public_view`.

### 7.4 Additional checks

- **Preimage.** For every trace with `snapshot_version >= 2`, recompute
  §7.3 and compare with `reasoning_hash`. A mismatch, or a missing
  `public_view`, is a failure.
- **Audit path.** For every trace that carries an `audit_path` and falls in
  a v2 anchor (per §4.3), fold §7.2. A mismatch is a failure.
