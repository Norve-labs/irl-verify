//! Offline verification of IRL proof bundles.
//!
//! This crate is deliberately self-contained: it shares no code with the
//! IRL Engine. The entire verification algorithm is defined by `SPEC.md`
//! and reimplemented here from that document, so it serves both as a
//! working verifier and as a reference implementation of the spec.
//!
//! Verification is pure computation — no network, no database. The only
//! step that requires external tooling is tying each Merkle root to a
//! Bitcoin block, which uses the standard OpenTimestamps client against
//! the receipt embedded in the bundle.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

// ── Bundle format (SPEC.md §2, §7) ───────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofBundle {
    pub bundle_version: u32,
    pub generated_at: DateTime<Utc>,
    pub engine_version: String,
    pub period_from: DateTime<Utc>,
    pub period_to: DateTime<Utc>,
    #[serde(default)]
    pub agent_id: Option<String>,
    pub spec: serde_json::Value,
    pub traces: Vec<BundleTrace>,
    pub anchors: Vec<BundleAnchor>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BundleTrace {
    pub trace_id: String,
    #[serde(default)]
    pub agent_id: Option<String>,
    pub reasoning_hash: String,
    #[serde(default)]
    pub exchange_tx_id: Option<String>,
    #[serde(default)]
    pub final_proof: Option<String>,
    pub verification_status: String,
    pub valid_time: DateTime<Utc>,
    pub txn_time: DateTime<Utc>,
    /// §7.3: seal format. Absent = 1 (whole-snapshot seal, §3.1).
    #[serde(default = "default_snapshot_version")]
    pub snapshot_version: i64,
    /// §7.3: v2 public field view the seal is recomputed from.
    #[serde(default)]
    pub public_view: Option<PublicView>,
    /// §7.2: v2 Merkle audit path from this trace's leaf to its anchor root.
    #[serde(default)]
    pub audit_path: Option<Vec<MerkleStep>>,
}

fn default_snapshot_version() -> i64 {
    1
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BundleAnchor {
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub leaf_count: i64,
    pub merkle_root: String,
    pub leaves: Vec<String>,
    #[serde(default)]
    pub ots_receipt_base64: Option<String>,
    /// §7.1: root construction. Absent = v1 (§3.3).
    #[serde(default)]
    pub merkle_algo: Option<String>,
}

/// §7.2: one sibling on the climb from a leaf to the root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleStep {
    /// Lower-hex 32-byte sibling node.
    pub sibling: String,
    /// True when the sibling is the LEFT child (the current node is on the right).
    pub sibling_is_left: bool,
}

/// §7.3: the public half of a v2 seal. Numbers are re-serialized the way the
/// engine prints them (shortest round-trip, `1.0` for integral floats).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicView {
    pub trace_id: String,
    pub latent_fingerprint: String,
    pub direction: String,
    pub quantity: f64,
    pub notional: f64,
    pub asset: String,
    pub mta_hash: String,
    pub mta_regime_id: u8,
    pub valid_time: i64,
    pub txn_time: i64,
    pub private_commitment: String,
}

/// §7.1 tag for the domain-separated root construction.
pub const MERKLE_ALGO_V2: &str = "rfc6962-sha256-v2";

// ── Hash constructions (SPEC.md §3, §7) ──────────────────────────────────────

/// `final_proof = lower-hex SHA-256(reasoning_hash_ascii || "||" || exchange_tx_id_ascii)`
pub fn compute_final_proof(reasoning_hash: &str, exchange_tx_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(reasoning_hash.as_bytes());
    hasher.update(b"||");
    hasher.update(exchange_tx_id.as_bytes());
    hex::encode(hasher.finalize())
}

/// §3.3 step 1: a leaf is its 32-byte hex decoding, else SHA-256 of its UTF-8 bytes.
fn leaf_bytes(leaf: &str) -> [u8; 32] {
    match hex::decode(leaf) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => Sha256::digest(leaf.as_bytes()).into(),
    }
}

fn sha256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Binary SHA-256 Merkle root over hex-encoded leaves.
///
/// - Leaves are used in the order supplied (txn_time ascending).
/// - A leaf that decodes to exactly 32 bytes is used as raw bytes;
///   otherwise the UTF-8 bytes of the hex string are SHA-256'd first.
/// - Odd node count at any level duplicates the last node (Bitcoin convention).
/// - Empty input yields `[0u8; 32]`.
pub fn compute_merkle_root(leaves: &[String]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let nodes: Vec<[u8; 32]> = leaves.iter().map(|h| leaf_bytes(h)).collect();
    fold_levels(nodes, |l, r| sha256_parts(&[l, r]))
}

/// §7.1 v2 root: leaf = SHA-256(0x00 || leaf), node = SHA-256(0x01 || l || r),
/// odd levels duplicate the last node. Empty input yields `[0u8; 32]`.
pub fn compute_merkle_root_v2(leaves: &[String]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let nodes: Vec<[u8; 32]> = leaves
        .iter()
        .map(|h| sha256_parts(&[&[0x00], &leaf_bytes(h)]))
        .collect();
    fold_levels(nodes, |l, r| sha256_parts(&[&[0x01], l, r]))
}

fn fold_levels(
    mut nodes: Vec<[u8; 32]>,
    parent: impl Fn(&[u8; 32], &[u8; 32]) -> [u8; 32],
) -> [u8; 32] {
    while nodes.len() > 1 {
        if nodes.len() % 2 == 1 {
            let last = *nodes.last().expect("nodes is non-empty");
            nodes.push(last);
        }
        nodes = nodes
            .chunks(2)
            .map(|pair| parent(&pair[0], &pair[1]))
            .collect();
    }
    nodes[0]
}

/// §7.2: fold a v2 audit path from `leaf` and compare with `root_hex`.
/// A malformed sibling or root fails rather than panics.
pub fn verify_audit_path(leaf: &str, path: &[MerkleStep], root_hex: &str) -> bool {
    let mut acc = sha256_parts(&[&[0x00], &leaf_bytes(leaf)]);
    for step in path {
        let sibling = match hex::decode(&step.sibling) {
            Ok(bytes) if bytes.len() == 32 => bytes,
            _ => return false,
        };
        acc = if step.sibling_is_left {
            sha256_parts(&[&[0x01], &sibling, &acc])
        } else {
            sha256_parts(&[&[0x01], &acc, &sibling])
        };
    }
    hex::decode(root_hex)
        .map(|root| root == acc)
        .unwrap_or(false)
}

/// Canonical JSON (§7.3): object keys sorted, no whitespace, scalars as
/// serde_json prints them.
fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by_key(|(k, _)| *k);
            let inner: Vec<String> = entries
                .into_iter()
                .map(|(k, v)| format!("{}:{}", Value::String(k.clone()), canonical_json(v)))
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", inner.join(","))
        }
        scalar => scalar.to_string(),
    }
}

/// §7.3: `reasoning_hash = lower-hex SHA-256(canonical JSON of the public view)`.
pub fn compute_public_view_hash(view: &PublicView) -> String {
    let value = serde_json::json!({
        "trace_id": view.trace_id,
        "latent_fingerprint": view.latent_fingerprint,
        "direction": view.direction,
        "quantity": view.quantity,
        "notional": view.notional,
        "asset": view.asset,
        "mta_hash": view.mta_hash,
        "mta_regime_id": view.mta_regime_id,
        "valid_time": view.valid_time,
        "txn_time": view.txn_time,
        "private_commitment": view.private_commitment,
    });
    hex::encode(Sha256::digest(canonical_json(&value).as_bytes()))
}

// ── Verification (SPEC.md §4, §7.4) ──────────────────────────────────────────

#[derive(Debug, Default, Serialize)]
pub struct VerificationReport {
    pub final_proofs_checked: usize,
    pub final_proof_failures: Vec<String>,
    pub anchors_checked: usize,
    pub anchor_root_failures: Vec<String>,
    pub anchors_with_ots_receipt: usize,
    pub traces_anchored: usize,
    /// Trace falls inside an anchor period but its hash is absent from the
    /// leaf list — evidence of tampering. Hard failure.
    pub inclusion_failures: Vec<String>,
    /// Trace not covered by any anchor in the bundle (e.g. sealed after the
    /// most recent anchor cycle). Warning, not failure.
    pub traces_unanchored: Vec<String>,
    /// §7.4: v2 seals recomputed from their public view.
    pub preimage_checked: usize,
    pub preimage_failures: Vec<String>,
    /// §7.4: v2 audit paths folded to their anchor root.
    pub audit_paths_checked: usize,
    pub audit_path_failures: Vec<String>,
}

impl VerificationReport {
    pub fn passed(&self) -> bool {
        self.final_proof_failures.is_empty()
            && self.anchor_root_failures.is_empty()
            && self.inclusion_failures.is_empty()
            && self.preimage_failures.is_empty()
            && self.audit_path_failures.is_empty()
    }
}

fn anchor_is_v2(anchor: &BundleAnchor) -> bool {
    anchor.merkle_algo.as_deref() == Some(MERKLE_ALGO_V2)
}

/// Run all offline checks against a bundle.
pub fn verify_bundle(bundle: &ProofBundle) -> VerificationReport {
    let mut report = VerificationReport::default();
    check_binding(bundle, &mut report);
    check_preimages(bundle, &mut report);
    let leaf_sets = check_roots(bundle, &mut report);
    check_inclusion(bundle, &leaf_sets, &mut report);
    report
}

/// §4.1 — recompute final_proof for every bound trace.
fn check_binding(bundle: &ProofBundle, report: &mut VerificationReport) {
    for trace in &bundle.traces {
        if let (Some(tx_id), Some(claimed)) = (&trace.exchange_tx_id, &trace.final_proof) {
            report.final_proofs_checked += 1;
            let recomputed = compute_final_proof(&trace.reasoning_hash, tx_id);
            if &recomputed != claimed {
                report.final_proof_failures.push(format!(
                    "trace {}: claimed final_proof {} != recomputed {}",
                    trace.trace_id, claimed, recomputed
                ));
            }
        }
    }
}

/// §7.4 — recompute every v2 seal from its public view.
fn check_preimages(bundle: &ProofBundle, report: &mut VerificationReport) {
    for trace in bundle.traces.iter().filter(|t| t.snapshot_version >= 2) {
        report.preimage_checked += 1;
        match &trace.public_view {
            Some(view) => {
                let recomputed = compute_public_view_hash(view);
                if recomputed != trace.reasoning_hash {
                    report.preimage_failures.push(format!(
                        "trace {}: reasoning_hash {} != recomputed from public view {}",
                        trace.trace_id, trace.reasoning_hash, recomputed
                    ));
                }
            }
            None => report.preimage_failures.push(format!(
                "trace {}: snapshot_version {} but no public_view to recompute from",
                trace.trace_id, trace.snapshot_version
            )),
        }
    }
}

/// §4.2 / §7.1 — recompute every anchor's root with its declared algorithm.
fn check_roots<'a>(
    bundle: &'a ProofBundle,
    report: &mut VerificationReport,
) -> Vec<HashSet<&'a str>> {
    let mut leaf_sets = Vec::with_capacity(bundle.anchors.len());
    for anchor in &bundle.anchors {
        report.anchors_checked += 1;
        if anchor.ots_receipt_base64.is_some() {
            report.anchors_with_ots_receipt += 1;
        }
        let span = format!("anchor {}..{}", anchor.period_start, anchor.period_end);
        if anchor.leaves.len() as i64 != anchor.leaf_count {
            report.anchor_root_failures.push(format!(
                "{span}: leaf_count {} != {} leaves supplied",
                anchor.leaf_count,
                anchor.leaves.len()
            ));
        }
        let recomputed = match anchor.merkle_algo.as_deref() {
            None => Some(compute_merkle_root(&anchor.leaves)),
            Some(MERKLE_ALGO_V2) => Some(compute_merkle_root_v2(&anchor.leaves)),
            Some(other) => {
                report
                    .anchor_root_failures
                    .push(format!("{span}: unsupported merkle_algo {other:?}"));
                None
            }
        };
        if let Some(root) = recomputed.map(hex::encode) {
            if root != anchor.merkle_root {
                report.anchor_root_failures.push(format!(
                    "{span}: claimed root {} != recomputed {root}",
                    anchor.merkle_root
                ));
            }
        }
        leaf_sets.push(anchor.leaves.iter().map(String::as_str).collect());
    }
    leaf_sets
}

/// §4.3 / §7.4 — each trace must be a leaf of the anchor covering its txn_time;
/// a v2 audit path, when supplied, must fold to that anchor's root.
fn check_inclusion(
    bundle: &ProofBundle,
    leaf_sets: &[HashSet<&str>],
    report: &mut VerificationReport,
) {
    for trace in &bundle.traces {
        let covering = bundle
            .anchors
            .iter()
            .position(|a| trace.txn_time > a.period_start && trace.txn_time <= a.period_end);
        let Some(idx) = covering else {
            report.traces_unanchored.push(trace.trace_id.clone());
            continue;
        };
        let anchor = &bundle.anchors[idx];
        if leaf_sets[idx].contains(trace.reasoning_hash.as_str()) {
            report.traces_anchored += 1;
        } else {
            report.inclusion_failures.push(format!(
                "trace {}: txn_time {} falls in anchor {}..{} but reasoning_hash \
                 is absent from its leaf list",
                trace.trace_id, trace.txn_time, anchor.period_start, anchor.period_end
            ));
        }
        if let (Some(path), true) = (&trace.audit_path, anchor_is_v2(anchor)) {
            report.audit_paths_checked += 1;
            if !verify_audit_path(&trace.reasoning_hash, path, &anchor.merkle_root) {
                report.audit_path_failures.push(format!(
                    "trace {}: audit path does not fold to anchor root {}",
                    trace.trace_id, anchor.merkle_root
                ));
            }
        }
    }
}

// ── OpenTimestamps file (SPEC.md §5) ─────────────────────────────────────────

/// Detached `.ots` file header: "\0OpenTimestamps\0\0Proof\0" + 8 magic bytes.
const OTS_MAGIC: &[u8] = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";
const OTS_MAJOR_VERSION: u8 = 0x01;
const OTS_OP_SHA256: u8 = 0x08;

/// §5: wrap an anchor's stored calendar timestamp into a standard detached
/// `.ots` file whose stamped digest is the Merkle root, ready for
/// `ots upgrade` and `ots verify -d <merkle_root>`.
pub fn ots_file(merkle_root_hex: &str, receipt: &[u8]) -> Option<Vec<u8>> {
    let root = hex::decode(merkle_root_hex)
        .ok()
        .filter(|r| r.len() == 32)?;
    let mut out = Vec::with_capacity(OTS_MAGIC.len() + 2 + 32 + receipt.len());
    out.extend_from_slice(OTS_MAGIC);
    out.push(OTS_MAJOR_VERSION);
    out.push(OTS_OP_SHA256);
    out.extend_from_slice(&root);
    out.extend_from_slice(receipt);
    Some(out)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn hash_hex(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }

    fn ts(hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 1, hour, 0, 0).unwrap()
    }

    fn make_trace(hour: u32, tx: Option<&str>) -> BundleTrace {
        let reasoning_hash = hash_hex(format!("snapshot-{hour}").as_bytes());
        let final_proof = tx.map(|t| compute_final_proof(&reasoning_hash, t));
        BundleTrace {
            trace_id: format!("trace-{hour}"),
            agent_id: None,
            reasoning_hash,
            exchange_tx_id: tx.map(String::from),
            final_proof,
            verification_status: if tx.is_some() { "MATCHED" } else { "PENDING" }.into(),
            valid_time: ts(hour) - chrono::Duration::seconds(5),
            txn_time: ts(hour),
            snapshot_version: 1,
            public_view: None,
            audit_path: None,
        }
    }

    fn make_bundle(traces: Vec<BundleTrace>) -> ProofBundle {
        let leaves: Vec<String> = traces.iter().map(|t| t.reasoning_hash.clone()).collect();
        let root = hex::encode(compute_merkle_root(&leaves));
        ProofBundle {
            bundle_version: 1,
            generated_at: Utc::now(),
            engine_version: "test".into(),
            period_from: ts(0),
            period_to: ts(23),
            agent_id: None,
            spec: serde_json::json!({}),
            traces,
            anchors: vec![BundleAnchor {
                period_start: ts(0),
                period_end: ts(23),
                leaf_count: leaves.len() as i64,
                merkle_root: root,
                leaves,
                ots_receipt_base64: None,
                merkle_algo: None,
            }],
        }
    }

    /// Re-root the bundle's only anchor with the v2 construction.
    fn to_v2(bundle: &mut ProofBundle) {
        let anchor = &mut bundle.anchors[0];
        anchor.merkle_root = hex::encode(compute_merkle_root_v2(&anchor.leaves));
        anchor.merkle_algo = Some(MERKLE_ALGO_V2.into());
    }

    /// Audit path for leaf `index`, built independently of `verify_audit_path`.
    fn path_for(leaves: &[String], mut index: usize) -> Vec<MerkleStep> {
        let mut level: Vec<[u8; 32]> = leaves
            .iter()
            .map(|h| sha256_parts(&[&[0x00], &leaf_bytes(h)]))
            .collect();
        let mut path = Vec::new();
        while level.len() > 1 {
            if level.len() % 2 == 1 {
                level.push(*level.last().unwrap());
            }
            path.push(MerkleStep {
                sibling: hex::encode(level[index ^ 1]),
                sibling_is_left: index % 2 == 1,
            });
            level = level
                .chunks(2)
                .map(|p| sha256_parts(&[&[0x01], &p[0], &p[1]]))
                .collect();
            index /= 2;
        }
        path
    }

    #[test]
    fn valid_bundle_passes() {
        let bundle = make_bundle(vec![
            make_trace(1, Some("exch-1")),
            make_trace(2, Some("exch-2")),
            make_trace(3, None),
        ]);
        let report = verify_bundle(&bundle);
        assert!(report.passed(), "{report:?}");
        assert_eq!(report.final_proofs_checked, 2);
        assert_eq!(report.traces_anchored, 3);
    }

    #[test]
    fn tampered_final_proof_fails() {
        let mut bundle = make_bundle(vec![make_trace(1, Some("exch-1"))]);
        bundle.traces[0].final_proof = Some(hash_hex(b"forged"));
        assert!(!verify_bundle(&bundle).passed());
    }

    #[test]
    fn tampered_merkle_root_fails() {
        let mut bundle = make_bundle(vec![make_trace(1, Some("exch-1"))]);
        bundle.anchors[0].merkle_root = hash_hex(b"forged-root");
        assert!(!verify_bundle(&bundle).passed());
    }

    #[test]
    fn deleted_leaf_breaks_inclusion_and_root() {
        let mut bundle = make_bundle(vec![
            make_trace(1, Some("exch-1")),
            make_trace(2, Some("exch-2")),
        ]);
        bundle.anchors[0].leaves.remove(0);
        let report = verify_bundle(&bundle);
        assert!(!report.passed());
        assert_eq!(report.inclusion_failures.len(), 1);
        assert!(!report.anchor_root_failures.is_empty());
    }

    #[test]
    fn single_leaf_root_is_leaf_itself() {
        let leaf = hash_hex(b"only");
        let root = compute_merkle_root(std::slice::from_ref(&leaf));
        assert_eq!(hex::encode(root), leaf);
    }

    #[test]
    fn odd_leaf_count_duplicates_last() {
        let a = hash_hex(b"a");
        let b = hash_hex(b"b");
        let c = hash_hex(b"c");
        let root = compute_merkle_root(&[a.clone(), b.clone(), c.clone()]);

        let pair = |x: &str, y: &str| -> [u8; 32] {
            let mut h = Sha256::new();
            h.update(hex::decode(x).unwrap());
            h.update(hex::decode(y).unwrap());
            h.finalize().into()
        };
        let ab = hex::encode(pair(&a, &b));
        let cc = hex::encode(pair(&c, &c));
        let expected = pair(&ab, &cc);
        assert_eq!(root, expected);
    }

    #[test]
    fn v2_single_leaf_root_is_prefixed_leaf_hash() {
        let leaf = hash_hex(b"only");
        let expected = sha256_parts(&[&[0x00], &hex::decode(&leaf).unwrap()]);
        assert_eq!(
            compute_merkle_root_v2(std::slice::from_ref(&leaf)),
            expected
        );
    }

    #[test]
    fn v2_root_differs_from_v1_for_the_same_leaves() {
        let leaves = vec![hash_hex(b"a"), hash_hex(b"b")];
        assert_ne!(
            compute_merkle_root(&leaves),
            compute_merkle_root_v2(&leaves)
        );
    }

    #[test]
    fn v2_bundle_passes_and_v1_reading_would_not() {
        let mut bundle = make_bundle(vec![make_trace(1, Some("exch-1")), make_trace(2, None)]);
        to_v2(&mut bundle);
        assert!(verify_bundle(&bundle).passed());
        bundle.anchors[0].merkle_algo = None; // a v1-only verifier's view of the same anchor
        assert_eq!(verify_bundle(&bundle).anchor_root_failures.len(), 1);
    }

    #[test]
    fn unknown_merkle_algo_fails_explicitly() {
        let mut bundle = make_bundle(vec![make_trace(1, None)]);
        bundle.anchors[0].merkle_algo = Some("sha3-tree".into());
        let report = verify_bundle(&bundle);
        assert!(report.anchor_root_failures[0].contains("unsupported merkle_algo"));
    }

    #[test]
    fn v2_audit_paths_fold_for_every_leaf_of_an_odd_tree() {
        let mut bundle = make_bundle((1..=5).map(|h| make_trace(h, None)).collect());
        to_v2(&mut bundle);
        let leaves = bundle.anchors[0].leaves.clone();
        for (i, trace) in bundle.traces.iter_mut().enumerate() {
            trace.audit_path = Some(path_for(&leaves, i));
        }
        let report = verify_bundle(&bundle);
        assert!(report.passed(), "{report:?}");
        assert_eq!(report.audit_paths_checked, 5);
    }

    #[test]
    fn v2_flipped_audit_step_fails() {
        let mut bundle = make_bundle(vec![make_trace(1, None), make_trace(2, None)]);
        to_v2(&mut bundle);
        let mut path = path_for(&bundle.anchors[0].leaves, 0);
        path[0].sibling_is_left = !path[0].sibling_is_left;
        bundle.traces[0].audit_path = Some(path);
        assert_eq!(verify_bundle(&bundle).audit_path_failures.len(), 1);
    }

    fn sample_view(trace_id: &str) -> PublicView {
        PublicView {
            trace_id: trace_id.into(),
            latent_fingerprint: hash_hex(b"fingerprint"),
            direction: "long".into(),
            quantity: 1.0,
            notional: 65000.5,
            asset: "BTC-USD".into(),
            mta_hash: hash_hex(b"mta"),
            mta_regime_id: 2,
            valid_time: 1_780_000_000_000,
            txn_time: 1_780_000_000_123,
            private_commitment: hash_hex(b"private"),
        }
    }

    #[test]
    fn v2_seal_is_hash_of_sorted_canonical_public_view() {
        let view = sample_view("trace-1");
        // Keys sorted, no whitespace, integral float printed as 1.0.
        let expected = format!(
            "{{\"asset\":\"BTC-USD\",\"direction\":\"long\",\"latent_fingerprint\":\"{}\",\"mta_hash\":\"{}\",\"mta_regime_id\":2,\"notional\":65000.5,\"private_commitment\":\"{}\",\"quantity\":1.0,\"trace_id\":\"trace-1\",\"txn_time\":1780000000123,\"valid_time\":1780000000000}}",
            view.latent_fingerprint, view.mta_hash, view.private_commitment
        );
        assert_eq!(
            compute_public_view_hash(&view),
            hash_hex(expected.as_bytes())
        );
    }

    #[test]
    fn v2_preimage_checked_and_tamper_detected() {
        let mut trace = make_trace(1, Some("exch-1"));
        let view = sample_view(&trace.trace_id);
        trace.reasoning_hash = compute_public_view_hash(&view);
        trace.final_proof = Some(compute_final_proof(&trace.reasoning_hash, "exch-1"));
        trace.snapshot_version = 2;
        trace.public_view = Some(view);
        let mut bundle = make_bundle(vec![trace]);
        let report = verify_bundle(&bundle);
        assert!(report.passed(), "{report:?}");
        assert_eq!(report.preimage_checked, 1);

        bundle.traces[0].public_view.as_mut().unwrap().quantity = 2.0;
        assert_eq!(verify_bundle(&bundle).preimage_failures.len(), 1);
        bundle.traces[0].public_view = None;
        assert_eq!(verify_bundle(&bundle).preimage_failures.len(), 1);
    }

    #[test]
    fn ots_file_has_header_root_then_receipt() {
        let root = hash_hex(b"root");
        let file = ots_file(&root, &[0xf0, 0x01]).unwrap();
        assert!(file.starts_with(b"\x00OpenTimestamps\x00\x00Proof\x00"));
        assert_eq!(&file[31..33], &[0x01, 0x08]);
        assert_eq!(hex::encode(&file[33..65]), root);
        assert_eq!(&file[65..], &[0xf0, 0x01]);
        assert!(ots_file("not-hex", &[]).is_none());
    }
}
