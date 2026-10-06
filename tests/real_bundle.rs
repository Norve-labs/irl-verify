//! A real production bundle (IRL reference agent 22d35e4a, 2026-10-05
//! 18:00–22:00 UTC, engine 1.3.0): one MATCHED trace and four anchors built
//! with `rfc6962-sha256-v2`. Each anchor root was independently confirmed in
//! Bitcoin blocks 970064–970093 via OpenTimestamps.

use irl_verify::{compute_merkle_root, ots_file, verify_bundle, ProofBundle};

fn bundle() -> ProofBundle {
    serde_json::from_str(include_str!("fixtures/bundle-2026-10-05.json")).expect("fixture parses")
}

#[test]
fn real_v2_bundle_passes() {
    let report = verify_bundle(&bundle());
    assert!(report.passed(), "{report:?}");
    assert_eq!(report.final_proofs_checked, 1);
    assert_eq!(report.anchors_checked, 4);
    assert_eq!(report.traces_anchored, 1);
    assert_eq!(report.anchors_with_ots_receipt, 4);
}

#[test]
fn reading_v2_anchors_as_v1_fails_every_root() {
    // What irl-verify 1.0.0 did with this bundle: four false root failures.
    let b = bundle();
    let failures = b
        .anchors
        .iter()
        .filter(|a| hex::encode(compute_merkle_root(&a.leaves)) != a.merkle_root)
        .count();
    assert_eq!(failures, 4);
}

#[test]
fn tampered_order_id_fails() {
    let mut b = bundle();
    b.traces[0].exchange_tx_id = Some("paper-forged".into());
    assert_eq!(verify_bundle(&b).final_proof_failures.len(), 1);
}

#[test]
fn dumped_receipt_is_a_detached_ots_file_for_the_root() {
    use base64::Engine;
    let b = bundle();
    let anchor = &b.anchors[1];
    let receipt = base64::engine::general_purpose::STANDARD
        .decode(anchor.ots_receipt_base64.as_ref().unwrap())
        .unwrap();
    let file = ots_file(&anchor.merkle_root, &receipt).unwrap();
    assert!(file.starts_with(b"\x00OpenTimestamps\x00\x00Proof\x00"));
    assert_eq!(hex::encode(&file[33..65]), anchor.merkle_root);
}
