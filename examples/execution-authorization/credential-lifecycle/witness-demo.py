#!/usr/bin/env python3
"""Fixed local credential/checkpoint/witness experiment; public output only."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("credential_witness_demo_fixture", HERE / "witness_fixture.py")
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)

CASE_IDS = (
    "matched-adoption", "older-generation", "receiver-only-rollback", "both-stores-rollback",
    "same-generation-conflict", "witness-behind", "witness-unavailable", "witness-response-replay",
    "signer-revocation-rollback", "selected-input-byte-mismatch", "offline-invalid-witness-unavailable",
    "context-change-rejected",
)


def create_demo():
    inputs, receipt_key, witness_key = f.generate_inputs(), f.keypair(), f.keypair()
    cases, public = [], {}

    def add(case_id, result, expected, **checks):
        expected_overall = "INVALID" if expected == "INVALID" else "INDETERMINATE"
        observed = {"local_status_matches": result["local_status"] == expected,
                    "overall_status_matches": result["overall_status"] == expected_overall, **checks}
        cases.append({"case_id": case_id, "test_result": "PASS" if all(value is True for value in observed.values()) else "FAIL",
                      "local_status": result["local_status"], "overall_status": result["overall_status"],
                      "witness_status": result.get("witness_status"),
                      "reason": result.get("witness_reason", result.get("state_reason", result.get("adoption_error"))),
                      "expectation_results": observed})

    def rejection(call):
        try:
            call()
            return {"local_status": "VALID", "overall_status": "INDETERMINATE", "adoption_error": None}
        except f.receiver.StateError as error:
            status = "INVALID" if error.exit_code == 1 else "INDETERMINATE"
            return {"local_status": status, "overall_status": status, "adoption_error": error.code}

    with tempfile.TemporaryDirectory(prefix="evidect-credential-witness-demo-private-") as temporary:
        base = Path(temporary)

        def fresh(name):
            root = base / name
            root.mkdir(mode=0o700)
            lab = f.Lab(root, inputs, receipt_key, witness_key)
            delivery = lab.delivery()
            lab.adopt_pair(delivery)
            return lab, delivery

        def next_generation(lab):
            # A different exact-byte representation of the same five requests.
            # Advancing this checkpoint does not claim an additional provider action.
            return lab.delivery(2, evidence=inputs["evidence"] + b"\n")

        lab, original = fresh("matched-adoption")
        before = lab.databases()
        matched = lab.verify(original)
        add("matched-adoption", matched, "VALID", verification_does_not_mutate_stores=lab.databases() == before,
            scoped_evidence_reverified=matched["receiver"]["receiver"]["credential"]["result"]["evidence_consistency"] == "VALID")
        public = {"lifecycle-evidence.json": original["evidence"], "lifecycle-trust.json": original["trust"],
                  "lifecycle-expectation.json": original["expectation"], "receipt-package.json": original["package"],
                  "receipt-public.pem": original["public"].encode("ascii"), "checkpoint.json": f.encode(original["pin"]),
                  "witness-trust.json": f.encode(lab.selected_trust()), "witness-verification.json": f.encode(matched)}

        lab, old = fresh("older-generation")
        current = next_generation(lab)
        lab.adopt_pair(current)
        checked = lab.verify(old)
        refused = rejection(lambda: lab.adopt_to(lab.store, old))
        add("older-generation", checked, "INVALID", old_adoption_rejected=refused["adoption_error"] == "GENERATION_ROLLBACK",
            adopted_generation_retained=lab.store.select(lab.stream, f.KIND)["generation"] == 2)

        lab, old = fresh("receiver-only-rollback")
        backup = lab.store.path.read_bytes()
        lab.adopt_pair(next_generation(lab))
        lab.store.path.write_bytes(backup)
        local = lab.local(old)
        checked = lab.verify(old)
        add("receiver-only-rollback", checked, "INVALID", old_local_check_still_passes=local["local_status"] == "VALID",
            witness_detects_receiver_behind=checked["witness_reason"] == "RECEIVER_BEHIND_WITNESS")

        lab, old = fresh("both-stores-rollback")
        prior = lab.verify(old)
        receiver_backup, witness_backup = lab.databases()
        lab.adopt_pair(next_generation(lab))
        lab.store.path.write_bytes(receiver_backup)
        lab.witness_store.path.write_bytes(witness_backup)
        checked = lab.verify(old)
        add("both-stores-rollback", checked, "VALID", limitation_retained=checked["limits"]["both_stores_rollback"] == "NOT_DETECTED",
            fresh_challenge_does_not_restore_history=checked["query_sha256"] != prior["query_sha256"])

        lab, old = fresh("same-generation-conflict")
        conflicting = lab.delivery(evidence=inputs["evidence"] + b"\n")
        refused = rejection(lambda: lab.adopt_to(lab.store, conflicting))
        add("same-generation-conflict", refused, "INVALID", exact_conflict=refused["adoption_error"] == "SAME_GENERATION_CONFLICT",
            existing_checkpoint_retained=lab.store.select(lab.stream, f.KIND)["checkpoint_sha256"] == f.receiver.state.digest(old["pin"]))

        lab, _ = fresh("witness-behind")
        current = next_generation(lab)
        lab.adopt_to(lab.store, current)
        checked = lab.verify(current)
        add("witness-behind", checked, "INDETERMINATE", no_fallback_success=checked["witness_reason"] == "WITNESS_BEHIND_RECEIVER")

        lab, original = fresh("witness-unavailable")
        add("witness-unavailable", lab.verify(original, exchange=f.unavailable), "INDETERMINATE")

        lab, old = fresh("witness-response-replay")
        backup, responses = lab.store.path.read_bytes(), []
        def capture(query):
            response = lab.transport()(query)
            responses.append(response)
            return response
        initial = lab.verify(old, exchange=capture)
        lab.adopt_pair(next_generation(lab))
        lab.store.path.write_bytes(backup)
        checked = lab.verify(old, exchange=lambda _query: responses[0])
        add("witness-response-replay", checked, "INVALID", original_response_was_valid=initial["local_status"] == "VALID",
            new_challenge_rejects_replay=checked["witness_reason"] == "WITNESS_CHALLENGE_MISMATCH")

        lab, original = fresh("signer-revocation-rollback")
        backup = lab.store.path.read_bytes()
        for store in (lab.store, lab.witness_store):
            store.revoke(original["pin"]["key_fingerprint"])
        lab.store.path.write_bytes(backup)
        checked = lab.verify(original)
        add("signer-revocation-rollback", checked, "INVALID",
            revoked_witness_record_retained=checked["witness_reason"] == "WITNESS_SIGNER_REVOKED")

        lab, original = fresh("selected-input-byte-mismatch")
        changed = [lab.verify({**original, field: original[field] + b"\n"}) for field in ("trust", "expectation")]
        add("selected-input-byte-mismatch", changed[0], "INVALID",
            both_selected_inputs_bound=all(item["local_status"] == "INVALID" for item in changed),
            same_json_semantics_do_not_replace_bytes=all(item["receiver"]["receiver"]["credential"]["result"]["evidence_consistency"] == "VALID"
                                                       for item in changed))

        lab, original = fresh("offline-invalid-witness-unavailable")
        corrupt = json.loads(original["evidence"])
        corrupt["attempts"][0]["signed_inputs"]["request"]["signature"] = "0" * 128
        bad = lab.delivery(evidence=f.encode(corrupt))
        checked = lab.verify(bad, exchange=f.unavailable)
        add("offline-invalid-witness-unavailable", checked, "INVALID",
            original_offline_contradiction_retained=checked["receiver"]["receiver"]["credential"]["result"]["evidence_consistency"] == "INVALID")

        lab, _ = fresh("context-change-rejected")
        other_inputs = f.generate_inputs()
        different_context = lab.delivery(2, **other_inputs)
        refused = rejection(lambda: lab.adopt_to(lab.store, different_context))
        add("context-change-rejected", refused, "INVALID", context_lineage_preserved=refused["adoption_error"] == "STREAM_SCOPE_MISMATCH")

    summary = {"format": "evidect-credential-witness-demo/1", "test_result": "PASS" if
               tuple(item["case_id"] for item in cases) == CASE_IDS and all(item["test_result"] == "PASS" for item in cases) else "FAIL",
               "case_count": len(cases), "cases": cases, "signed_request_count": 5, "provider_request_count": 5,
               "count_scope": "PUBLIC_MATCHED_ADOPTION_EVIDENCE_ONLY",
               "overall_status": "INDETERMINATE", "report_signed": False, "production_observed": False,
               "independent_assessment": False, "external_anchor_verified": False, "witness_integrated": True,
               "control_status": "NOT_ASSESSED", "legal_compliance": "NOT_ASSESSED", "both_stores_rollback": "NOT_DETECTED",
               "limits": {"administrative_separation": "NOT_ENFORCED_IN_LOCAL_EXPERIMENT",
                          "provider_observation_authenticity": "NOT_ESTABLISHED", "provider_log_completeness": "NOT_ESTABLISHED",
                          "historical_authorization": "NOT_ASSESSED", "collector_current_freshness": "NOT_ESTABLISHED",
                          "witness_freshness": "RECORDED_CHALLENGE_BOUND_SNAPSHOT_NOT_GLOBAL_LATEST",
                          "trusted_time": "NOT_ESTABLISHED", "live_witness_service_after_demo": "NOT_RUNNING"},
               "notice": "PASS grades fixed local scenarios, including an undetected simultaneous rollback. "
                         "Request counts describe only the public matched-adoption evidence, not all twelve scenarios. "
                         "Generation 2 changes exact evidence bytes, not the five recorded provider actions. "
                         "The public receipt signs selected bytes; it does not authenticate provider observations or independent administration."}
    if summary["test_result"] != "PASS":
        raise RuntimeError("SYNTHETIC_WITNESS_EXPECTATION_FAILED")
    public["demo-summary.json"] = f.encode(summary)
    if any(b"PRIVATE KEY" in raw or b'"privateKey"' in raw for raw in public.values()):
        raise RuntimeError("PRIVATE_MATERIAL_IN_PUBLIC_OUTPUT")
    return summary, public


def write_demo(output_directory):
    summary, files = create_demo()
    directory = Path(output_directory).absolute()
    directory.mkdir(mode=0o700)  # No overwrite, merge, reset or automatic parent creation.
    inventory = {}
    for name, raw in files.items():
        f.write_owned(directory / name, raw)
        inventory[name] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    manifest = {"format": "evidect-credential-witness-demo-manifest/1", "files": inventory,
                "notice": "Unsigned public artifact inventory. Private keys and both temporary databases are not published."}
    f.write_owned(directory / "manifest.json", f.encode(manifest))
    return summary


def main(argv=None):
    try:
        parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
        parser.add_argument("--output", required=True)
        args = parser.parse_args(argv)
        if not args.output:
            raise ValueError("OUTPUT_REQUIRED")
        summary = write_demo(args.output)
        print(json.dumps(summary, sort_keys=True, ensure_ascii=True, allow_nan=False, indent=2))
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        print("Synthetic credential witness demo failed; use one new output directory.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
