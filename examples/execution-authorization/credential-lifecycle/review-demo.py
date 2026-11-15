#!/usr/bin/env python3
"""Export ten current synthetic receiver results as unsigned review artifacts."""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


f = load("credential_review_demo_fixture", HERE / "witness_fixture.py")
review = load("credential_review_demo_writer", HERE / "review.py")
CASE_IDS = ("matched-witness", "receiver-rollback", "witness-unavailable", "local-only", "missing-state-error",
            "inventory-difference", "receipt-signature-mismatch", "expired-checkpoint", "uninspected-inventory",
            "unattributed-provider-record")
FILES = {"verification.json", "review.json", "review.html", "review.md", "manifest.json"}


def write_demo(output_directory):
    output = Path(output_directory).absolute()
    output.mkdir(mode=0o700)  # An existing output, including a symlink, is never reused.
    inputs, receipt_key, witness_key = f.generate_inputs(), f.keypair(), f.keypair()
    cases = []

    def record(case_id, mode, result, expected, *, already_written=False, cli_exit=None,
               description="Current synthetic verification result.", diagnostic_checks=None):
        destination = output / case_id
        if not already_written:
            review.write_review(destination, result, mode)
        projection = json.loads((destination / "review.json").read_bytes())
        expected_overall = "INVALID" if expected == "INVALID" else "INDETERMINATE"
        checks = {"expected_local_status": result["local_status"] == expected,
                  "expected_overall_status": result["overall_status"] == expected_overall,
                  "outer_status_retained": projection["local_status"] == result["local_status"] and
                                           projection["overall_status"] == result["overall_status"],
                  "same_run_retained": json.loads((destination / "verification.json").read_bytes()) == result,
                  "fixed_public_files_only": {path.name for path in destination.iterdir()} == FILES}
        if cli_exit is not None:
            checks["verification_exit_preserved"] = cli_exit == {"VALID": 0, "INVALID": 1, "INDETERMINATE": 2}[expected]
        if diagnostic_checks is not None:
            checks.update(diagnostic_checks(result, projection))
        cases.append({"case_id": case_id, "directory": case_id, "mode": mode, "source_format": result["format"],
                      "test_result": "PASS" if all(value is True for value in checks.values()) else "FAIL",
                      "local_status": result["local_status"], "overall_status": result["overall_status"],
                      "description": description, "expectation_results": checks})

    with tempfile.TemporaryDirectory(prefix="evidect-review-demo-private-") as temporary:
        private_root = Path(temporary)

        def unadopted(case_id, **selection):
            root = private_root / case_id
            root.mkdir(mode=0o700)
            lab = f.Lab(root, inputs, receipt_key, witness_key)
            return lab, lab.delivery(**selection)

        def fresh(case_id):
            lab, delivery = unadopted(case_id)
            lab.adopt_pair(delivery)
            return lab, delivery

        def missing_state(case_id, lab, original, expected, **details):
            paths = {}
            for name, raw in [("package", original["package"]), ("evidence", original["evidence"]),
                              ("credential-trust", original["trust"]), ("expectation", original["expectation"])]:
                path = lab.root / (name + ".input")
                f.write_owned(path, raw)
                paths[name] = path
            missing = lab.root / "state-not-created"
            command = [sys.executable, "-I", "-B", str(HERE / "receive.py"), "verify-local",
                       "--state-dir", str(missing), "--stream", lab.stream,
                       "--output", str(output / case_id)]
            for name, path in paths.items():
                command.extend(["--" + name, str(path)])
            completed = subprocess.run(command, capture_output=True, timeout=40)
            if not completed.stdout or completed.stderr or missing.exists():
                raise RuntimeError("SYNTHETIC_ERROR_EXPORT_FAILED")
            result = json.loads(completed.stdout)
            if result["format"] != "evidect-credential-receiver-error/1":
                raise RuntimeError("SYNTHETIC_ERROR_RESULT_REQUIRED")
            record(case_id, "verify-local", result, expected, already_written=True,
                   cli_exit=completed.returncode, **details)

        lab, original = fresh("matched-witness")
        record("matched-witness", "verify-witness", lab.verify(original), "VALID")

        lab, original = fresh("receiver-rollback")
        backup = lab.store.path.read_bytes()
        newer = lab.delivery(2, evidence=original["evidence"] + b"\n")
        lab.adopt_pair(newer)
        lab.store.path.write_bytes(backup)
        record("receiver-rollback", "verify-witness", lab.verify(original), "INVALID")

        lab, original = fresh("witness-unavailable")
        record("witness-unavailable", "verify-witness", lab.verify(original, exchange=f.unavailable), "INDETERMINATE")

        lab, original = fresh("local-only")
        record("local-only", "verify-local", lab.local(original), "VALID")

        lab, original = fresh("missing-state-error")
        missing_state("missing-state-error", lab, original, "INDETERMINATE",
                      description="The CLI is given an uncreated state directory; available original inputs are still rechecked.")

        expectation = json.loads(inputs["expectation"])
        replaced = expectation["requestDigests"][0]
        replacement = next(char * 64 for char in "0123456789abcdef" if char * 64 not in expectation["requestDigests"])
        expectation["requestDigests"][0] = replacement
        lab, original = unadopted("inventory-difference", expectation=f.encode(expectation))
        missing_state("inventory-difference", lab, original, "INVALID",
            description="One receiver-selected expected digest is replaced while both inventory counts remain five. "
                        "This inconsistent candidate is not adopted; the CLI also reports missing receiver state.",
            diagnostic_checks=lambda source, projected: {
                "inventory_compared": projected["inventory"]["assessment"] == "COMPARED",
                "equal_counts_are_not_success": projected["inventory"]["expected_count"] == 5 and
                                                projected["inventory"]["supplied_unique_count"] == 5 and
                                                projected["inventory"]["status"] == "INVALID",
                "missing_digest_retained": projected["inventory"]["missing_request_digests"] == [replacement],
                "unexpected_digest_retained": projected["inventory"]["unexpected_request_digests"] == [replaced]})

        lab, original = fresh("receipt-signature-mismatch")
        altered = json.loads(original["package"])
        altered["signature"]["signature"] = "0" * 128
        result = lab.local({**original, "package": f.encode(altered)})
        record("receipt-signature-mismatch", "verify-local", result, "INVALID",
            description="The detached receipt signature is corrupted after adoption; the original credential inputs remain unchanged.",
            diagnostic_checks=lambda source, projected: {
                "signature_mismatch_retained": any(check["name"] == "signature" and check["status"] == "INVALID" and
                    check["reason"] == "SIGNATURE_OR_KEY_MISMATCH" for check in projected["receipt_checks"])})

        lab, original = fresh("expired-checkpoint")
        result = lab.local(original, now=original["pin"]["expires_at"])
        record("expired-checkpoint", "verify-local", result, "INDETERMINATE",
            description="Verification uses an explicit synthetic evaluation time at checkpoint expiry. "
                        "The signature still matches; freshness is unresolved.",
            diagnostic_checks=lambda source, projected: {
                "signature_match_is_not_expiry_success": any(check["name"] == "signature" and check["status"] == "VALID"
                    for check in projected["receipt_checks"]),
                "checkpoint_expiry_retained": any(check["name"] == "checkpoint_expiry" and check["status"] == "INDETERMINATE"
                    and check["reason"] == "CHECKPOINT_EXPIRED" for check in projected["receipt_checks"])})

        lab, original = unadopted("uninspected-inventory", evidence=b"{}")
        missing_state("uninspected-inventory", lab, original, "INVALID",
            description="The evidence document is malformed, so inventory was never computed. "
                        "The candidate is not adopted and the CLI also reports missing receiver state.",
            diagnostic_checks=lambda source, projected: {
                "inventory_not_checked": projected["inventory"]["assessment"] == "NOT_CHECKED",
                "uncalculated_counts_and_lists_are_null": all(projected["inventory"][key] is None for key in
                    ("expected_count", "supplied_unique_count", "missing_request_digests", "unexpected_request_digests")),
                "original_initial_counts_retained_only_in_source": source["receiver"]["credential"]["result"]["inventory"]["expected_count"] == 0 and
                    source["receiver"]["credential"]["result"]["inventory"]["supplied_unique_count"] == 0})

        evidence = json.loads(inputs["evidence"])
        records = evidence["provider_observation"]["records"]
        records.append({**records[0], "attempt": records[-1]["attempt"] + 1,
                        "providerRequestId": "synthetic-unattributed-request", "dispatchId": None, "requestDigest": None})
        lab, original = unadopted("unattributed-provider-record", evidence=f.encode(evidence))
        missing_state("unattributed-provider-record", lab, original, "INDETERMINATE",
            description="One synthetic unsigned provider record without a request association is added. "
                        "All five retained attempts match, but global correlation remains unresolved; this candidate is not adopted and state is missing.",
            diagnostic_checks=lambda source, projected: {
                "individual_attempts_match": len(projected["attempts"]) == 5 and
                    all(attempt["status"] == "VALID" for attempt in projected["attempts"]),
                "global_correlation_not_promoted": projected["provider_correlation"]["status"] == "INDETERMINATE" and
                    projected["provider_correlation"]["reason"] == "UNATTRIBUTED_PROVIDER_RECORDS",
                "unattributed_provider_id_retained": projected["provider_correlation"]["unattributed_provider_request_ids"] ==
                    ["synthetic-unattributed-request"]})

    matched = tuple(item["case_id"] for item in cases) == CASE_IDS and all(item["test_result"] == "PASS" for item in cases)
    summary = {"format": "evidect-credential-review-demo/1", "test_result": "PASS" if matched else "FAIL",
               "case_count": len(cases), "cases": cases, "overall_status": "INDETERMINATE",
               "report_signed": False, "production_observed": False, "independent_assessment": False,
               "external_anchor_verified": False, "control_status": "NOT_ASSESSED", "legal_compliance": "NOT_ASSESSED",
               "limits": {"report_authenticity": "UNSIGNED_DERIVED_VIEW_NOT_EVIDENCE",
                          "saved_witness_freshness": "HISTORICAL_EXCHANGE_ONLY_NOT_CURRENT_FRESHNESS",
                          "both_stores_rollback": "NOT_DETECTED", "provider_log_completeness": "NOT_ESTABLISHED"},
               "notice": "PASS means the ten expected display/export cases matched, including INVALID and INDETERMINATE results. "
                         "Inner signature or receipt matches do not replace the outer receiver result. "
                         "Saved review files are unsigned and do not establish current witness health or independent operation."}
    if not matched:
        raise RuntimeError("SYNTHETIC_REVIEW_EXPECTATION_FAILED")
    f.write_owned(output / "demo-summary.json", f.encode(summary))
    return summary


def main(argv=None):
    try:
        values = sys.argv[1:] if argv is None else argv
        flags = [value.split("=", 1)[0] for value in values if value.startswith("--")]
        if len(flags) != len(set(flags)):
            raise ValueError("REPEATED_ARGUMENT")
        parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
        parser.add_argument("--output", required=True)
        args = parser.parse_args(values)
        if not args.output:
            raise ValueError("OUTPUT_REQUIRED")
        result = write_demo(args.output)
        print(json.dumps(result, sort_keys=True, ensure_ascii=True, allow_nan=False, indent=2))
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        print("Synthetic credential review export failed; use one new output directory.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
