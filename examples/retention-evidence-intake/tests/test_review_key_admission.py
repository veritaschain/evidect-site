"""Configured reviewer keys must not make signature claims without a secret."""

from copy import deepcopy
from pathlib import Path
import sys
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

EXPERIMENT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXPERIMENT))

from retention_intake import IntakeError
from retention_intake.decision import validate_reviewer_trust, verify_decision_signature
from retention_intake.model import digest, encoded, raw_digest

P = 2**255 - 19
SMALL_ORDER_POINTS = (
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
)


def trust_for(raw):
    return {
        "format": "evidect-retention-review-trust/0.1", "mode": "synthetic-test-only",
        "policy_id": "synthetic-policy", "case_id": "synthetic-case",
        "target_sha256": "ab" * 32, "service": "synthetic-service",
        "environment": "synthetic", "scope": "synthetic-scope",
        "keys": [{"key_id": raw_digest(raw), "reviewer_ref": "synthetic-reviewer",
                  "public_key_hex": raw.hex(), "roles": ["review"],
                  "not_before": "2026-01-01T00:00:00Z", "not_after": "2026-12-01T00:00:00Z",
                  "revoked_at": None}],
    }


class ReviewerKeyAdmissionTests(unittest.TestCase):
    def test_vectors_exhaust_the_eight_small_order_points(self):
        # Independent test-only Edwards decoding/doubling, not verification code.
        d = -121665 * pow(121666, -1, P) % P
        root_minus_one = pow(2, (P - 1) // 4, P)
        points = set()
        for encoded_point in SMALL_ORDER_POINTS:
            value = int.from_bytes(bytes.fromhex(encoded_point), "little")
            y, sign = value & (2**255 - 1), value >> 255
            xx = (y * y - 1) * pow(d * y * y + 1, -1, P) % P
            x = pow(xx, (P + 3) // 8, P)
            if x * x % P != xx:
                x = x * root_minus_one % P
            self.assertEqual(x * x % P, xx)
            if x & 1 != sign:
                x = -x % P
            self.assertEqual(x & 1, sign)
            self.assertNotIn((x, y), points)
            points.add((x, y))
            for _ in range(3):
                product = d * x * x * y * y % P
                x, y = (2 * x * y * pow(1 + product, -1, P) % P,
                        (y * y + x * x) * pow(1 - product, -1, P) % P)
            self.assertEqual((x, y), (0, 1))
        self.assertEqual(len(points), 8)

    def test_all_small_order_configured_keys_are_rejected(self):
        for point in SMALL_ORDER_POINTS:
            policy = trust_for(bytes.fromhex(point))
            original = deepcopy(policy)
            with self.subTest(point=point), self.assertRaisesRegex(IntakeError, "^REVIEW_KEY_SMALL_ORDER$"):
                validate_reviewer_trust(policy, allow_synthetic=True)
            self.assertEqual(policy, original)

    def test_noncanonical_coordinates_and_zero_x_sign_aliases_are_rejected(self):
        values = [(y | (sign << 255)) for y in range(P, 2**255) for sign in (0, 1)]
        values += [y | (1 << 255) for y in (1, P - 1)]
        self.assertEqual(len(values), 40)
        for value in values:
            with self.subTest(value=value), self.assertRaisesRegex(IntakeError, "^REVIEW_KEY_ENCODING_NONCANONICAL$"):
                validate_reviewer_trust(trust_for(value.to_bytes(32, "little")), allow_synthetic=True)

    def test_forged_identity_signature_cannot_be_reported_as_verified(self):
        public = bytes.fromhex(SMALL_ORDER_POINTS[0])
        policy = trust_for(public)
        body = {
            "format": "evidect-retention-review-decision/0.1", "criteria": "evidect-retention-review/0.1",
            "decision_id": "synthetic-decision", "case_id": policy["case_id"],
            "reviewer_ref": "synthetic-reviewer", "key_id": raw_digest(public),
            "dossier_sha256": "ab" * 32, "assignment_sha256": "ab" * 32,
            "target_sha256": policy["target_sha256"], "reviewer_trust_sha256": digest(policy),
            "review_current": {"format": "evidect-retention-current/0.1",
                "checked_at": "2026-10-30T12:20:00Z", "context": {
                    "service": policy["service"], "environment": "synthetic", "scope": policy["scope"],
                    "release": "synthetic-release", "config_digest": "ab" * 32,
                    "policy_revision": "synthetic-policy", "generation": 1}},
            "review_current_report_sha256": "ab" * 32, "action": "CLOSE_REVIEW",
            "expires_at": "2026-11-01T12:00:00Z", "note": "Synthetic forgery regression",
            "items": [], "requirements": [],
        }
        raw = encoded(body)
        signature = {"format": "evidect-retention-review-signature/0.1", "algorithm": "Ed25519",
                     "decision_raw_sha256": raw_digest(raw), "key_id": raw_digest(public),
                     "signature": (public + bytes(32)).hex()}
        with self.assertRaisesRegex(IntakeError, "^REVIEW_KEY_SMALL_ORDER$"):
            verify_decision_signature(raw, signature, policy, allow_synthetic=True)

    def test_fresh_generated_keys_and_empty_trust_keep_existing_behavior(self):
        public = Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        policy = trust_for(public)
        self.assertEqual(validate_reviewer_trust(policy, allow_synthetic=True), policy)
        self.assertIsNone(validate_reviewer_trust(None, allow_synthetic=True))
        policy["keys"] = []
        self.assertEqual(validate_reviewer_trust(policy, allow_synthetic=True), policy)

    def test_unused_small_order_key_also_invalidates_the_selected_policy(self):
        public = Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        policy = trust_for(public)
        policy["keys"].extend(trust_for(bytes.fromhex(SMALL_ORDER_POINTS[0]))["keys"])
        with self.assertRaisesRegex(IntakeError, "^REVIEW_KEY_SMALL_ORDER$"):
            validate_reviewer_trust(policy, allow_synthetic=True)


if __name__ == "__main__":
    unittest.main()
