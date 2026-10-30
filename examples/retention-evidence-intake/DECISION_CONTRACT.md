# Signed work-review decision contract

**Version 0.1; experimental, synthetic and non-normative.** This extension
records a key-attributed decision about completing a scoped review. It does not
establish control effectiveness, completed deletion, a person's identity or
actual human review, legal compliance, certification or production observation.

The [existing intake](CONTRACT.md) and [follow-up dossier](FOLLOWUP.md) retain
their original formats and meanings. The historical dossier still says
`case_status: OPEN`. A new wrapper reports a separate `work_state`; it does not
rewrite the dossier or upgrade its evidence state.

## 1. APIs and independent receiver choices

All public APIs require `allow_synthetic=True`:

```python
prepare_decision(snapshots, assignment, review_current, reviewer_trust,
                 decision_id=..., reviewer_ref=..., key_id=...,
                 vap_source=..., allow_synthetic=False)

sign_decision(decision_raw, private_key_pem, allow_synthetic=False)

verify_decision_signature(decision_raw, signature, reviewer_trust,
                          allow_synthetic=False)

evaluate_case(snapshots, assignment, decision_raw, signature,
              reviewer_trust, checkpoint, current,
              vap_source=..., allow_synthetic=False)
```

`snapshots` and `assignment` use the existing follow-up contract. They must be
selected by the receiver; reports, downloaded keys or embedded verifier paths
are not substitutes. Mutable receiver JSON values are copied before checks,
and those checked values are consumed throughout the call. The original VAP
input and trust bytes remain exact-byte selections.

Both `review_current` and `current` use the existing strict
`evidect-retention-current/0.1` shape. The former is the decision's declared
review context and cutoff; the latter is the separately supplied context and
time at which the receiver evaluates present applicability. These are caller
declarations, not external timestamps or continuous deployment observations.

Every preparation and case evaluation recomputes the original follow-up
dossier. The latest original VAP evidence is also evaluated at the separately
supplied current time. A matching historical decision is checked against an
additional recomputation at its own `review_current`.

The two time evaluations remain separate from the original dossier. Advancing
the current clock does not rewrite its historical `checked_at`, change its
digest or create a new provider statement.

## 2. Receiver reviewer trust

The exact reviewer-trust fields are:

```json
{
  "format": "evidect-retention-review-trust/0.1",
  "mode": "synthetic-test-only",
  "policy_id": "receiver-selected-policy",
  "case_id": "receiver-selected-case",
  "target_sha256": "<target digest from the recomputed dossier>",
  "service": "synthetic-service",
  "environment": "synthetic",
  "scope": "receiver-selected-scope",
  "keys": [
    {
      "key_id": "<SHA-256 of raw 32-byte Ed25519 public key>",
      "reviewer_ref": "synthetic-reviewer",
      "public_key_hex": "<64 lowercase hexadecimal characters>",
      "roles": ["review"],
      "not_before": "<explicit timezone-bearing timestamp>",
      "not_after": "<explicit timezone-bearing timestamp>",
      "revoked_at": null
    }
  ]
}
```

The placeholders describe a shape, not usable trust data. The caller protects
this policy and provisions keys separately from candidate evidence. Its
provenance, policy authority and latestness are external assumptions.

At most sixteen distinct keys are accepted. `key_id` is computed over the raw
public key bytes, **not** SPKI DER or PEM text. The configured ID must match the
key. The known RFC 8032 TEST 1 public demo key is rejected. No key in a decision
or signature sidecar becomes trusted automatically.

`roles` may be empty or contain `review` once; no other role is supported. An
empty role list can still supply a key for mathematical signature checking,
but cannot authorize review. The reviewer reference, role, case, target,
service, environment and scope must match for authorization.

Key validity is the interval `not_before <= time < not_after`.
`revoked_at` is explicitly null or a timestamp; at or after a supplied revocation
time, the key cannot authorize the work state. These checks use the selected
policy rather than a live revocation service.

The whole reviewer-trust object is pinned in the signed body using the
receiver's `model.digest()` encoding. A changed policy requires renewed review.
If that digest changes, the verifier cannot reconstruct historical authorization
from the new policy: `authorization_at_review` becomes
`INDETERMINATE / POLICY_CHANGED`. Signature verification and authorization under
the current selected policy remain separate checks.

## 3. Decision body and incomplete drafts

The exact completed-body fields are:

| Field | Meaning |
| --- | --- |
| `format` | `evidect-retention-review-decision/0.1` |
| `criteria` | `evidect-retention-review/0.1` |
| `decision_id`, `case_id` | Nonempty decision and case references |
| `reviewer_ref`, `key_id` | Declared reviewer and selected signing-key ID |
| `dossier_sha256` | Receiver digest of the full recomputed historical follow-up dossier |
| `assignment_sha256` | Receiver digest of its assignment |
| `target_sha256` | Full VAP target digest from that dossier |
| `reviewer_trust_sha256` | Receiver digest of the independently selected reviewer policy |
| `review_current` | Exact receiver current-context object at the declared review cutoff |
| `review_current_report_sha256` | Receiver digest of the latest original evidence re-evaluated at that cutoff |
| `action` | `CLOSE_REVIEW` or `KEEP_OPEN` |
| `expires_at` | Explicit expiry, strictly after `review_current.checked_at` |
| `note` | Nonempty reviewer-declared note |
| `items` | Dispositions for all historical dossier review items |
| `requirements` | Dispositions for all receiver evidence requests |

`prepare_decision()` computes the binding fields, but leaves `action` and
`expires_at` null, the overall note empty, and all dispositions null with empty
notes. This draft cannot be signed until completed. Preparing a draft does not
record an approval or authenticate a person's acceptance.

The draft selects configured key/reference metadata but does not grant review
authority. Its review time cannot predate the latest selected snapshot, and its
generation cannot be lower. The case evaluator still enforces the full
authorization and closure conditions after signing.

Each `items` entry has exactly:

```json
{
  "item_sha256": "<model.digest(full dossier.review_items entry)>",
  "disposition": "REVIEWED",
  "note": "Explicit scoped reasoning supplied by the reviewer",
  "snapshot_ids": ["an-existing-selected-snapshot"]
}
```

`requirements` entries use the same shape with `requirement_sha256` instead of
`item_sha256`. The requirement digest is `model.digest()` of the original
required-evidence string, including its JSON-string encoding.

Each completed disposition is `REVIEWED` or `ACTION_REQUIRED`, with a nonempty
note and one through eight distinct selected snapshot IDs. The evaluator
requires every original item and requirement exactly once; missing, duplicate,
unknown or extra identifiers fail coverage. At most 256 item dispositions and
16 requirement dispositions are accepted. Ordinary text follows the existing
bounded receiver text contract.

`CLOSE_REVIEW` requires every disposition to be `REVIEWED`. `KEEP_OPEN` can
include `ACTION_REQUIRED`. These values are reviewer statements: a snapshot
reference, explanatory note or signature does not independently prove that a
request was satisfied or a risk ceased to exist.

## 4. Detached signature and private-key boundary

The exact signature-sidecar fields are:

```json
{
  "format": "evidect-retention-review-signature/0.1",
  "algorithm": "Ed25519",
  "decision_raw_sha256": "<SHA-256 of the exact decision file bytes>",
  "key_id": "<configured raw-public-key SHA-256>",
  "signature": "<128 lowercase hexadecimal characters>"
}
```

Let `D = SHA256(decision_raw)` as 32 binary bytes. The signed Ed25519 message is:

```python
b"EVIDECT-RETENTION-REVIEW\x00v1\x00" + D
```

This domain and encoding are local to this experiment. They are not an adopted
VAP wire format, the upstream JCS signing format or the observation-receipt
signature domain. Whitespace changes in the decision file invalidate the raw
pin and detached signature relationship.

`sign_decision()` accepts a bounded, unencrypted Ed25519 PKCS#8 PEM byte string.
The key must match the body's key ID; the known public demo key is rejected.
The helper validates completed body shape, action and disposition values, but
does not receive the original dossier and therefore cannot establish coverage,
authority or current applicability. Case evaluation performs those checks.

Private key bytes are never returned in signatures or reports. The operator CLI
additionally enforces private-file ownership, permissions and safe reads. A
local PEM adapter does not provide production enrollment, HSM/KMS protection,
memory zeroization or proof that a human controlled the signing operation.

`verify_decision_signature()` returns `status`, `reason`, the validated `body`
and `key_id`. Its `VALID` means the bytes verify under the separately configured
key. Missing or unknown trust is `INDETERMINATE`; demonstrated raw-pin, key-ID
or signature mismatch is `INVALID`. Neither role authorization nor work closure
is inferred from this mathematical result.

## 5. Receiver-selected latest-decision checkpoint

The checkpoint has exactly:

```json
{
  "format": "evidect-retention-review-checkpoint/0.1",
  "case_id": "receiver-selected-case",
  "decision_raw_sha256": "<exact selected decision bytes SHA-256>",
  "expires_at": "<explicit timezone-bearing timestamp>"
}
```

The receiver chooses this record through a separate, explicit operation. Case
evaluation never adopts a checkpoint from candidate evidence. The case and
exact decision bytes must match. This prevents an older `CLOSE_REVIEW` from
replacing a subsequently selected `KEEP_OPEN` **relative to the protected
checkpoint**.

The checkpoint is unsigned receiver state. Its protection, authority and
latestness are external assumptions. Replacing both it and the evidence can
hide history. No global append-only database, independent checkpoint authority
or complete operational chronology is claimed.

An absent or mismatched checkpoint cannot permit closure. At or after the
expiry of a matching checkpoint, an authenticated prior closure requires
renewed review. No default checkpoint lifetime is invented.

## 6. Closure and renewal rules

The wrapper recomputes the dossier and the latest original evidence at current
time even when no decision is supplied. Both decision and signature must be
present together or absent together. Unusable raw inputs, unsupported formats,
malformed JSON and source/dependency failures are input errors, not findings
about an external provider.

For a matching historical dossier, the evaluator checks exact assignment and
target binding, complete disposition coverage, the declared review-time report,
and reviewer authorization. A current trust policy with the same digest but an
unauthorized reviewer/role/scope or invalid key time cannot substantiate a valid
historical review.

A closure additionally requires usable evidence at review time: local evidence
must be `VALID`, the intake must not be `UNASSESSABLE`, and the receiver binding
and context must be current and matching. Historical invalid inputs can remain
in a dossier that has a usable later input; the old invalid result remains
unchanged and must be covered by a disposition.

If a retention deadline or exception ended after the latest archived snapshot
but by `review_current`, closure fails with
`REVIEW_TIME_BOUNDARIES_REQUIRE_NEW_SNAPSHOT`. Append an explicitly selected
current snapshot and prepare a fresh decision so that the additional findings
enter the dossier. Drafting or recording `KEEP_OPEN` remains possible. Merely
signing a digest of a newer current report does not silently dispose of those
newly crossed boundaries.

For present applicability, the evaluator independently checks:

- The selected checkpoint, current policy, and reviewer authorization now.
- Decision and checkpoint expiry.
- The complete current context and generation against the reviewed context.
- Current usability of the latest original evidence and receiver binding.
- Actual retention/exception boundaries crossed after the review cutoff.

Boundary detection compares individual record IDs and explicit timestamps in
`(review_current.checked_at, current.checked_at]`. Exception entries also retain
their location and reason. It does not rely only on reason-code differences:
a second deadline can require renewed review even when the same general code
was already present at review time.

Changing evidence, assignment or policy makes an authenticated prior closure
stale. A mismatching current dossier does not prove that the older signed
dossier was false; its historical report cannot be reconstructed from different
inputs, so the decision-time report remains null in that evaluation.

The original work due time is separate from all these validity boundaries. A
review after `assignment.review_due_at` can be recorded as late; that deadline
does not reopen completed work by itself. `review_due_state` is calculated only
when the historical dossier matches, preventing a new assignment from changing
the apparent deadline of the old review.

## 7. Report states and limits

The report format is `evidect-retention-case-report/0.1`, using criteria
`evidect-retention-review/0.1`.

| `work_state` | Meaning within the supplied receiver assumptions |
| --- | --- |
| `OPEN` | No decision has been selected, or the authenticated decision keeps review open |
| `CLOSED_REVIEW` | The signed review-completion statement matches the selected dossier/checkpoint and remains applicable now |
| `REOPEN_REQUIRED` | An authenticated prior closure has become stale through changes, expiry, present authorization, unusable current evidence or a newly crossed boundary |
| `UNASSESSABLE` | Signature, trust, checkpoint, temporal order or completed decision consistency cannot substantiate the work state |

Known signature/raw-pin/key mismatch, unknown trust, missing/wrong checkpoint,
impossible future or rollback time, and inconsistent bindings/coverage prevent
closure with `UNASSESSABLE`. Other staleness produces `REOPEN_REQUIRED` for a
prior `CLOSE_REVIEW`. An authenticated `KEEP_OPEN` remains open with stale
conditions visible; it grants no closing authority.

The report preserves `dossier`, `current_intake`, parsed `decision`, optional
`decision_time_intake`, reviewer-policy digest, checkpoint, crossed boundaries
and declared review lateness. Its check names include `signature`, `checkpoint`,
`authorization_at_review`, `authorization_now`, `dossier_binding`,
`policy_binding`, `decision_time`, `current_context`, `current_evidence`,
`current_boundaries`, `disposition_coverage` and `decision_expiry`.
Each has `VALID`, `INVALID` or `INDETERMINATE` status and an explicit reason.
These are individual checks, not company/security ratings.

All output states retain `control_status: UNASSESSABLE`,
`legal_compliance: NOT_ASSESSED`, `production_observed: false`,
`certification: NOT_ASSESSED` and `notification_sent: false`.
No output authorizes an AI upload, performs deletion, sends a message, creates
a scheduled task, establishes external timestamping or provides independent
reproduction. A reviewer's signature attributes the selected statement under
configured trust; it does not prove an actual person's identity or reasoning.

The receiving code, interpreter, installed dependencies, source pins and local
OS remain execution trust assumptions. Record the reviewed source version
alongside results. Current clocks, protected checkpoints and provider-trust
updates require operational arrangements beyond this offline workflow.
