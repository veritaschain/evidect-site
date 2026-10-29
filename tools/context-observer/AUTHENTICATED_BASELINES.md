# Authenticated observation baselines (experimental)

This **first-party, non-normative** increment adds detached signatures and an
explicit caller-pinned baseline to the existing read-only file observer. It does
not add a VAP/VCP format, live AILEX integration, control test, certification,
legal decision or external timestamp. Existing observer receipts and synthetic
signed histories remain unchanged.

## What changes

An ordinary receipt hash can be recomputed by anyone who edits that receipt.
This wrapper can require a signature made by a separately configured Ed25519
key **and** an exact, non-expired baseline checkpoint chosen by the caller.
A valid signature on an older receipt cannot replace the currently pinned one.
No key found inside evidence becomes trusted automatically. The existing RFC
8032 TEST 1 public demo key is explicitly rejected for this wrapper.

The checkpoint is not a transparency-service receipt. Its protected storage,
authority and latestness are an **operator responsibility**. Replacing both the
checkpoint and the evidence, compromising the signer, or controlling the local
clock/OS is outside this mechanism. This is a local reference check, not proof
of global history, complete capture or current deployed state.

## Requirements and commands

Python 3.10+, Node.js 22+, supported POSIX file-descriptor operations. No new npm
or pip dependencies. `authenticated.py` handles strict bounded JSON and file
validation; `receipt_crypto.mjs` uses Node's built-in Ed25519 implementation.
No shell, network, daemon, scheduled execution or application execution is used.
The trusted Node executable/source tree and parent directories must be controlled
by the operator. Private keys enter the helper over stdin, never command arguments
or environment variables. The helper does not inherit `NODE_OPTIONS`.

Create a receipt with the ordinary observer only after selecting public or
explicitly scrubbed files, as described in [README.md](README.md). Signing accepts
one existing **unencrypted Ed25519 PKCS#8 PEM** private key. It must be a
single-link regular file owned by the running user with no group/other access
(for example, mode 0600). The tool does not create, register or rotate operating
keys, connect to a KMS/HSM, or securely erase process memory. Treat this local PEM
adapter as an experimental integration boundary, not a production key-management
solution. There is no bundled operational private key.

```sh
python3 -I -B tools/context-observer/authenticated.py sign \
  --receipt /private/receipts/001.json \
  --private-key /private/keys/observer.pem \
  --output /private/receipts/001.signature.json
```

This creates a new detached sidecar, exclusively, with mode 0600. It does not
change the receipt. The receipt's internal `signature: NOT_PROVIDED` continues to
refer to the original unsigned format; the signature lives in the sidecar.
Output parents must exist and be trusted. Existing outputs are never overwritten.

A **separately provisioned** SPKI public-key PEM and protected checkpoint are
needed to accept a baseline. After reviewing a receipt, the authorized operator
must pin these exact values in its own state store (schema example below;
placeholders must be replaced, not copied as working values):

```json
{
  "format": "evidect-observation-checkpoint/1",
  "receipt_sha256": "<64 lowercase hexadecimal digits of the complete receipt file>",
  "key_fingerprint": "<SHA-256 of the trusted public key's SPKI DER>",
  "context_digest": "<context_digest of the reviewed receipt>",
  "context": {
    "service": "reviewed-service", "environment": "staging", "release": "reviewed-release",
    "scope": "reviewed-scope", "policy_revision": "reviewed-criteria", "generation": 1
  },
  "expires_at": 1793318400
}
```

`expires_at` is an example Unix timestamp, **not a recommended or legal retention
period**. Choose a future review deadline under your own policy. All context
fields, not only generation, must match the reviewed receipt exactly. No automatic
checkpoint creation or promotion is provided: copying values from untrusted input
would not establish trustworthy enrollment. Provision the public key out of band.

```sh
python3 -I -B tools/context-observer/authenticated.py verify \
  --receipt /private/receipts/001.json \
  --signature /private/receipts/001.signature.json \
  --trusted-public-key /protected/trust/observer-public.pem \
  --checkpoint /protected/state/current-checkpoint.json
```

| Condition | Local authentication | Baseline usable |
| --- | --- | --- |
| Exact bytes, correct configured key, matching current unexpired pin | VALID | true |
| Edited bytes, incorrect signature/key, or a different pinned receipt | INVALID | false |
| No trusted key or no separate checkpoint | INDETERMINATE | false |
| Valid signature but checkpoint expired | INDETERMINATE | false |
| Malformed input, duplicate JSON keys, null checkpoint, unsupported key | Input error | no acceptance |

`overall_status` is still INDETERMINATE for a valid local result, because no
external anchor is verified. `control_status` and `legal_compliance` are always
NOT_ASSESSED; `production_observed` is always false. Signature success establishes
only the relationship to the configured key and bytes, not who owns that key or
whether the observation is true. An authorized signer can sign fabricated,
well-formed receipts; this is **not remote attestation of the collector**.

## Collect with an authenticated previous observation

```sh
python3 -I -B tools/context-observer/authenticated.py collect \
  --root /reviewed/read-only-export \
  --manifest /private/selection.json \
  --previous /private/receipts/001.json \
  --signature /private/receipts/001.signature.json \
  --trusted-public-key /protected/trust/observer-public.pem \
  --checkpoint /protected/state/current-checkpoint.json \
  --output /private/receipts/002.json
```

The baseline is parsed once from the same in-memory bytes used for verification.
If authentication fails, the observer is not invoked and no new receipt is written.
Once accepted, the original observer compares selected files and context, retaining
its generation/rollback and file-safety checks. The new receipt is **unsigned**
until explicitly signed separately. Its original disclosure fields are preserved;
stdout contains a distinct baseline-authentication report, not an in-band upgrade
of the receipt's trust. Nothing is automatically approved or promoted to current.

No change still means NO_CHANGE_IN_OBSERVED_SCOPE, never PASS. A changed context
requires an advanced generation and REVALIDATION_REQUIRED. Actual runtime tests,
criteria evaluation, deployment binding, assessment signing and the connection to
the earlier synthetic evaluation demo remain separate, unimplemented steps.

## Exact signature coverage and exit codes

Let `D = SHA256(raw_receipt_file_bytes)` and `P = ASCII("EVIDECT-CONTEXT-RECEIPT")`.
The Ed25519 message is `P || 0x00 || ASCII("v1") || 0x00 || D` (32 binary digest
bytes, not hex text). The sidecar contains format, algorithm, lowercase digest,
SHA-256 of SPKI DER, and a 64-byte signature encoded as 128 lowercase hex digits.
Whitespace changes in the receipt invalidate the detached signature. Hashes of
selected file contents alone are not the signature message. This encoding is
local to this experiment, not an adopted protocol or RFC 8785 canonicalization.

Verify exit 0: the local baseline gate passed, **not full evidence validity**.
Verify exit 1: a demonstrated signature/hash/checkpoint mismatch. Exit 2: missing
trust/checkpoint, expired checkpoint, malformed input or I/O/crypto error. A valid
indeterminate report is JSON; input errors have generic stderr and no JSON result.
Collect/sign exit 0 only reports successful local operation; they never certify
controls. Invalid baseline collection exits 2 without producing a new receipt.

Limits inherited from the observer apply, plus 8 KiB PEM files, 16 KiB crypto IPC,
128 KiB receipt/sidecar/checkpoint input, a ten-second helper timeout, no key reads
through symlinks/hardlinks, and exclusive output creation. Ordinary error messages
contain no private key, raw file content or absolute path. No memory-zeroization,
crash-safe directory transaction, atomic filesystem snapshot, secret discovery,
revocation service or unobserved-event recovery is claimed.

## Verification of this increment

```sh
python3 -I -B tools/context-observer/test_authenticated.py -v
python3 -I -B tools/context-observer/test_observe.py -v
node --test examples/control-revalidation/demo.test.mjs
```

Tests generate fresh ephemeral keys in temporary memory/directories, destroy their
temporary files, and upload only test logs in CI. No private key or production
receipt is retained in artifacts. The actual file/CLI test signs a collected public
test receipt, verifies it against separate trust/pin, then collects again. Negative
controls cover rewritten and rehashed data, wrong keys, older signed baselines,
expiry, demo-key refusal, missing trust, size limits and no-overwrite behavior.
Both Linux and macOS runs are first-party GitHub-hosted tests, not independent
operators. CI has no recurrence and changes no deployment settings.

Implementation references: [Node.js crypto](https://nodejs.org/docs/latest-v22.x/api/crypto.html)
and [Python OS descriptor operations](https://docs.python.org/3.13/library/os.html).
The trust policy, checkpoint semantics, scope and limits above are project design
choices, not claims made by those API references.
