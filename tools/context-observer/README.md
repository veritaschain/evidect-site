# Read-only context observer (experimental)

EVIDECT's first-party, non-normative **file-change observation** tool. It reads an
explicit allowlist of local files and records their SHA-256/size, relative paths,
and operator-declared service/release/scope/policy/generation. It does not open a
network connection, execute application code, query a database, read environment
variables, or change selected files. It creates only the requested new receipt,
outside the observed directory. No daemon, schedule or background monitoring.

**Not an AILEX production connector, control-effectiveness test, certification,
VAP/VCP wire format, legal conclusion or independent assessment.** No MFA/EDR or
authorization behavior is tested, even if a selected file contains such settings.
The earlier [synthetic state demo](../../examples/control-revalidation/README.md)
remains separate and unchanged. This tool does not sign real observations using
the demo's public test key or feed local files into synthetic PASS decisions.

## Run (Python 3.10+ on supported POSIX systems)

After reviewing this source, run from the repository root. Choose a new receipt
path each time; no existing file is overwritten. No third-party package install
is needed. Example inputs select two **public example files**, not a deployment:

```sh
python3 -I -B tools/context-observer/test_observe.py -v
python3 -I -B tools/context-observer/observe.py \
  --root "$PWD" \
  --manifest tools/context-observer/selection.example.json \
  --output /tmp/evidect-context-001.json
python3 -I -B tools/context-observer/observe.py \
  --root "$PWD" \
  --manifest tools/context-observer/selection.example.json \
  --previous /tmp/evidect-context-001.json \
  --output /tmp/evidect-context-002.json
```

The first run reports `BASELINE_REQUIRED`. An identical second run reports
`NO_CHANGE_IN_OBSERVED_SCOPE`, **not PASS**. Changes to selected bytes, file
selection, release, scope or policy require an increased operator-supplied
`generation` and produce `REVALIDATION_REQUIRED`. A lower generation is rejected.
Restoring earlier bytes with a new generation still changes the context digest;
this tool never reactivates an old assessment. `control_status` is always
`NOT_ASSESSED`. Exit 0 means collection/comparison completed, not that controls
are compliant. Exit 2 means an input/output error and produces no new valid
receipt; `--previous` containing JSON null never becomes an initial observation.

## Observation scope and trust boundary

The receipt is **unsigned**. Its hash is a consistency check, not authentication.
An operator/attacker able to edit the receipt can recalculate it. Both labels and
the generation counter are operator declarations. Monotonic checks apply only
against the supplied previous receipt; replacing both baseline and counter can
hide history. Secure storage, independent checkpoints, signing identities,
external anchoring and actual runtime collectors are separate future work.

Files are read twice with bounded reads and per-file identity/change checks.
This detects the tested concurrent-change cases, but is **not** an atomic
filesystem snapshot, a proof of deployed code, or continuous observation. Changes
outside the allowlist or between invocations can be missed. A read-only snapshot
mount is preferable for real deployment integration. The root's provenance and
filesystem/OS are trusted inputs; the tool is not hardened against a hostile
kernel or privileged administrator.

`limits.production_observed` remains false even when an operator's environment
label says `production`: reading files alone does not establish production
behavior. All receipts say `runtime_controls: NOT_ASSESSED`,
`legal_compliance: NOT_ASSESSED`, `signature: NOT_PROVIDED` and
`external_anchor: NOT_VERIFIED`. A change signal must invalidate or request review
of an *independent* control assessment, not generate a new favorable assessment.

## Input safety and privacy

Use **public or explicitly scrubbed non-secret files only**. No raw file contents,
absolute paths, credentials, actor names or actual machine identifiers are
included by the observer. Relative names, labels, file sizes and hashes still
reveal information. Unsalted hashes of small-value settings can be guessed;
hashing is not anonymization, secret redaction or proof of confidentiality.
Review an output before sharing it. Do not commit private receipts to this public
repository. The tool does not automatically upload receipts anywhere.

Hidden/traversal paths, common secret-like filenames, unsupported extensions,
symlinks in every selected relative component, hardlinked or nonregular files,
invalid UTF-8/duplicate-key JSON, oversized selections and an output under the
observed root are rejected. This filename policy is a guardrail, **not a secret
scanner**. Limits: 32 selected files, 1 MiB each, 16 MiB total; manifest/baseline
128 KiB and JSON depth 64. Files are opened read-only relative to a held root
directory descriptor. The caller chooses the root and must trust its parent
path. Platforms without safe directory-relative/no-follow operations fail rather
than silently weakening these checks. Windows is not supported in this increment.
Local file access may update filesystem access times; read-only refers to no
content/configuration writes, not zero filesystem metadata side effects.

The new receipt is created with exclusive-create and mode 0600. Directory parents
must already exist and be operator-controlled. An ordinary write failure removes
the incomplete file; power loss can still leave an incomplete receipt, which must
be parsed and validated before comparison. Generic I/O errors avoid printing raw
file contents or absolute input paths.

Implementation references: [Python OS descriptor operations](https://docs.python.org/3.13/library/os.html)
and [JSON decoding hooks](https://docs.python.org/3/library/json.html). This tool's
scope and limits are project design decisions, not requirements from those docs.

## AILEX integration gate

The AILEX repository and installed runtime have not been inspected through this
increment. Before enabling a real collector, the owner must identify the exact
repository/release and a non-secret configuration export. The workflow is:

1. Review an allowlist for the *actual* deployment, secret separation, access role,
   source provenance, and whether file settings are actually in effect.
2. Collect using a least-privilege runtime identity with no remediation rights;
   retain private receipts in owner-controlled storage, not public Actions logs.
3. Bind the observed context to independently executed authentication/authorization/
   logging tests, approved criteria and authenticated evidence. Unknown remains
   unknown; no legacy/demo key is used as an operational identity.
4. Review changes and retest. Do not automatically certify from hash equality.

The shipped sample observes repository files only. Its CI uses GitHub-hosted
Ubuntu/macOS and no secrets, deploys nothing, and uploads only public sample
receipts/test logs for 30 days. No recurring schedule is added.
