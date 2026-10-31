# Incident motivation and source limits

**Informative background only. Checked 2026-10-31 JST.**

This ledger records attribution, not liability or technical attribution findings. Its sources motivate
questions; they do not supply incident telemetry, credentials, payloads or findings to the synthetic lab.

## Cursor — vendor statement

[Cursor's notice][cursor], published October 29 and updated October 30 at 11:30 PT, identifies
modified `Anthropic.claude-code` **2.1.312 and 2.1.313 for Windows/macOS** in its marketplace.
Cursor describes host-data transmission, SSH-key insertion and persistence; it says SSH activation
generally lacked required privileges. This is a vendor account, not independent forensics.
The stated availability window is October 29 02:27–13:35 PT
(October 29 18:27–October 30 05:35 JST). The inspected revision supplies no affected-user count.

**Reported earlier estimate:** [Reuters][reuters] (October 30, 08:32 UTC) attributes an upper bound of
5,000 affected users to Cursor. That is not a confirmed remote-login count and is separate from the
later official-notice revision.

## WIRED — reported and disputed

[WIRED][wired] (October 29) reports sources alleging personal Claude Code use, administrative access,
two months of activity, and apparent credential/system-information transmission to an unnamed third party.
Accenture says an independent investigation found the allegations unfounded and that it met its obligations.
DoD declined network-status comment; Anthropic referred to policy. The article identifies CUI on NIPRNet
and reports no indication of classified-system intrusion.

CUI is unclassified information requiring safeguarding or dissemination controls, according to
[NARA][cui]; it is not a synonym for classified information. No independent incident investigation,
affected-system access or adjudication is performed by this repository.

## Experiment design — our questions, not source findings

| Question chosen for this fixture | What the lab measures | What remains outside it |
| --- | --- | --- |
| Does approval still match selected execution context? | Re-read a non-executable synthetic file, a fixed local destination and the current observer ID before the wrapper dispatches | Loaded-code integrity, marketplace integrity, host attestation and general TOCTOU protection |
| Does a recorded denial agree with observed effects? | Read both journals; deliberately inject one same-operation effect from the controller after an actual denial | Attribution to the denied agent, real egress or a real attacker |
| What happens when observation stops? | Actually stop the owned child before or after the harmless write and preserve unknown observations | Independent third-party observation, continuous monitoring and incident containment |

These choices are not claims that the reported incidents lacked every log or approval, that their causes
have been proved, or that this experiment would have prevented them. The journals and keys are synthetic.
Existing VAP experiments already contain bypass/outage controls; see the [scope and overlap note](README.md#既存試験との関係と限界).

## Review history

- **Previous review:** Distinguished the vendor account from WIRED's disputed reporting.
  Reuters text was not available in that review.
- **2026-10-31:** Reopened the updated Cursor notice and WIRED report. Retrieved Reuters' original
  report and added its separately attributed upper bound. Earlier retrieval failure is not treated as
  a permanent source status. The current Cursor notice's two package versions govern this summary.
- Preserve source dates and uncertainty when updating this ledger. None of these records changes
  the scope or assurance of a synthetic test result.

[cursor]: https://cursor.com/blog/claude-code-extension-security-notice
[reuters]: https://www.reuters.com/business/media-telecom/cursor-says-up-5000-users-affected-by-tampered-claude-code-extension-2026-10-30/
[wired]: https://www.wired.com/story/a-defense-contractor-gave-their-personal-ai-agent-access-to-a-secure-pentagon-system/
[cui]: https://www.archives.gov/cui
