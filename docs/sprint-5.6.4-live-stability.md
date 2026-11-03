# CSA 5.6.4 live stability and acceptance

The HOME collection failure reproduced under Windows PowerShell 5.1 after
`Import-Module`. Both a domain-style SID and a UNC host reached a regex callback
whose new closure could not resolve `Get-CSAPrivacyDigest`. The fix performs
match replacement inside the module and retains the assessment-scoped digest.
`COLLECTOR_PRIVACY_TRANSFORM_FAILED` stops before evidence is written or sent.
The EXE ends the attempt at this diagnostic without offering re-collection.

## PowerShell Quick Start

Save `Start-CSACollector.ps1` from the approved assessment Join page. In its
download folder, run this command as the current standard user.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-CSACollector.ps1
```

The process setting expires when PowerShell exits. Group Policy and Windows
application control still apply. If Windows stops execution before the script
starts, use the Windows diagnostic and follow the approved signed EXE or offline
handoff. For production, prefer independently authenticated, signed distribution.
[Microsoft PowerShell execution policies](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-5.1)

Quick Start retries one interrupted download before collection. Trust failures
stop immediately. Verified bytes are held only for the current launch. A later
invocation starts a new session-bound retrieval, so temporary package contents and
credentials can be removed at exit. Successful phases emit elapsed milliseconds
for download, archive verification, extraction with entry verification, collection
and submission. EXE retains its staged package within the running process for
the existing operator-controlled retry path.

## LAB and HOME acceptance

1. Verify the 5.6.4 installer, exact source commit, SHA-256 and signing state.
   Use isolated assessment data for acceptance. Create a fresh assessment for
   each transport under the applicable organization policy.
2. **HOME EXE first.** Run as a standard user. Verify that both `Collection
   completed` and `Evidence accepted by CSA Lab` appear, the server records the
   accepted submission, and temporary data cleanup succeeds. For raw Shell `0`,
   look for OFF with the field-heuristic label in the Executive Summary and
   unknown verified conversion and percentage. Check the report and Lab export
   for prohibited raw identifiers without copying the source identifiers to CI.
3. **LAB EXE.** Repeat the collection and acceptance checks. For raw Shell `1`,
   expect ON as a Shell indication. Inspect `BIT-001`, the fleet totals and the
   Microsoft baseline together. Confirm that a Shell-only endpoint never becomes
   a verified PASS or FAIL.
4. **PowerShell Quick Start.** Repeat on both endpoints where policy permits.
   Confirm a new accepted submission per run and the same evidence and privacy
   semantics as EXE. Record the phase timings and any policy diagnostic.
5. Compare with a trusted operator's read-only Windows measurement using the
   [5.6.3 oracle procedure](sprint-5.6.3-bitlocker.md). The LAB/HOME live evidence
   stays local. The disabled `Verify BitLocker status` action requires COL-1.

| Synthetic observation | Expected finding and presentation |
| --- | --- |
| LAB Shell 1 alone | PARTIAL. ON Shell indication. Verified percentage unknown. |
| HOME Shell 0 with successful read | PARTIAL. OFF field heuristic. Verification advised. |
| HOME historical 0 without read provenance | NOT_EVALUATED. Raw 0 retained. |
| LAB used-space-only conversion complete, On, 100%, XTS-AES 128 | PASS. Verified protection and conversion. |
| HOME fully decrypted, Off, 0% | FAIL. Enable protection using approved policy. |
| Fully encrypted, protection Off | FAIL. Investigate suspension and resume protection. |
| Shell 0 plus verified On, or Shell 1 plus verified Off | SOURCE_CONFLICT / PARTIAL. Both observations retained. |
| Shell suspended, locked or transitioning | PARTIAL attention. Verified conversion unknown. |
| Missing, malformed or failed Shell read | No indication. No confirmed control finding. |

The Shell labels for values 1–6 follow observed Windows behavior. Value 0 is the
CSA field convention and requires an actual successful Int32 read on the OS mount.
The interpretation method travels with the observation. Structured conversion and
protection stay independent of Shell; a conflict keeps the stronger provider's
facts visible while the assessment is inconclusive. [Chromium Windows Shell reference](https://chromium.googlesource.com/chromium/src/+/bf772ea22907d55f33c4c23f5595d7cbb017d4de/components/device_signals/core/common/win/platform_utils_win.cc)

**Release HOLD.** Complete LAB/HOME acceptance, architecture review, separate
[COL-1 approval](COL-1-trust-anchor-design.md) and the outstanding CVE/KEV audit
work before promotion.
