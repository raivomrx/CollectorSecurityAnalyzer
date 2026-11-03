# CSA 5.6.3 BitLocker evidence acceptance

Release HOLD. LAB and HOME acceptance and an independent BL-2 through BL-5
re-audit are pending. The observations below are synthetic expectations.

| Source | Evidence retained | Interpretation |
| --- | --- | --- |
| Shell property | Raw value, observation time, and On/Off indication for 1/2 | Conversion, percentage and method unknown. Other values have unknown protection. |
| Get-BitLockerVolume | OS type, mount, volume status, protection, lock, percentage and method | Conversion state establishes whether encryption finished. Percentage is a separate measurement. |
| Win32_EncryptableVolume | System drive verified against Win32_OperatingSystem, conversion, protection and measured fields | Structured read-only fallback. Wipe and pause states require attention. |
| Provider disagreement | Both observations and source timestamps | SOURCE_CONFLICT with no selected authoritative conclusion. |
| Operator comparison | Locally observed allowlisted fields | External comparison for acceptance. CSA findings derive from the submitted evidence. |

The standard runtime uses structured providers and Shell. The retained
manage-bde parser fixtures cover legacy English and German output.
Historical BitLocker findings should be re-run against fresh evidence.
Older evidence without authoritative provenance cannot establish complete encryption.

## LAB live checklist

1. Record the exact candidate build and verify its SHA-256 and publisher status.
2. Create a fresh assessment and run the standard-user Collector. For Shell-only
   evidence with raw value 1, confirm PROTECTION ON INDICATED, PARTIAL and unknown
   encryption percentage. Check provider and observation timestamp.
3. With local approval, an operator may compare the OS volume using the read-only
   command below. The historical comparison is FullyEncrypted, On and 100%.
4. After independent helper and Lab trust are approved, repeat via the
   authenticated verification path. Expect BIT-001 PASS with authoritative
   provenance. Check Executive Summary, BitLocker detail and baseline results.

## HOME live checklist

1. Verify the exact candidate and start a fresh standard-user assessment.
2. Confirm a Shell-only raw value of 0 gives NOT_EVALUATED, unknown percentage
   and no unencrypted-drive remediation. Review Microsoft baseline evidence.
3. With local approval, compare the OS volume locally. The historical comparison
   is FullyDecrypted, Off and 0%.
4. After approval of the authenticated verification path, expect BIT-001 FAIL
   with fully decrypted wording and one enable-protection action. A fully
   encrypted volume with protection off instead calls for investigating suspension
   and resuming protection.

The operator runs this command interactively in an approved elevated PowerShell
session on the endpoint. Keep its result local and sanitize any review excerpts.

```powershell
Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop |
  Select-Object MountPoint, VolumeType, VolumeStatus, ProtectionStatus,
                EncryptionPercentage, EncryptionMethod, LockStatus
```

## Synthetic expected panels

| Panel | Status | Wording and coverage |
| --- | --- | --- |
| LAB Shell-only | PARTIAL | Protection on indicated. Percentage unknown. |
| LAB authoritative | PASS | Fully encrypted and protection on. 100% measured. |
| HOME Shell-only | NOT_EVALUATED | Protection unknown. Percentage unknown. |
| HOME authoritative | FAIL | Fully decrypted with protection off. 0% measured. |
| Protection suspended/off | FAIL | Encrypted with protection off. Investigate suspension and resume protection. |

## COL-1 dependency

The disabled Verify BitLocker status control explains the trust requirement.
The reserved Lab POST action returns BITLOCKER_VERIFICATION_COL1_REQUIRED
before reading the payload. The draft supplemental schema defines the
allowlisted observation and identity bindings for the future authenticated path.
The current gate rejects all payloads, including valid schema, replayed nonce,
wrong assessment, unknown publisher and unexpected protector fields.

Enablement requires independent publisher and Lab authentication, explicit
operator consent, verification of the actual OS volume, and an expiring
single-use nonce bound to the session, endpoint and original submission.
Consume that nonce atomically with an append-only supplemental record.
The original submission stays immutable. See the [COL-1 design](COL-1-trust-anchor-design.md).

Run the synthetic suite before live acceptance. Provide only sanitized evidence
and an exact source archive to the independent reviewer after operator approval.

References

- [Microsoft Get-BitLockerVolume](https://learn.microsoft.com/en-us/powershell/module/bitlocker/get-bitlockervolume)
- [Microsoft GetConversionStatus](https://learn.microsoft.com/en-us/windows/win32/secprov/getconversionstatus-win32-encryptablevolume)
- [Microsoft GetProtectionStatus](https://learn.microsoft.com/en-us/windows/win32/secprov/getprotectionstatus-win32-encryptablevolume)
