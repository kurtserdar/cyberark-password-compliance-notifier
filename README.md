# CyberArk Password Compliance Notifier

**English** | [Türkçe](README.tr.md)

A single-file PowerShell script for **CyberArk PAM Self-Hosted** that scans every account through the PVWA REST API, finds the ones whose password is past the change interval defined on their platform (non-compliant), resolves the members of each affected safe to e-mail addresses, and sends **one consolidated mail per recipient**. Administrators receive a run summary with a full list and a CSV report is written on every run.

Built to be dropped into any organisation: change the configuration block (or ship a per-customer `.psd1` file), store credentials once, schedule it with Windows Task Scheduler.

## Features

- **Compliance check per platform** – uses each platform's *Require password change every X days* value; never-changed accounts are evaluated from creation time. Optional early warning (`NotifyDaysBeforeDue`) and CPM-failure reporting.
- **Recipient resolution** – safe members with any of the configured permissions (Retrieve / Use / Update / Manage Safe by default). Users and **nested groups** are resolved to e-mail addresses via plain **LDAP (389/636, no RSAT required)**, the Vault user record, or a fallback `user@domain`.
- **No mail storms** – one mail per person covering all their safes; per-recipient/per-account re-notification throttle (`ReNotifyEveryDays`); hard cap per run (`MaxMailsPerRun`).
- **Staged rollout** – `NotifyAccountOwners = $false` (pilot: admins only, with a *planned recipients* table) and `NotifyOnlySafes` (mail owners of selected safes only).
- **Admin summary** – counts, safes without recipients, warnings, full account table, path of the CSV report. Fatal errors produce a separate failure mail.
- **Robust** – credentials stored DPAPI-encrypted (`-SetCredential`, `-SetSmtpCredential`, `-SetADCredential`), TLS 1.2/1.3, automatic re-login on 401, exponential retry on 429/5xx, `nextLink` pagination, meaningful exit codes for Task Scheduler, log rotation.
- **Portable** – Windows PowerShell 5.1 and PowerShell 7; PAM Self-Hosted 11.x – 14.x (v2 endpoints with legacy fallbacks).

## How it works

```
PVWA logon (CyberArk / LDAP / Windows auth)
   └─ Platforms/Targets ............ change interval per platform
   └─ Accounts (paged) ............. lastModifiedTime + interval < today → non-compliant
        └─ group by safe
             └─ Safes/{safe}/Members  (filtered by permission, exclusions)
                  └─ User  → LDAP mail / Vault record / fallback domain
                  └─ Group → LDAP nested members → mail
   └─ one HTML mail per recipient (throttled, capped)
   └─ CSV report + admin summary mail
```

## Requirements

| Item | Notes |
|---|---|
| Windows Server with PowerShell 5.1+ | PowerShell 7 also works |
| Network | PVWA (443), SMTP, domain controller LDAP (389 or 636 for LDAPS) |
| CyberArk user | Member of the built-in **Auditors** group (read-only; sees every safe). Any other user only sees safes where it has *List* permission. |
| Task account | A domain account; used for integrated LDAP authentication. No RSAT / ActiveDirectory module needed. |
| SMTP | Anonymous relay or authenticated (STARTTLS supported) |

## Quick start

1. Copy `Send-CyberArkComplianceNotification.ps1` to the server (e.g. `C:\PAM\Notify\`).
2. Edit the `$Config` block at the top of the script **or** copy `example.config.psd1`, fill it in and pass it with `-ConfigFile`.
3. Store credentials **as the Windows account that will run the scheduled task** (DPAPI binds the file to user + machine):

   ```powershell
   powershell.exe -ExecutionPolicy Bypass -File .\Send-CyberArkComplianceNotification.ps1 -SetCredential       # PVWA auditor user
   powershell.exe -ExecutionPolicy Bypass -File .\Send-CyberArkComplianceNotification.ps1 -SetSmtpCredential   # only if SmtpAuthenticate = $true
   ```

4. Dry run – no mail is sent, everything goes to the log and the CSV report:

   ```powershell
   powershell.exe -ExecutionPolicy Bypass -File .\Send-CyberArkComplianceNotification.ps1 -DryRun -Verbose
   ```

5. Real run:

   ```powershell
   powershell.exe -ExecutionPolicy Bypass -File .\Send-CyberArkComplianceNotification.ps1 [-ConfigFile .\customer.psd1]
   ```

6. Task Scheduler: *Program* `powershell.exe`, *Arguments* `-ExecutionPolicy Bypass -NonInteractive -File C:\PAM\Notify\Send-CyberArkComplianceNotification.ps1`, run as the account from step 3, *Run whether user is logged on or not*.

## Recommended rollout

| Phase | Setting | Effect |
|---|---|---|
| 1 – Pilot | `NotifyAccountOwners = $false` | Full scan, recipients resolved, **admins only**. Summary contains a *Planned recipients per safe* table showing who *would* be mailed. |
| 2 – Staged | `NotifyAccountOwners = $true`, `NotifyOnlySafes = @('Safe-A','Safe-B')` | Owners of the listed safes are mailed; everything else stays admin-only. |
| 3 – Full | `NotifyOnlySafes = @()` | Everyone. |

The notification state file is not touched while owner mails are suppressed, so the first real mail always carries the complete list.

## Configuration reference

All keys live in the `$Config` block; any of them can be overridden from a `.psd1` file (`-ConfigFile`).

### PVWA
| Key | Default | Description |
|---|---|---|
| `PvwaAddress` | – | `https://pvwa.example.com` (no `/PasswordVault`) |
| `AuthMethod` | `CyberArk` | `CyberArk`, `LDAP` or `Windows` (IIS integrated auth, no credential file) |
| `AuditorUser` | – | Vault/LDAP user name |
| `CredentialFile` | `pvwa.cred.xml` | DPAPI file created with `-SetCredential` |
| `SkipCertificateCheck` | `$false` | Lab only |
| `ApiPageSize` / `ApiTimeoutSec` / `ApiRetryCount` / `ApiCallDelayMs` | 500 / 120 / 3 / 0 | Tuning for large environments |

### Scope
| Key | Description |
|---|---|
| `IncludedSafes` | Non-empty = only these safes |
| `ExcludedSafes`, `ExcludedSafePatterns` | Exact names and regexes; defaults cover CyberArk system safes |
| `ExcludedPlatforms` | Platform IDs to ignore |
| `OnlyCpmManagedAccounts` | Skip accounts with automatic management disabled |
| `IncludeCpmFailures` | Also report accounts whose last CPM operation failed |
| `DefaultChangeDays` | Used when a platform has no change interval (0 = skip such accounts) |
| `NotifyDaysBeforeDue` | Warn N days before the password becomes overdue |

### Recipients / Active Directory
| Key | Default | Description |
|---|---|---|
| `RequiredPermissions` | Retrieve, Use, Update, ManageSafe | A member needs *any* of these to be notified |
| `ExcludedMembers`, `ExcludedMemberPatterns` | CyberArk built-ins | Members never notified |
| `ResolveLdapViaAD` | `$true` | Resolve users/groups against AD |
| `ADProvider` | `LDAP` | `LDAP` (System.DirectoryServices, 389/636) or `ADModule` (RSAT, ADWS 9389) |
| `ADServer` | `''` | DC or domain FQDN. **Set this on hardened servers.** |
| `ADUseSsl`, `ADPort`, `ADSearchBase`, `ADTimeoutSec` | – | LDAPS, Global Catalog (3268), base DN, per-query timeout |
| `ADCredentialFile` | `''` | Only when the task account cannot read AD (`-SetADCredential`) |
| `ADDomainMap` | `@{}` | CyberArk directory name → AD FQDN (multi-domain) |
| `ExpandGroups`, `MaxGroupMembers` | `$true`, 200 | Nested group expansion and safety cap |
| `FallbackMailDomain` | `''` | `user@domain` when no mail attribute is found |

### Mail / rollout
| Key | Default | Description |
|---|---|---|
| `SmtpServer`, `SmtpPort`, `SmtpUseSsl`, `SmtpAuthenticate`, `SmtpCredentialFile` | – | STARTTLS via `SmtpUseSsl` |
| `SenderMail`, `SenderDisplayName`, `MailSubject`, `MailCc` | – | |
| `AdminMail`, `SendAdminSummary` | – | Summary recipients; `$false` = only on problems |
| `NotifyAccountOwners` | `$true` | `$false` = pilot mode |
| `NotifyOnlySafes` | `@()` | Staged rollout |
| `ReNotifyEveryDays` | 1 | Re-notification throttle per recipient + account (0 = always) |
| `MaxMailsPerRun` | 500 | Hard cap (admin mails exempt) |
| `StateFile`, `LogDirectory`, `LogRetentionDays`, `ReportDirectory`, `ReportRetentionDays` | – | Housekeeping |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Configuration / prerequisite error |
| 2 | PVWA authentication error |
| 3 | PVWA API or unexpected fatal error |
| 4 | Mail transport error (nothing could be delivered) |
| 5 | Completed with warnings (some recipients/accounts skipped) |

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `LDAP connectivity FAILED ... An operations error occurred` | Bind is anonymous. Run the task as a domain account; do not set an empty `ADCredentialFile`. Fixed in v3.2 for integrated auth. |
| Script hangs after `Configuration OK` with `ADProvider = 'ADModule'` | `Import-Module ActiveDirectory` hangs on hardened servers (DC discovery / ADWS 9389 / CRL checks). Use `ADProvider = 'LDAP'` (default). |
| `No e-mail address found for user 'x'` | User has no `mail` attribute and no valid UPN; set `FallbackMailDomain` or fix AD. Run with `-Verbose` to see the LDAP filter used. |
| `Safe 'x' has no notifiable members` | Members are excluded (built-ins), lack the required permissions, or could not be resolved. Accounts are listed in the admin summary. |
| `Mailbox unavailable. Unknown user` | SMTP server rejects the recipient address (typical in labs). |
| `Credential file ... not found` | Run `-SetCredential` **as the task account on the same machine**. |
| `Retrieved N accounts` is lower than expected | Auditor user lacks *List* on some safes; add it to the **Auditors** group. |

## Security notes

- The script is **read-only** against CyberArk; it never changes passwords or accounts.
- Passwords are stored with Windows DPAPI, bound to the task account and machine; the files are unreadable elsewhere.
- Keep `SkipCertificateCheck = $false` in production; trust the PVWA certificate chain on the server instead.
- `.gitignore` excludes credential, log, report and state files – never commit them.

## Contributing

Issues and pull requests are welcome. Please do not include customer names, hostnames or e-mail addresses in logs attached to issues.

## License

MIT – see [LICENSE](LICENSE).
