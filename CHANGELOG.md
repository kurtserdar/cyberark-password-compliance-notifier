# Changelog

## 3.2 - 2026-09-30
- Fixed integrated-authentication LDAP bind (path-only `DirectoryEntry`); explicit `AuthenticationTypes` with an empty user name produced an anonymous bind and `An operations error occurred` on hardened domain controllers.
- User lookup also matches the full member name against `userPrincipalName`, `mail` and `proxyAddresses` (Vault user names mapped to UPN/e-mail).
- Richer diagnostics in "No e-mail address found" warnings (provider, server).

## 3.0
- New default AD provider: plain LDAP via `System.DirectoryServices` (TCP 389/636). No RSAT / ActiveDirectory module, no ADWS (9389), no `Import-Module` hang. Nested group membership resolved in one query (`LDAP_MATCHING_RULE_IN_CHAIN`).
- `ADProvider = 'ADModule'` kept as an option; imports without the `AD:` drive and verifies connectivity with a timeout.
- Optional bind credential (`-SetADCredential`, `ADCredentialFile`).

## 2.5
- Rollout switches: `NotifyAccountOwners` (pilot mode, admins only) and `NotifyOnlySafes` (staged rollout). Admin summary gained a *Planned recipients per safe* table and a mode banner.

## 2.3 - 2.4
- Worked around Windows PowerShell 5.1 compiler bug (`Argument types do not match`): no here-string sub-expressions, no generic `List` objects passed as parameters, arrays everywhere.
- .NET stack trace logged on fatal errors.

## 2.0 - 2.2
- StrictMode-safe access to all API data (`Get-Prop`), case-insensitive property lookup.
- `AuthMethod` (CyberArk / LDAP / Windows), `-ConfigFile` (.psd1 overrides), `searchIn`-aware member resolution, `ADDomainMap`, regex exclusions, `ExcludedPlatforms`, `MaxMailsPerRun`, CSV report, null-safe table sorting.

## 1.0
- Initial release.
