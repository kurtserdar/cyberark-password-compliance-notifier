#Requires -Version 5.1
<#
.SYNOPSIS
    CyberArk PAM (Self-Hosted) password-compliance notifier.

.DESCRIPTION
    Scans every account the auditor user can see through the PVWA REST API,
    determines which accounts are past their platform-defined password change
    interval (non-compliant), resolves the members of each affected safe to
    e-mail addresses (Vault users, LDAP users and LDAP groups via Active
    Directory) and sends each recipient ONE consolidated HTML mail listing all
    accounts they are responsible for. A summary mail is sent to the
    administrator(s) and a CSV/HTML report is written to disk on every run.

    Designed to be run unattended (Windows Task Scheduler) once a day.

.PARAMETER SetCredential
    Interactive one-time setup: prompts for the PVWA (auditor) credential and
    stores it DPAPI-encrypted for the CURRENT Windows user on the CURRENT
    machine. Run this ONCE as the same Windows account that will execute the
    scheduled task, e.g.:
        runas /user:DOMAIN\svc_cyberark_notify "powershell.exe -File ...ps1 -SetCredential"

.PARAMETER SetSmtpCredential
    Same as -SetCredential, but for the SMTP account (only needed when the
    SMTP server requires authentication).

.PARAMETER DryRun
    Runs the whole pipeline but does NOT send any e-mail and does NOT update
    the notification state file. Everything is written to the log/report.

.PARAMETER ConfigFile
    Optional path to a .psd1 file whose keys override the $Config block below.
    Lets you keep one script and one config file per environment.

.PARAMETER Verbose
    Additional debug output (standard PowerShell common parameter).

.NOTES
    Exit codes:
        0  success
        1  configuration / prerequisite error
        2  PVWA authentication error
        3  PVWA API / unexpected fatal error
        4  mail transport error (no mail could be delivered)
        5  completed with non-fatal warnings (some recipients/accounts skipped)

    Works with PAM Self-Hosted 11.x - 14.x REST API (v2 endpoints, falls back
    to legacy endpoints where needed).
    Requires: PowerShell 5.1+ (or 7.x), network access to PVWA + SMTP,
              RSAT ActiveDirectory module if LDAP users/groups must be resolved.
    The auditor user only sees accounts in safes where it has List permission
    (the built-in Auditors group sees everything).
#>
[CmdletBinding()]
param(
    [switch]$SetCredential,
    [switch]$SetSmtpCredential,
    [switch]$SetADCredential,
    [switch]$DryRun,
    [string]$ConfigFile
)

# =============================================================================
#  CONFIGURATION  -  edit this block (or override with -ConfigFile <file.psd1>)
# =============================================================================
$Config = @{

    # ---- PVWA / Vault ------------------------------------------------------
    PvwaAddress            = 'https://pvwa.example.com'   # scheme + host (no trailing slash, no /PasswordVault)
    AuthMethod             = 'CyberArk'                   # CyberArk | LDAP | Windows  (Windows = IIS integrated auth with the task account, no credential file)
    AuditorUser            = 'AuditorUser'                # Vault/LDAP user with Auditor role (or List permission on the safes)
    CredentialFile         = "$PSScriptRoot\pvwa.cred.xml"   # DPAPI-encrypted; created with -SetCredential
    SkipCertificateCheck   = $false                       # $true ONLY for lab environments with self-signed certs
    ApiTimeoutSec          = 120
    ApiRetryCount          = 3                            # retries on 429/5xx/timeouts
    ApiPageSize            = 500                          # accounts per page (max 1000)
    ApiCallDelayMs         = 0                            # optional pause between API calls (large environments / rate limits)

    # ---- Scope -------------------------------------------------------------
    IncludedSafes          = @()                          # empty = all safes; otherwise only these (exact names, case-insensitive)
    ExcludedSafes          = @('VaultInternal','Notification Engine','PVWAConfig','PVWAReports',
                               'PVWATicketingSystem','PVWAUserPrefs','PVWAPublicData','PasswordManager',
                               'PasswordManager_Pending','PasswordManager_Info','PasswordManagerShared',
                               'PasswordManagerTemp','AccountsFeedADAccounts','AccountsFeedDiscoveryLogs',
                               'PSM','PSMSessions','PSMUnmanagedSessionAccounts','PSMRecordings',
                               'PSMUniversalConnectors','PSMNotifications','PSMPADBridgeConf','PSMPADBUserProfile',
                               'PSMPConf','PSMPLiveSessions','SharedAuth_Internal','TelemetryConfig','System',
                               'CyberArk Reports','ConfigurationsSafe','Applications')
    ExcludedSafePatterns   = @('^PSM.*','^PasswordManager.*','^PVWA.*')   # regex, applied in addition to ExcludedSafes
    ExcludedPlatforms      = @()                          # platform IDs to ignore entirely (exact, case-insensitive)
    OnlyCpmManagedAccounts = $false                       # $true = ignore accounts with automaticManagementEnabled = false
    IncludeCpmFailures     = $false                       # $true = also report accounts whose last CPM operation failed
    DefaultChangeDays      = 0                            # used when a platform has no "require change every X days"; 0 = no policy -> skip
    NotifyDaysBeforeDue    = 0                            # >0 = also warn N days BEFORE the password becomes overdue

    # ---- Recipient resolution --------------------------------------------
    RequiredPermissions    = @('retrieveAccounts','useAccounts','updateAccountContent','manageSafe')  # member needs ANY of these
    ExcludedMembers        = @('Master','Batch','Backup Users','Auditors','Operators','DR Users','Notification Engines',
                               'PVWAGWAccounts','PVWAAppUsers','PVWAAppUser','PVWAUsers','PSMAppUsers','PSMPApp',
                               'PasswordManager','PasswordManagerUser','Vault Admins','Administrator','AIMWebService')
    ExcludedMemberPatterns = @('^PSM.*','^PasswordManager.*','^PVWA.*','^AIM.*','^Prov_.*')          # regex
    ResolveLdapViaAD       = $true                        # resolve domain users/groups against Active Directory
    ADProvider             = 'LDAP'                       # LDAP = System.DirectoryServices over TCP 389/636, no RSAT needed (recommended)
                                                          # ADModule = RSAT ActiveDirectory module over ADWS TCP 9389 (can hang on hardened servers)
    ADServer               = ''                           # DC or domain FQDN (e.g. 'dc01.corp.local' or 'corp.local'); empty = current domain (LDAP) / auto-discover (ADModule)
    ADUseSsl               = $false                       # LDAP provider: $true = LDAPS on 636 (server certificate must be trusted)
    ADPort                 = 0                            # LDAP provider: 0 = default (389 / 636 with ADUseSsl); 3268 = Global Catalog
    ADSearchBase           = ''                           # LDAP provider: optional base DN; empty = defaultNamingContext of the server
    ADCredentialFile       = ''                           # LDAP provider: optional DPAPI file (create with -SetADCredential) when the task account cannot read AD; empty = integrated auth
    ADTimeoutSec           = 30                           # LDAP provider: per-query timeout
    ADLoadDefaultDrive     = $false                       # ADModule provider only: keep $false (avoids DC-discovery hang at Import-Module)
    ADDomainMap            = @{}                          # optional: CyberArk directory name -> AD domain FQDN, e.g. @{ 'corp' = 'corp.example.com' }
    ExpandGroups           = $true                        # expand LDAP + Vault groups to their members (recursive)
    MaxGroupMembers        = 200                          # safety valve: skip groups larger than this (logged)
    FallbackMailDomain     = ''                           # e.g. 'example.com' -> username@example.com when no mail attribute is found; empty = skip user

    # ---- SMTP --------------------------------------------------------------
    SmtpServer             = 'smtp.example.com'
    SmtpPort               = 25
    SmtpUseSsl             = $false                       # STARTTLS
    SmtpAuthenticate       = $false                       # $true -> uses SmtpCredentialFile
    SmtpCredentialFile     = "$PSScriptRoot\smtp.cred.xml"  # created with -SetSmtpCredential
    SenderMail             = 'cyberark-noreply@example.com'
    SenderDisplayName      = 'CyberArk Password Compliance'
    MailSubject            = '[CyberArk] Accounts requiring password change'
    MailCc                 = @()                          # always CC these addresses on user mails (optional)
    AdminMail              = @('pam-admins@example.com')  # receives the run summary + fatal error notices
    SendAdminSummary       = $true                        # $false = admin mail only on errors
    MaxMailsPerRun         = 500                          # safety valve against mail storms on first production run
    NotifyAccountOwners    = $true                        # $false = PILOT MODE: scan + resolve recipients + admin summary only, no mails to account owners
    NotifyOnlySafes        = @()                          # staged rollout: when non-empty, owners are mailed ONLY for these safes (exact names, case-insensitive); others go to admin summary only
    ReNotifyEveryDays      = 1                            # 1 = daily reminder; 0 = always; N = at most once every N days per recipient+account
    StateFile              = "$PSScriptRoot\notify-state.json"

    # ---- Logging / reports ------------------------------------------------
    LogDirectory           = "$PSScriptRoot\Logs"
    LogRetentionDays       = 60
    ReportDirectory        = "$PSScriptRoot\Reports"      # CSV of non-compliant accounts per run; '' = disabled
    ReportRetentionDays    = 90
}
# =============================================================================
#  END OF CONFIGURATION
# =============================================================================


# -----------------------------------------------------------------------------
#  Globals & helpers
# -----------------------------------------------------------------------------
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:ExitCode      = 0
$script:Warnings      = New-Object System.Collections.Generic.List[string]
$script:LogFile       = $null
$script:PvwaToken     = $null
$script:PvwaBase      = $null
$script:IsCore        = $PSVersionTable.PSVersion.Major -ge 6
$script:RunStart      = Get-Date
$script:UserCache     = @{}    # name -> mail (or $null)
$script:GroupCache    = @{}    # group -> [string[]] mails
$script:StopWatch     = [System.Diagnostics.Stopwatch]::StartNew()
$script:MailsSent     = 0

function Get-Prop {
    <# Safe property accessor for data coming from the API (StrictMode-proof).
       Returns $Default when the object is null or the property does not exist. #>
    param($Object, [Parameter(Mandatory)][string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    if ($Object -is [hashtable]) { if ($Object.ContainsKey($Name)) { return $Object[$Name] } else { return $Default } }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) {
        # case-insensitive fallback (API casing differs between versions)
        $p = $Object.PSObject.Properties | Where-Object { $_.Name -ieq $Name } | Select-Object -First 1
    }
    if ($null -eq $p -or $null -eq $p.Value) { return $Default }
    return $p.Value
}

function Get-PropPath {
    <# Get-Prop for nested paths: Get-PropPath $obj 'secretManagement.lastModifiedTime' #>
    param($Object, [Parameter(Mandatory)][string]$Path, $Default = $null)
    $cur = $Object
    foreach ($seg in $Path.Split('.')) {
        $cur = Get-Prop $cur $seg
        if ($null -eq $cur) { return $Default }
    }
    return $cur
}

function Write-Log {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','DEBUG')][string]$Level = 'INFO'
    )
    $line = '{0} [{1,-5}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow; $script:Warnings.Add($Message) | Out-Null }
        'DEBUG' { Write-Verbose $line }
        default { Write-Host $line }
    }
    if ($script:LogFile) {
        try { Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 } catch { }
    }
}

function Remove-OldFiles {
    param([string]$Directory, [string]$Filter, [int]$Days)
    if (-not $Directory -or $Days -le 0 -or -not (Test-Path -LiteralPath $Directory)) { return }
    Get-ChildItem -Path $Directory -Filter $Filter -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-1 * $Days) } |
        Remove-Item -Force -ErrorAction SilentlyContinue
}

function Initialize-Logging {
    try {
        if (-not (Test-Path -LiteralPath $Config.LogDirectory)) {
            New-Item -ItemType Directory -Path $Config.LogDirectory -Force | Out-Null
        }
        $script:LogFile = Join-Path $Config.LogDirectory ('ComplianceNotify_{0}.log' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
        Remove-OldFiles -Directory $Config.LogDirectory -Filter 'ComplianceNotify_*.log' -Days $Config.LogRetentionDays
    } catch {
        Write-Host "WARNING: cannot initialise log file: $($_.Exception.Message)" -ForegroundColor Yellow
        $script:LogFile = $null
    }
}

function Merge-ConfigFile {
    if (-not $ConfigFile) { return }
    if (-not (Test-Path -LiteralPath $ConfigFile)) { throw "CONFIG: ConfigFile '$ConfigFile' not found." }
    try { $override = Import-PowerShellDataFile -Path $ConfigFile }
    catch { throw "CONFIG: ConfigFile '$ConfigFile' could not be parsed: $($_.Exception.Message)" }
    foreach ($k in $override.Keys) {
        if (-not $Config.ContainsKey($k)) { Write-Log "ConfigFile: unknown key '$k' ignored." 'WARN'; continue }
        $Config[$k] = $override[$k]
    }
    Write-Log "Configuration overrides loaded from '$ConfigFile' ($($override.Count) keys)."
}

function Test-Configuration {
    $errors = @()
    if ([string]::IsNullOrWhiteSpace($Config.PvwaAddress) -or $Config.PvwaAddress -notmatch '^https?://') { $errors += 'PvwaAddress must start with http:// or https://' }
    if ($Config.AuthMethod -notin 'CyberArk','LDAP','Windows') { $errors += "AuthMethod must be CyberArk, LDAP or Windows (got '$($Config.AuthMethod)')" }
    if ($Config.AuthMethod -ne 'Windows') {
        if ([string]::IsNullOrWhiteSpace($Config.AuditorUser)) { $errors += 'AuditorUser is empty' }
        if (-not (Test-Path -LiteralPath $Config.CredentialFile)) { $errors += "Credential file '$($Config.CredentialFile)' not found. Run the script once with -SetCredential as the task account." }
    }
    if ([string]::IsNullOrWhiteSpace($Config.SmtpServer))   { $errors += 'SmtpServer is empty' }
    if ($Config.SmtpPort -lt 1 -or $Config.SmtpPort -gt 65535) { $errors += 'SmtpPort is out of range' }
    if (-not (Test-MailAddress $Config.SenderMail)) { $errors += 'SenderMail is not a valid address' }
    if ([string]::IsNullOrWhiteSpace($Config.MailSubject))  { $errors += 'MailSubject is empty' }
    if (-not $Config.AdminMail -or @($Config.AdminMail).Count -eq 0) { $errors += 'AdminMail must contain at least one address' }
    foreach ($a in @($Config.AdminMail)) { if (-not (Test-MailAddress $a)) { $errors += "AdminMail '$a' is not a valid address" } }
    if ($Config.ApiPageSize -lt 1 -or $Config.ApiPageSize -gt 1000) { $errors += 'ApiPageSize must be 1..1000' }
    if ($Config.SmtpAuthenticate -and -not (Test-Path -LiteralPath $Config.SmtpCredentialFile)) { $errors += "SMTP credential file '$($Config.SmtpCredentialFile)' not found. Run with -SetSmtpCredential." }
    if ($Config.NotifyAccountOwners -isnot [bool]) { $errors += 'NotifyAccountOwners must be $true or $false' }
    foreach ($rx in @($Config.ExcludedSafePatterns) + @($Config.ExcludedMemberPatterns)) {
        try { [void][regex]::new($rx) } catch { $errors += "Invalid regex pattern '$rx'" }
    }
    if ($Config.ADProvider -notin 'LDAP','ADModule') { $errors += "ADProvider must be LDAP or ADModule (got '$($Config.ADProvider)')" }
    if ($Config.ResolveLdapViaAD -and $Config.ADProvider -eq 'ADModule' -and -not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Log 'ActiveDirectory module not available - switching ADProvider to LDAP.' 'WARN'
        $Config.ADProvider = 'LDAP'
    }
    if ($Config.ResolveLdapViaAD -and $Config.ADProvider -eq 'LDAP' -and $Config.ADCredentialFile -and -not (Test-Path -LiteralPath $Config.ADCredentialFile)) {
        $errors += "AD credential file '$($Config.ADCredentialFile)' not found. Run with -SetADCredential."
    }
    if ($errors.Count) {
        foreach ($e in $errors) { Write-Log $e 'ERROR' }
        throw 'CONFIG: Configuration validation failed.'
    }
    $script:PvwaBase = $Config.PvwaAddress.TrimEnd('/') + '/PasswordVault/API'
    Write-Log "Configuration OK. PVWA=$($Config.PvwaAddress) Auth=$($Config.AuthMethod) User=$($Config.AuditorUser) DryRun=$DryRun PS=$($PSVersionTable.PSVersion) Host=$env:COMPUTERNAME RunAs=$env:USERDOMAIN\$env:USERNAME"
}

function Initialize-Tls {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        if ([Enum]::IsDefined([Net.SecurityProtocolType], 'Tls13')) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls13
        }
    } catch { Write-Log "Could not set TLS protocol: $($_.Exception.Message)" 'WARN' }

    if ($Config.SkipCertificateCheck -and -not $script:IsCore) {
        Write-Log 'Certificate validation DISABLED (SkipCertificateCheck = $true) - do not use in production.' 'WARN'
        try {
            if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
                Add-Type -TypeDefinition @"
using System.Net; using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
}
"@
            }
            [Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        } catch {
            [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        }
    }
}

function Save-StoredCredential {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Prompt, [string]$UserName)
    $cred = if ($UserName) { Get-Credential -UserName $UserName -Message $Prompt } else { Get-Credential -Message $Prompt }
    if (-not $cred) { throw 'CONFIG: No credential entered.' }
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $cred | Export-Clixml -Path $Path -Force
    Write-Host "Credential for '$($cred.UserName)' stored (DPAPI, user=$env:USERDOMAIN\$env:USERNAME, host=$env:COMPUTERNAME) in: $Path" -ForegroundColor Green
}

function Get-StoredCredential {
    param([Parameter(Mandatory)][string]$Path)
    try {
        $cred = Import-Clixml -Path $Path
        if ($cred -isnot [System.Management.Automation.PSCredential]) { throw 'file does not contain a PSCredential' }
        return $cred
    } catch {
        throw "CONFIG: Cannot read credential file '$Path' (it must be created by the same Windows user on the same machine): $($_.Exception.Message)"
    }
}

function Test-MailAddress {
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address)) { return $false }
    try { [void](New-Object System.Net.Mail.MailAddress($Address)); return $true } catch { return $false }
}

function Test-MatchesAny {
    param([string]$Value, [string[]]$Exact, [string[]]$Patterns)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    foreach ($e in @($Exact))    { if ($e -and $Value -ieq $e) { return $true } }
    foreach ($p in @($Patterns)) { if ($p -and $Value -imatch $p) { return $true } }
    return $false
}

# -----------------------------------------------------------------------------
#  PVWA REST helpers
# -----------------------------------------------------------------------------
function Get-ErrorDetail {
    param($ErrorRecord)
    $status = $null; $body = $null
    try {
        $resp = $ErrorRecord.Exception.Response
        if ($resp) {
            $status = [int]$resp.StatusCode
            if ($script:IsCore -and $ErrorRecord.ErrorDetails) {
                $body = $ErrorRecord.ErrorDetails.Message
            } elseif (-not $script:IsCore) {
                $stream = $resp.GetResponseStream()
                if ($stream) { $reader = New-Object IO.StreamReader($stream); $body = $reader.ReadToEnd(); $reader.Dispose() }
            }
        }
    } catch { }
    $code = $null; $msg = $null
    if ($body) {
        try { $j = $body | ConvertFrom-Json; $code = Get-Prop $j 'ErrorCode'; $msg = Get-Prop $j 'ErrorMessage' } catch { $msg = $body }
    }
    if (-not $msg) { $msg = $ErrorRecord.Exception.Message }
    return [pscustomobject]@{ Status = $status; Code = $code; Message = $msg }
}

function Invoke-PvwaApi {
    param(
        [Parameter(Mandatory)][ValidateSet('GET','POST','PUT','DELETE','PATCH')][string]$Method,
        [Parameter(Mandatory)][string]$Uri,          # absolute, or relative to /PasswordVault/API
        $Body = $null,
        [switch]$NoAuth,
        [switch]$NoReLogin,
        [switch]$NoRetry
    )
    if ($Uri -notmatch '^https?://') { $Uri = $script:PvwaBase + '/' + $Uri.TrimStart('/') }

    $headers = @{ 'Content-Type' = 'application/json'; 'Accept' = 'application/json' }
    if (-not $NoAuth) {
        if (-not $script:PvwaToken) { throw 'AUTH: Not authenticated to PVWA.' }
        $headers['Authorization'] = $script:PvwaToken
    }
    $params = @{ Method = $Method; Uri = $Uri; Headers = $headers; TimeoutSec = $Config.ApiTimeoutSec; ErrorAction = 'Stop' }
    if ($null -ne $Body) { $params['Body'] = ($Body | ConvertTo-Json -Depth 10 -Compress); $params['ContentType'] = 'application/json' }
    if ($script:IsCore -and $Config.SkipCertificateCheck) { $params['SkipCertificateCheck'] = $true }
    if (-not $script:IsCore) { $params['UseBasicParsing'] = $true }
    if ($Config.AuthMethod -eq 'Windows') { $params['UseDefaultCredentials'] = $true }

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            Write-Log "$Method $Uri (attempt $attempt)" 'DEBUG'
            if ($Config.ApiCallDelayMs -gt 0) { Start-Sleep -Milliseconds $Config.ApiCallDelayMs }
            return Invoke-RestMethod @params
        } catch {
            $detail = Get-ErrorDetail $_
            $retryable = ($detail.Status -in 429, 500, 502, 503, 504) -or ($null -eq $detail.Status -and $_.Exception -is [System.Net.WebException]) -or ($_.Exception.Message -match 'timed out|timeout')
            if ($detail.Status -eq 401 -and -not $NoReLogin -and -not $NoAuth -and $attempt -le 2) {
                Write-Log 'Session expired (401) - re-authenticating.' 'WARN'
                Connect-Pvwa
                $headers['Authorization'] = $script:PvwaToken
                $params['Headers'] = $headers
                continue
            }
            if ($retryable -and -not $NoRetry -and $attempt -le $Config.ApiRetryCount) {
                $delay = [math]::Min(60, [math]::Pow(2, $attempt) * 2)
                Write-Log "API call failed (HTTP $($detail.Status) $($detail.Code) - $($detail.Message)). Retrying in ${delay}s..." 'WARN'
                Start-Sleep -Seconds $delay
                continue
            }
            throw "API: $Method $Uri -> HTTP $($detail.Status) $($detail.Code) $($detail.Message)"
        }
    }
}

function Connect-Pvwa {
    $user = $null; $body = $null
    switch ($Config.AuthMethod) {
        'Windows' {
            $endpoint = 'auth/Windows/Logon'
            $user = "$env:USERDOMAIN\$env:USERNAME"
            $body = @{ concurrentSession = $true }
        }
        default {
            $cred = Get-StoredCredential -Path $Config.CredentialFile
            if ($cred.UserName -ne $Config.AuditorUser) {
                Write-Log "Credential file user '$($cred.UserName)' differs from AuditorUser '$($Config.AuditorUser)'. Using credential file user." 'WARN'
            }
            $endpoint = if ($Config.AuthMethod -eq 'LDAP') { 'auth/LDAP/Logon' } else { 'auth/CyberArk/Logon' }
            $user = $cred.UserName
            $body = @{ username = $cred.UserName; password = $cred.GetNetworkCredential().Password; concurrentSession = $true }
        }
    }
    try {
        $token = Invoke-PvwaApi -Method POST -Uri $endpoint -Body $body -NoAuth -NoReLogin
    } catch {
        throw "AUTH: PVWA logon ($($Config.AuthMethod)) failed for '$user': $($_.Exception.Message)"
    } finally {
        if ($body -and $body.ContainsKey('password')) { $body['password'] = $null }
        $body = $null
    }
    if ($null -eq $token) { throw 'AUTH: PVWA logon returned no token.' }
    if ($token -isnot [string]) {
        # some versions/proxies wrap the token in an object
        $t2 = Get-Prop $token 'CyberArkLogonResult'
        if (-not $t2) { $t2 = Get-Prop $token 'token' }
        if (-not $t2) { throw 'AUTH: PVWA logon returned an unexpected token format.' }
        $token = [string]$t2
    }
    $script:PvwaToken = $token.Trim().Trim('"')
    Write-Log "Authenticated to PVWA as '$user' via $($Config.AuthMethod)."
}

function Disconnect-Pvwa {
    if ($script:PvwaToken) {
        try { Invoke-PvwaApi -Method POST -Uri 'auth/Logoff' -NoReLogin -NoRetry | Out-Null; Write-Log 'PVWA session closed.' }
        catch { Write-Log "Logoff failed (ignored): $($_.Exception.Message)" 'DEBUG' }
        $script:PvwaToken = $null
    }
}

function Get-PvwaPagedValues {
    <# Follows nextLink for endpoints returning { value:[], count, nextLink }; also
       accepts legacy shapes ({ members:[] }, { Users:[] }, bare arrays). #>
    param([Parameter(Mandatory)][string]$Uri, [string]$Description = 'items', [string[]]$ItemKeys = @('value','members','Members','Users','Platforms','accounts'))
    $all = New-Object System.Collections.Generic.List[object]
    $next = $Uri
    $page = 0
    while ($next) {
        $page++
        $resp = Invoke-PvwaApi -Method GET -Uri $next
        if ($null -eq $resp) { break }
        $items = $null
        if ($resp -is [array]) { $items = @($resp) }
        else {
            foreach ($k in $ItemKeys) {
                $v = Get-Prop $resp $k
                if ($null -ne $v) { $items = @($v); break }
            }
        }
        if ($null -eq $items) { $items = @() }
        foreach ($i in $items) { $all.Add($i) }
        $next = $null
        $nl = Get-Prop $resp 'nextLink'
        if ($nl) {
            $next = [string]$nl
            if ($next -notmatch '^https?://') { $next = $Config.PvwaAddress.TrimEnd('/') + '/PasswordVault/' + $next.TrimStart('/') }
        }
        Write-Log "Fetched page $page of $Description ($($items.Count) items, total so far $($all.Count))" 'DEBUG'
        if ($page -gt 10000) { throw "API: Paging safety limit reached for $Description" }
    }
    return $all
}

# -----------------------------------------------------------------------------
#  Data retrieval
# -----------------------------------------------------------------------------
function Get-PlatformPolicies {
    # Returns hashtable: platformId (lower) -> @{ ChangeDays; PerformChange; Name; Active }
    $map = @{}
    try {
        $resp = Invoke-PvwaApi -Method GET -Uri 'Platforms/Targets'
        $platforms = @(Get-Prop $resp 'Platforms' @())
        foreach ($p in $platforms) {
            $platformKey = [string](Get-Prop $p 'PlatformID')
            if (-not $platformKey) { continue }
            $days = $null; $perform = $null
            $chg = Get-PropPath $p 'CredentialsManagementPolicy.Change'
            if ($chg) {
                $d = Get-Prop $chg 'RequirePasswordEveryXDays'
                if ($null -ne $d -and "$d" -match '^\d+$') { $days = [int]$d }
                $pa = Get-Prop $chg 'PerformAutomatic'
                if ($null -ne $pa) { $perform = [bool]$pa }
            }
            $map[$platformKey.ToLowerInvariant()] = @{ Name = [string](Get-Prop $p 'Name' $platformKey); Active = (Get-Prop $p 'Active'); ChangeDays = $days; PerformChange = $perform }
        }
        Write-Log "Loaded $($map.Count) target platform policies."
    } catch {
        Write-Log "Could not load platform policies from Platforms/Targets: $($_.Exception.Message). Falling back to per-platform lookups / DefaultChangeDays." 'WARN'
    }
    return $map
}

function Get-PlatformPolicyLazy {
    param([Parameter(Mandatory)][hashtable]$Map, [Parameter(Mandatory)][string]$PlatformId)
    $key = $PlatformId.ToLowerInvariant()
    if ($Map.ContainsKey($key)) { return $Map[$key] }
    $entry = @{ Name = $PlatformId; Active = $null; ChangeDays = $null; PerformChange = $null }
    try {
        $p = Invoke-PvwaApi -Method GET -Uri ('Platforms/' + [uri]::EscapeDataString($PlatformId)) -NoRetry
        $det = Get-Prop $p 'Details'
        $chg = Get-PropPath $det 'CredentialsManagementPolicy.Change'
        if ($chg) {
            $d = Get-Prop $chg 'RequirePasswordEveryXDays'
            if ($null -ne $d -and "$d" -match '^\d+$') { $entry.ChangeDays = [int]$d }
            $pa = Get-Prop $chg 'PerformAutomatic'
            if ($null -ne $pa) { $entry.PerformChange = [bool]$pa }
        }
        $pn = Get-Prop $det 'PolicyName'; if ($pn) { $entry.Name = [string]$pn }
        Write-Log "Loaded platform '$PlatformId' via legacy endpoint (ChangeDays=$($entry.ChangeDays))." 'DEBUG'
    } catch {
        Write-Log "Platform '$PlatformId' could not be loaded: $($_.Exception.Message)" 'WARN'
    }
    $Map[$key] = $entry
    return $entry
}

function Get-AllAccounts {
    $uri = 'Accounts?limit={0}&offset=0' -f $Config.ApiPageSize
    $accounts = Get-PvwaPagedValues -Uri $uri -Description 'accounts'
    Write-Log "Retrieved $($accounts.Count) accounts from PVWA."
    return $accounts
}

function ConvertFrom-Epoch {
    param($Value)
    if ($null -eq $Value) { return $null }
    $s = "$Value".Trim()
    if ($s -eq '' -or $s -eq '0' -or $s -eq '-1') { return $null }
    try {
        $n = [int64]$s
        if ($n -gt 100000000000) { $n = [int64]($n / 1000) }   # milliseconds -> seconds
        return [DateTimeOffset]::FromUnixTimeSeconds($n).UtcDateTime
    } catch { return $null }
}

function Test-SafeInScope {
    param([string]$SafeName)
    if ([string]::IsNullOrWhiteSpace($SafeName)) { return $false }
    if (@($Config.IncludedSafes).Count -gt 0) {
        return (Test-MatchesAny -Value $SafeName -Exact $Config.IncludedSafes -Patterns @())
    }
    return -not (Test-MatchesAny -Value $SafeName -Exact $Config.ExcludedSafes -Patterns $Config.ExcludedSafePatterns)
}

function Get-NonCompliantAccounts {
    param([AllowEmptyCollection()][object[]]$Accounts = @(), [Parameter(Mandatory)][hashtable]$PlatformMap)
    $result = New-Object System.Collections.Generic.List[object]
    $now = (Get-Date).ToUniversalTime()
    $skippedScope = 0; $skippedManual = 0; $skippedNoPolicy = 0; $skippedPlatform = 0; $evaluated = 0

    foreach ($a in $Accounts) {
        $safe = [string](Get-Prop $a 'safeName' '')
        if (-not (Test-SafeInScope $safe)) { $skippedScope++; continue }

        $platformId = [string](Get-Prop $a 'platformId' '')
        if ($platformId -and (Test-MatchesAny -Value $platformId -Exact $Config.ExcludedPlatforms -Patterns @())) { $skippedPlatform++; continue }

        $sm        = Get-Prop $a 'secretManagement'
        $autoRaw   = Get-Prop $sm 'automaticManagementEnabled'
        $auto      = if ($null -eq $autoRaw) { $true } else { [bool]$autoRaw }
        $lastMod   = ConvertFrom-Epoch (Get-Prop $sm 'lastModifiedTime')
        $cpmStatus = [string](Get-Prop $sm 'status' '')
        if ($Config.OnlyCpmManagedAccounts -and -not $auto) { $skippedManual++; continue }

        $policy = if ($platformId) { Get-PlatformPolicyLazy -Map $PlatformMap -PlatformId $platformId } else { @{ Name=''; ChangeDays=$null; PerformChange=$null } }
        $changeDays = $policy.ChangeDays
        if (($null -eq $changeDays -or $changeDays -le 0) -and $Config.DefaultChangeDays -gt 0) { $changeDays = $Config.DefaultChangeDays }

        $evaluated++
        $reasons = @()
        $dueDate = $null; $daysOverdue = $null
        if ($null -ne $changeDays -and $changeDays -gt 0) {
            if ($null -eq $lastMod) {
                $created = ConvertFrom-Epoch (Get-Prop $a 'createdTime')
                if ($created) { $dueDate = $created.AddDays($changeDays) } else { $reasons += 'Password never changed (no lastModifiedTime)' }
            } else {
                $dueDate = $lastMod.AddDays($changeDays)
            }
            if ($dueDate) {
                $daysOverdue = [int][math]::Floor(($now - $dueDate).TotalDays)
                if ($daysOverdue -ge 0) { $reasons += "Password change overdue by $daysOverdue day(s)" }
                elseif ($Config.NotifyDaysBeforeDue -gt 0 -and (-$daysOverdue) -le $Config.NotifyDaysBeforeDue) { $reasons += "Password change due in $(-$daysOverdue) day(s)" }
            }
        } else {
            $skippedNoPolicy++
        }
        if ($Config.IncludeCpmFailures -and $cpmStatus -ieq 'failure') {
            $reasons += 'Last CPM operation failed'
        }
        if ($reasons.Count -eq 0) { continue }

        $result.Add([pscustomobject]@{
            Id            = [string](Get-Prop $a 'id' '')
            Safe          = $safe
            Name          = [string](Get-Prop $a 'name' '')
            UserName      = [string](Get-Prop $a 'userName' '')
            Address       = [string](Get-Prop $a 'address' '')
            PlatformId    = $platformId
            PlatformName  = [string]$policy.Name
            SecretType    = [string](Get-Prop $a 'secretType' '')
            CpmManaged    = $auto
            CpmStatus     = $cpmStatus
            LastChanged   = $lastMod
            ChangeDays    = $changeDays
            DueDate       = $dueDate
            DaysOverdue   = $daysOverdue
            Reasons       = ($reasons -join '; ')
        })
    }
    Write-Log ("Compliance evaluation: {0} evaluated, {1} NON-COMPLIANT, {2} out of scope (safe filter), {3} excluded platform, {4} manual skipped, {5} without change policy." -f $evaluated, $result.Count, $skippedScope, $skippedPlatform, $skippedManual, $skippedNoPolicy)
    return $result
}

# -----------------------------------------------------------------------------
#  Recipient resolution
# -----------------------------------------------------------------------------
function Get-SafeMembers {
    param([Parameter(Mandatory)][string]$SafeName)
    $enc = [uri]::EscapeDataString($SafeName)
    $attempts = @(
        "Safes/$enc/Members?limit=1000&offset=0&filter=includePredefinedUsers%20eq%20false",
        "Safes/$enc/Members?limit=1000&offset=0",
        "Safes/$enc/Members"
    )
    $lastErr = $null
    foreach ($u in $attempts) {
        try { return Get-PvwaPagedValues -Uri $u -Description "members of safe '$SafeName'" }
        catch { $lastErr = $_.Exception.Message; Write-Log "Member query '$u' failed, trying next variant: $lastErr" 'DEBUG' }
    }
    throw "API: Could not list members of safe '$SafeName': $lastErr"
}

function Test-MemberHasRequiredPermission {
    param($Member)
    $perms = Get-Prop $Member 'permissions'
    if ($null -eq $perms) { return $false }
    if ($perms -is [array]) {
        # legacy shape: [ { Key = 'RetrieveAccounts'; Value = $true }, ... ]
        foreach ($req in $Config.RequiredPermissions) {
            $hit = $perms | Where-Object { (Get-Prop $_ 'Key') -ieq $req -and [bool](Get-Prop $_ 'Value' $false) }
            if ($hit) { return $true }
        }
        return $false
    }
    foreach ($req in $Config.RequiredPermissions) {
        $v = Get-Prop $perms $req
        if ($null -ne $v -and [bool]$v) { return $true }
    }
    return $false
}

function Split-MemberName {
    # Returns @{ Sam = 'user'; Domain = 'DOMAIN' or '' }
    param([string]$Name)
    $n = "$Name".Trim()
    if ($n -match '^([^\\]+)\\(.+)$') { return @{ Sam = $Matches[2]; Domain = $Matches[1] } }
    if ($n -match '^([^@]+)@(.+)$')   { return @{ Sam = $Matches[1]; Domain = $Matches[2] } }
    if ($n -match '^CN=([^,]+),')     { return @{ Sam = $Matches[1]; Domain = '' } }
    return @{ Sam = $n; Domain = '' }
}

function Resolve-ADServer {
    # Decide which AD server/domain to query for a member coming from CyberArk directory $Directory
    param([string]$Directory, [string]$DomainFromName)
    if ($Config.ADServer) { return $Config.ADServer }
    foreach ($cand in @($Directory, $DomainFromName)) {
        if (-not $cand) { continue }
        if ($Config.ADDomainMap -and $Config.ADDomainMap.ContainsKey($cand)) { return $Config.ADDomainMap[$cand] }
        if ($cand -match '\.') { return $cand }   # already an FQDN
    }
    return $null
}

function Get-VaultUserMail {
    param([Parameter(Mandatory)][string]$UserName)
    try {
        $resp = Invoke-PvwaApi -Method GET -Uri ('Users?search={0}&extendedDetails=true' -f [uri]::EscapeDataString($UserName)) -NoRetry
        $users = @(Get-Prop $resp 'Users' @())
        $u = $users | Where-Object { (Get-Prop $_ 'username') -ieq $UserName } | Select-Object -First 1
        if ($u) {
            foreach ($path in 'internet.businessEmail','businessAddress.email','email','internet.homeEmail') {
                $mail = Get-PropPath $u $path
                if ($mail -and (Test-MailAddress $mail)) { return [string]$mail }
            }
        }
    } catch { Write-Log "Vault user lookup failed for '$UserName': $($_.Exception.Message)" 'DEBUG' }
    return $null
}

function Get-VaultGroupMemberNames {
    param([Parameter(Mandatory)][string]$GroupName)
    try {
        $resp = Invoke-PvwaApi -Method GET -Uri ('UserGroups?search={0}&includeMembers=true' -f [uri]::EscapeDataString($GroupName)) -NoRetry
        $groups = @(Get-Prop $resp 'value' @())
        $g = $groups | Where-Object { (Get-Prop $_ 'groupName') -ieq $GroupName } | Select-Object -First 1
        $members = @(Get-Prop $g 'members' @())
        return @($members | ForEach-Object { Get-Prop $_ 'username' } | Where-Object { $_ })
    } catch { Write-Log "Vault group lookup failed for '$GroupName': $($_.Exception.Message)" 'DEBUG' }
    return @()
}

# ---- LDAP provider (System.DirectoryServices, TCP 389/636, no RSAT) ----------
$script:LdapRootCache = @{}    # server -> @{ Path; Auth; Cred }

function ConvertTo-LdapFilterValue {
    # RFC 4515 escaping for values used inside an LDAP filter
    param([string]$Value)
    if ($null -eq $Value) { return '' }
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Value.ToCharArray()) {
        switch ($ch) {
            '\'    { [void]$sb.Append('\5c') }
            '*'    { [void]$sb.Append('\2a') }
            '('    { [void]$sb.Append('\28') }
            ')'    { [void]$sb.Append('\29') }
            "`0"   { [void]$sb.Append('\00') }
            default { [void]$sb.Append($ch) }
        }
    }
    return $sb.ToString()
}

function New-LdapEntry {
    <# Builds a DirectoryEntry. IMPORTANT: when no explicit credential is used, construct with the path ONLY.
       Passing $null user/password together with AuthenticationTypes makes PowerShell send an empty user name,
       which turns into an anonymous bind and the DC answers "An operations error occurred" (0x80072020). #>
    param([Parameter(Mandatory)][string]$Path, $Cred, [System.DirectoryServices.AuthenticationTypes]$Auth)
    if ($Cred) {
        return New-Object System.DirectoryServices.DirectoryEntry($Path, $Cred.UserName, $Cred.GetNetworkCredential().Password, $Auth)
    }
    $de = New-Object System.DirectoryServices.DirectoryEntry($Path)
    if ($Config.ADUseSsl) { $de.AuthenticationType = $Auth }
    return $de
}

function Get-LdapConnectionInfo {
    # Returns @{ Path = 'LDAP://server:port/DC=...'; Auth = AuthenticationTypes; Cred = PSCredential|$null }
    param([string]$Server)
    $key = if ($Server) { $Server.ToLowerInvariant() } else { '(default)' }
    if ($script:LdapRootCache.ContainsKey($key)) { return $script:LdapRootCache[$key] }

    $auth = [System.DirectoryServices.AuthenticationTypes]::Secure
    if ($Config.ADUseSsl) { $auth = [System.DirectoryServices.AuthenticationTypes]::Secure -bor [System.DirectoryServices.AuthenticationTypes]::SecureSocketsLayer }
    $port = [int]$Config.ADPort
    if ($port -le 0) { $port = if ($Config.ADUseSsl) { 636 } else { 389 } }
    $hostPart = ''
    if ($Server) { $hostPart = $Server + ':' + $port + '/' }

    $cred = $null
    if ($Config.ADCredentialFile) { $cred = Get-StoredCredential -Path $Config.ADCredentialFile }

    $base = $Config.ADSearchBase
    if (-not $base) {
        $rootDse = $null
        try {
            $rootDse = New-LdapEntry -Path ('LDAP://' + $hostPart + 'RootDSE') -Cred $cred -Auth $auth
            $base = [string]$rootDse.Properties['defaultNamingContext'].Value
            if ($port -eq 3268) { $base = '' }   # Global Catalog: search the whole forest
        } finally { if ($rootDse) { $rootDse.Dispose() } }
    }
    $info = @{ Path = ('LDAP://' + $hostPart + $base); Auth = $auth; Cred = $cred; Server = $Server; Port = $port }
    $script:LdapRootCache[$key] = $info
    Write-Log "LDAP connection: $($info.Path) (ssl=$($Config.ADUseSsl), cred=$(if ($cred) { $cred.UserName } else { 'integrated' }))" 'DEBUG'
    return $info
}

function Invoke-LdapSearch {
    # Returns SearchResult[] for the filter; $Properties = attribute names to load
    param([string]$Server, [Parameter(Mandatory)][string]$Filter, [string[]]$Properties = @(), [int]$SizeLimit = 0)
    $info = Get-LdapConnectionInfo -Server $Server
    $root = $null; $searcher = $null
    try {
        $root = New-LdapEntry -Path $info.Path -Cred $info.Cred -Auth $info.Auth
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
        $searcher.Filter          = $Filter
        $searcher.SearchScope     = [System.DirectoryServices.SearchScope]::Subtree
        $searcher.PageSize        = 1000
        $searcher.ClientTimeout   = [TimeSpan]::FromSeconds($Config.ADTimeoutSec)
        $searcher.ServerTimeLimit = [TimeSpan]::FromSeconds($Config.ADTimeoutSec)
        $searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::None
        if ($SizeLimit -gt 0) { $searcher.SizeLimit = $SizeLimit }
        [void]$searcher.PropertiesToLoad.Add('distinguishedName')
        foreach ($p in $Properties) { [void]$searcher.PropertiesToLoad.Add($p) }
        $results = New-Object System.Collections.Generic.List[object]
        $rc = $searcher.FindAll()
        try { foreach ($r in $rc) { $results.Add($r) } } finally { $rc.Dispose() }
        return ,$results.ToArray()
    } finally {
        if ($searcher) { $searcher.Dispose() }
        if ($root)     { $root.Dispose() }
    }
}

function Get-LdapProp {
    param($SearchResult, [string]$Name)
    if ($null -eq $SearchResult) { return $null }
    $coll = $SearchResult.Properties[$Name.ToLowerInvariant()]
    if ($null -eq $coll -or $coll.Count -eq 0) { return $null }
    return $coll[0]
}

function Get-LdapUserMail {
    # $Sam = short name (sAMAccountName); $FullName = original member name (may be UPN / e-mail / DOMAIN\user)
    param([Parameter(Mandatory)][string]$Sam, [string]$Server, [string]$FullName = '')
    $v = ConvertTo-LdapFilterValue $Sam
    $alts = "(sAMAccountName=$v)(userPrincipalName=$v)(mail=$v)"
    if ($FullName -and $FullName -ne $Sam -and $FullName -match '@') {
        $fv = ConvertTo-LdapFilterValue $FullName
        $alts += "(userPrincipalName=$fv)(mail=$fv)(proxyAddresses=smtp:$fv)"
    }
    $f = "(&(objectCategory=person)(objectClass=user)(|$alts))"
    $r = @(Invoke-LdapSearch -Server $Server -Filter $f -Properties @('mail','userPrincipalName','userAccountControl','sAMAccountName') -SizeLimit 2)
    if ($r.Length -eq 0) { Write-Log "LDAP: no user matched '$Sam' / '$FullName' (server='$Server')" 'DEBUG'; return $null }
    if ($r.Length -gt 1) { Write-Log "LDAP: '$Sam' matched more than one user - using first (sAMAccountName='$(Get-LdapProp $r[0] 'sAMAccountName')')" 'DEBUG' }
    $u = $r[0]
    $uac = [int](Get-LdapProp $u 'userAccountControl')
    if (($uac -band 2) -ne 0) { Write-Log "AD user '$Sam' is disabled - skipping." 'DEBUG'; return $null }
    $mail = [string](Get-LdapProp $u 'mail')
    if ($mail -and (Test-MailAddress $mail)) { return $mail }
    $upn = [string](Get-LdapProp $u 'userPrincipalName')
    if ($upn -and (Test-MailAddress $upn)) { return $upn }
    return $null
}

function Get-LdapGroupMemberSams {
    # Recursive (nested) group membership in ONE query via LDAP_MATCHING_RULE_IN_CHAIN; returns $null if group not found
    param([Parameter(Mandatory)][string]$Sam, [string]$Server)
    $fg = '(&(objectClass=group)(sAMAccountName={0}))' -f (ConvertTo-LdapFilterValue $Sam)
    $g = @(Invoke-LdapSearch -Server $Server -Filter $fg -Properties @('sAMAccountName') -SizeLimit 2)
    if ($g.Length -eq 0) { return $null }
    $dn = [string](Get-LdapProp $g[0] 'distinguishedName')
    $fm = '(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={0}))' -f (ConvertTo-LdapFilterValue $dn)
    $m = @(Invoke-LdapSearch -Server $Server -Filter $fm -Properties @('sAMAccountName'))
    $sams = New-Object System.Collections.Generic.List[string]
    foreach ($x in $m) { $v = [string](Get-LdapProp $x 'sAMAccountName'); if ($v) { $sams.Add($v) } }
    return ,$sams.ToArray()
}

function Test-LdapConnectivity {
    param([string]$Server)
    try {
        $info = Get-LdapConnectionInfo -Server $Server
        $null = @(Invoke-LdapSearch -Server $Server -Filter '(objectClass=domainDNS)' -Properties @('name') -SizeLimit 1)
        Write-Log "LDAP connectivity OK: $($info.Path)"
        return $true
    } catch {
        $inner = $_.Exception; while ($inner.InnerException) { $inner = $inner.InnerException }
        Write-Log "LDAP connectivity FAILED for server '$Server': $($inner.Message). AD lookups disabled for this run." 'WARN'
        return $false
    }
}

# ---- provider dispatch --------------------------------------------------------
function Get-ADUserMail {
    param([Parameter(Mandatory)][string]$Sam, [string]$Server, [string]$FullName = '')
    if (-not $Config.ResolveLdapViaAD) { return $null }
    try {
        if ($Config.ADProvider -eq 'LDAP') { return Get-LdapUserMail -Sam $Sam -Server $Server -FullName $FullName }
        $p = @{ ErrorAction = 'Stop' }; if ($Server) { $p['Server'] = $Server }
        $u = Get-ADUser -Identity $Sam -Properties mail, UserPrincipalName, Enabled @p
        if ($u) {
            if (-not $u.Enabled) { Write-Log "AD user '$Sam' is disabled - skipping." 'DEBUG'; return $null }
            if ($u.mail -and (Test-MailAddress $u.mail)) { return [string]$u.mail }
            if ($u.UserPrincipalName -and (Test-MailAddress $u.UserPrincipalName)) { return [string]$u.UserPrincipalName }
        }
    } catch {
        $inner = $_.Exception; while ($inner.InnerException) { $inner = $inner.InnerException }
        Write-Log "AD user lookup failed for '$Sam' (server='$Server', provider=$($Config.ADProvider)): $($inner.Message)" 'DEBUG'
    }
    return $null
}

function Get-ADGroupMemberSams {
    # Returns $null when the group cannot be resolved in AD (so caller can try Vault), otherwise string[]
    param([Parameter(Mandatory)][string]$Sam, [string]$Server)
    if (-not $Config.ResolveLdapViaAD) { return $null }
    try {
        if ($Config.ADProvider -eq 'LDAP') { return Get-LdapGroupMemberSams -Sam $Sam -Server $Server }
        $p = @{ ErrorAction = 'Stop' }; if ($Server) { $p['Server'] = $Server }
        $members = @(Get-ADGroupMember -Identity $Sam -Recursive @p | Where-Object { $_.objectClass -eq 'user' })
        return @($members | ForEach-Object { $_.SamAccountName })
    } catch {
        $inner = $_.Exception; while ($inner.InnerException) { $inner = $inner.InnerException }
        Write-Log "AD group lookup failed for '$Sam' (server='$Server', provider=$($Config.ADProvider)): $($inner.Message)" 'DEBUG'
    }
    return $null
}

function Resolve-UserMail {
    <# Returns mail address or $null.
       Directory = CyberArk 'searchIn' value: 'Vault' for internal users, otherwise the LDAP directory name.
       Order for LDAP users : AD -> Vault record -> FallbackMailDomain
       Order for Vault users: Vault record -> AD -> FallbackMailDomain #>
    param([Parameter(Mandatory)][string]$Name, [string]$Directory = '')
    $key = ($Name + '|' + $Directory).ToLowerInvariant()
    if ($script:UserCache.ContainsKey($key)) { return $script:UserCache[$key] }
    $parts  = Split-MemberName $Name
    $server = Resolve-ADServer -Directory $Directory -DomainFromName $parts.Domain
    $isVaultUser = ($Directory -ieq 'Vault')
    $mail = $null
    if ($isVaultUser) {
        $mail = Get-VaultUserMail -UserName $parts.Sam
        if (-not $mail) { $mail = Get-ADUserMail -Sam $parts.Sam -Server $server -FullName $Name }
    } else {
        $mail = Get-ADUserMail -Sam $parts.Sam -Server $server -FullName $Name
        if (-not $mail) { $mail = Get-VaultUserMail -UserName $parts.Sam }
        if (-not $mail -and $parts.Sam -ne $Name) { $mail = Get-VaultUserMail -UserName $Name }
    }
    if (-not $mail -and $Config.FallbackMailDomain) { $mail = '{0}@{1}' -f $parts.Sam, $Config.FallbackMailDomain }
    if ($mail -and -not (Test-MailAddress $mail)) { Write-Log "Resolved address '$mail' for '$Name' is not valid - ignored." 'WARN'; $mail = $null }
    $script:UserCache[$key] = $mail
    return $mail
}

function Resolve-GroupMails {
    param([Parameter(Mandatory)][string]$Name, [string]$Directory = '')
    $key = ($Name + '|' + $Directory).ToLowerInvariant()
    if ($script:GroupCache.ContainsKey($key)) { return $script:GroupCache[$key] }
    $script:GroupCache[$key] = @()   # cycle guard
    if (-not $Config.ExpandGroups) { Write-Log "Group '$Name' skipped (ExpandGroups = false)." 'WARN'; return @() }

    $parts  = Split-MemberName $Name
    $server = Resolve-ADServer -Directory $Directory -DomainFromName $parts.Domain
    $sams = $null
    if ($Directory -ine 'Vault') { $sams = Get-ADGroupMemberSams -Sam $parts.Sam -Server $server }
    if ($null -eq $sams) {
        $sams = Get-VaultGroupMemberNames -GroupName $parts.Sam
        if (@($sams).Count -eq 0 -and $parts.Sam -ne $Name) { $sams = Get-VaultGroupMemberNames -GroupName $Name }
        if (@($sams).Count -eq 0 -and $Directory -ieq 'Vault') { $sams = Get-ADGroupMemberSams -Sam $parts.Sam -Server $server }
    }
    $sams = @($sams | Where-Object { $_ })
    if ($sams.Count -eq 0) { Write-Log "Group '$Name' (directory '$Directory') has no resolvable members (AD/Vault)." 'WARN'; return @() }
    if ($sams.Count -gt $Config.MaxGroupMembers) { Write-Log "Group '$Name' has $($sams.Count) members (> MaxGroupMembers=$($Config.MaxGroupMembers)) - skipped." 'WARN'; return @() }

    $mails = New-Object System.Collections.Generic.List[string]
    foreach ($s in $sams) {
        $m = Resolve-UserMail -Name $s -Directory $Directory
        if ($m) { $mails.Add($m) } else { Write-Log "No e-mail for group member '$s' of '$Name'." 'DEBUG' }
    }
    $script:GroupCache[$key] = @($mails | Select-Object -Unique)
    return $script:GroupCache[$key]
}

function Get-SafeRecipients {
    # Returns hashtable: mail (lower) -> memberName(s) that led to it
    param([Parameter(Mandatory)][string]$SafeName)
    $recipients = @{}
    $members = Get-SafeMembers -SafeName $SafeName
    foreach ($m in $members) {
        $name = [string](Get-Prop $m 'memberName' (Get-Prop $m 'MemberName' ''))
        if (-not $name) { continue }
        if (Test-MatchesAny -Value $name -Exact $Config.ExcludedMembers -Patterns $Config.ExcludedMemberPatterns) { continue }
        if ($Config.AuditorUser -and $name -ieq $Config.AuditorUser) { continue }
        if ([bool](Get-Prop $m 'isPredefinedUser' $false)) { continue }
        $expRaw = Get-Prop $m 'membershipExpiryDate'
        if ($expRaw) {
            $exp = ConvertFrom-Epoch $expRaw
            if ($exp -and $exp -lt (Get-Date).ToUniversalTime()) { Write-Log "Membership of '$name' in '$SafeName' expired - skipped." 'DEBUG'; continue }
        }
        if (-not (Test-MemberHasRequiredPermission $m)) { Write-Log "Member '$name' of '$SafeName' lacks required permissions - skipped." 'DEBUG'; continue }

        $type      = [string](Get-Prop $m 'memberType' 'User')
        $directory = [string](Get-Prop $m 'searchIn' '')
        $mails = @()
        switch -Regex ($type) {
            '^group$' { $mails = @(Resolve-GroupMails -Name $name -Directory $directory) }
            '^role$'  { Write-Log "Member '$name' of '$SafeName' is a Role - not supported, skipped." 'WARN' }
            default   {
                $one = Resolve-UserMail -Name $name -Directory $directory
                if ($one) { $mails = @($one) } else { Write-Log "No e-mail address found for user '$name' (safe '$SafeName', directory '$directory', AD=$($Config.ResolveLdapViaAD)/$($Config.ADProvider), server='$(Resolve-ADServer -Directory $directory -DomainFromName (Split-MemberName $name).Domain)')." 'WARN' }
            }
        }
        foreach ($mail in $mails) {
            $mk = $mail.ToLowerInvariant()
            if ($recipients.ContainsKey($mk)) { if ($recipients[$mk] -notcontains $name) { $recipients[$mk] += $name } }
            else { $recipients[$mk] = @($name) }
        }
    }
    return $recipients
}

# -----------------------------------------------------------------------------
#  State (re-notification throttling)
# -----------------------------------------------------------------------------
function Get-NotifyState {
    if ($Config.ReNotifyEveryDays -le 0 -or -not (Test-Path -LiteralPath $Config.StateFile)) { return @{} }
    try {
        $raw = Get-Content -LiteralPath $Config.StateFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $h = @{}
        if ($raw) { foreach ($p in $raw.PSObject.Properties) { $h[$p.Name] = [string]$p.Value } }
        return $h
    } catch { Write-Log "State file unreadable - starting fresh: $($_.Exception.Message)" 'WARN'; return @{} }
}

function Save-NotifyState {
    param([hashtable]$State, [string[]]$ActiveKeys)
    if ($Config.ReNotifyEveryDays -le 0) { return }
    try {
        $pruned = @{}
        foreach ($k in @($ActiveKeys)) { if ($State.ContainsKey($k)) { $pruned[$k] = $State[$k] } }
        $tmp = $Config.StateFile + '.tmp'
        $pruned | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $tmp -Encoding UTF8
        Move-Item -LiteralPath $tmp -Destination $Config.StateFile -Force
    } catch { Write-Log "Could not write state file: $($_.Exception.Message)" 'WARN' }
}

# -----------------------------------------------------------------------------
#  Reports
# -----------------------------------------------------------------------------
function Write-Report {
    param([AllowEmptyCollection()][object[]]$NonCompliant = @(), [hashtable]$RecipientMap = @{})
    if (-not $Config.ReportDirectory) { return $null }
    try {
        if (-not (Test-Path -LiteralPath $Config.ReportDirectory)) { New-Item -ItemType Directory -Path $Config.ReportDirectory -Force | Out-Null }
        Remove-OldFiles -Directory $Config.ReportDirectory -Filter 'NonCompliant_*.csv' -Days $Config.ReportRetentionDays
        $file = Join-Path $Config.ReportDirectory ('NonCompliant_{0}.csv' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
        $rows = foreach ($a in $NonCompliant) {
            $to = @()
            if ($RecipientMap -and $RecipientMap.ContainsKey($a.Safe)) { $to = @($RecipientMap[$a.Safe].Keys | Sort-Object) }
            [pscustomobject]@{
                Safe = $a.Safe; AccountName = $a.Name; UserName = $a.UserName; Address = $a.Address
                PlatformId = $a.PlatformId; SecretType = $a.SecretType; CpmManaged = $a.CpmManaged; CpmStatus = $a.CpmStatus
                LastChangedUtc = $(if ($a.LastChanged) { $a.LastChanged.ToString('yyyy-MM-dd HH:mm') } else { '' })
                ChangeIntervalDays = $a.ChangeDays
                DueDateUtc = $(if ($a.DueDate) { $a.DueDate.ToString('yyyy-MM-dd HH:mm') } else { '' })
                DaysOverdue = $a.DaysOverdue; Reason = $a.Reasons; Recipients = ($to -join ';'); AccountId = $a.Id
            }
        }
        $rowArr = [object[]]@($rows)
        $rowArr | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        $rowCount = $rowArr.Length
        Write-Log "Report written: $file ($rowCount rows)"
        return $file
    } catch { Write-Log "Could not write report: $($_.Exception.Message)" 'WARN'; return $null }
}

# -----------------------------------------------------------------------------
#  Mail
# -----------------------------------------------------------------------------
function ConvertTo-HtmlSafe { param([string]$s) if ($null -eq $s) { return '' } return [System.Net.WebUtility]::HtmlEncode($s) }

function Format-Date { param($d) if ($d) { return ([datetime]$d).ToLocalTime().ToString('yyyy-MM-dd HH:mm') } return 'never' }

function New-AccountTableHtml {
    param([AllowEmptyCollection()][object[]]$Accounts = @())
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<table style="border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:13px;width:100%"><thead><tr style="background:#1f3b57;color:#fff">')
    foreach ($h in 'Safe','Account name','Username','Address','Platform','Last changed','Interval (days)','Due date','Overdue (days)','CPM','Reason') {
        [void]$sb.Append("<th style=""padding:6px 8px;text-align:left;border:1px solid #ccc"">$h</th>")
    }
    [void]$sb.Append('</tr></thead><tbody>')
    $i = 0
    # DaysOverdue may be $null (never-changed accounts) - normalise before sorting, mixed null/int comparison throws
    $sortKeys = @(
        @{ Expression = { [string]$_.Safe } },
        @{ Expression = { if ($null -eq $_.DaysOverdue) { [int]::MinValue } else { [int]$_.DaysOverdue } }; Descending = $true },
        @{ Expression = { [string]$_.Name } }
    )
    $sorted = New-Object System.Collections.Generic.List[object]
    $Accounts | Sort-Object -Property $sortKeys | ForEach-Object { $sorted.Add($_) }
    $td = '<td style="padding:5px 8px;border:1px solid #ddd">'
    foreach ($a in $sorted) {
        $i++
        $bg = '#ffffff'; if (($i % 2) -eq 0) { $bg = '#f3f6f9' }
        $od = ''; $odStyle = ''
        if ($null -ne $a.DaysOverdue) {
            $od = [string]$a.DaysOverdue
            if ([int]$a.DaysOverdue -ge 0) { $odStyle = 'color:#b00020;font-weight:bold' }
        }
        $cpm = 'manual'
        if ($a.CpmManaged) { $cpm = 'auto'; if ($a.CpmStatus) { $cpm = 'auto/' + [string]$a.CpmStatus } }
        $cells = [string[]]@(
            (ConvertTo-HtmlSafe $a.Safe), (ConvertTo-HtmlSafe $a.Name), (ConvertTo-HtmlSafe $a.UserName), (ConvertTo-HtmlSafe $a.Address),
            (ConvertTo-HtmlSafe $a.PlatformId), (Format-Date $a.LastChanged), ([string]$a.ChangeDays), (Format-Date $a.DueDate)
        )
        [void]$sb.Append('<tr style="background:' + $bg + '">')
        foreach ($v in $cells) { [void]$sb.Append($td + $v + '</td>') }
        [void]$sb.Append('<td style="padding:5px 8px;border:1px solid #ddd;' + $odStyle + '">' + $od + '</td>')
        [void]$sb.Append($td + (ConvertTo-HtmlSafe $cpm) + '</td>')
        [void]$sb.Append($td + (ConvertTo-HtmlSafe $a.Reasons) + '</td>')
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table>')
    return $sb.ToString()
}

function New-UserMailBody {
    <# NOTE: keep here-strings free of $( ... ) sub-expressions - Windows PowerShell 5.1 has a
       compiler bug ("Argument types do not match") with @() / method calls inside them. #>
    param([Parameter(Mandatory)][string]$Recipient, [AllowEmptyCollection()][object[]]$Accounts = @(), [AllowEmptyCollection()][string[]]$ViaMembers = @())
    $count     = [int]$Accounts.Length
    $safeSet   = New-Object System.Collections.Generic.List[string]
    foreach ($acc in $Accounts) { $sn = [string]$acc.Safe; if (-not $safeSet.Contains($sn)) { $safeSet.Add($sn) } }
    $safeSet.Sort()
    $safesHtml = ConvertTo-HtmlSafe ($safeSet.ToArray() -join ', ')
    $pvwaLink  = $Config.PvwaAddress.TrimEnd('/') + '/PasswordVault/'
    $viaSet    = New-Object System.Collections.Generic.List[string]
    foreach ($vm in $ViaMembers) { if ($vm) { $viaSet.Add([string]$vm) } }
    $viaHtml   = ''
    if ($viaSet.Count -gt 0) { $viaHtml = ' (membership via: ' + (ConvertTo-HtmlSafe ($viaSet.ToArray() -join ', ')) + ')' }
    $tableHtml = New-AccountTableHtml -Accounts $Accounts
    $stamp     = (Get-Date).ToString('yyyy-MM-dd HH:mm')
    $hostName  = [string]$env:COMPUTERNAME

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<html><body style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#222">')
    [void]$sb.Append('<p>Hello,</p>')
    [void]$sb.Append("<p>You are receiving this message because you are a member of the following CyberArk safe(s): <b>$safesHtml</b>$viaHtml.</p>")
    [void]$sb.Append("<p>The <b>$count</b> account(s) listed below are <b>not compliant</b> with their platform password policy - the password change interval has been exceeded or is about to be. ")
    [void]$sb.Append("Please change the password (or trigger a CPM change) via the PVWA: <a href=""$pvwaLink"">$pvwaLink</a></p>")
    [void]$sb.Append($tableHtml)
    [void]$sb.Append("<p style=""color:#666;font-size:12px;margin-top:20px"">This is an automated notification generated on $stamp by $hostName. Please do not reply to this message.</p>")
    [void]$sb.Append('</body></html>')
    return $sb.ToString()
}

function Send-Mail {
    param(
        [Parameter(Mandatory)][string[]]$To,
        [string[]]$Cc = @(),
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][string]$HtmlBody,
        [int]$Retries = 2,
        [switch]$IgnoreLimit
    )
    $toTxt = [string]::Join(';', [string[]]@($To))
    $ccTxt = [string]::Join(';', [string[]]@($Cc | Where-Object { $_ }))
    $bodyLen = $HtmlBody.Length
    if ($DryRun) { Write-Log "[DRYRUN] Would send mail To=$toTxt Cc=$ccTxt Subject='$Subject' ($bodyLen chars)"; return $true }
    if (-not $IgnoreLimit -and $Config.MaxMailsPerRun -gt 0 -and $script:MailsSent -ge $Config.MaxMailsPerRun) {
        Write-Log "MaxMailsPerRun ($($Config.MaxMailsPerRun)) reached - mail to $toTxt NOT sent." 'WARN'
        return $false
    }

    $attempt = 0
    while ($true) {
        $attempt++
        $client = $null; $msg = $null
        try {
            $client = New-Object System.Net.Mail.SmtpClient($Config.SmtpServer, $Config.SmtpPort)
            $client.EnableSsl = [bool]$Config.SmtpUseSsl
            $client.Timeout   = 60000
            $client.UseDefaultCredentials = $false
            if ($Config.SmtpAuthenticate) {
                $sc = Get-StoredCredential -Path $Config.SmtpCredentialFile
                $client.Credentials = $sc.GetNetworkCredential()
            }
            $msg = New-Object System.Net.Mail.MailMessage
            $msg.From = New-Object System.Net.Mail.MailAddress($Config.SenderMail, $Config.SenderDisplayName)
            foreach ($t in @($To)) { if (Test-MailAddress $t) { $msg.To.Add($t) } else { Write-Log "Invalid To address '$t' skipped." 'WARN' } }
            foreach ($c in @($Cc)) { if (Test-MailAddress $c) { $msg.CC.Add($c) } else { Write-Log "Invalid Cc address '$c' skipped." 'WARN' } }
            if ($msg.To.Count -eq 0) { throw 'No valid recipient address.' }
            $msg.Subject         = $Subject
            $msg.Body            = $HtmlBody
            $msg.IsBodyHtml      = $true
            $msg.BodyEncoding    = [System.Text.Encoding]::UTF8
            $msg.SubjectEncoding = [System.Text.Encoding]::UTF8
            $client.Send($msg)
            $script:MailsSent++
            Write-Log "Mail sent To=$toTxt Subject='$Subject'"
            return $true
        } catch {
            $inner = $_.Exception; while ($inner.InnerException) { $inner = $inner.InnerException }
            if ($attempt -le $Retries -and $inner -isnot [System.FormatException]) {
                Write-Log "Mail send failed (attempt $attempt): $($inner.Message). Retrying in 10s..." 'WARN'
                Start-Sleep -Seconds 10
                continue
            }
            Write-Log "Mail send FAILED To=${toTxt}: $($inner.Message)" 'ERROR'
            return $false
        } finally {
            if ($msg)    { $msg.Dispose() }
            if ($client) { $client.Dispose() }
        }
    }
}

function Send-AdminMail {
    param([string]$Subject, [string]$HtmlBody)
    try { [void](Send-Mail -To @($Config.AdminMail) -Subject $Subject -HtmlBody $HtmlBody -IgnoreLimit) }
    catch { Write-Log "Admin mail failed: $($_.Exception.Message)" 'ERROR' }
}

# -----------------------------------------------------------------------------
#  Main
# -----------------------------------------------------------------------------
function Invoke-Main {
    Initialize-Logging
    Write-Log '================ CyberArk compliance notification run started ================'
    Merge-ConfigFile

    # --- setup modes ---
    if ($SetCredential)     { Save-StoredCredential -Path $Config.CredentialFile     -Prompt 'PVWA auditor credential' -UserName $Config.AuditorUser; return }
    if ($SetSmtpCredential) { Save-StoredCredential -Path $Config.SmtpCredentialFile -Prompt 'SMTP credential'; return }
    if ($SetADCredential)   {
        $adPath = $Config.ADCredentialFile; if (-not $adPath) { $adPath = "$PSScriptRoot\ad.cred.xml" }
        Save-StoredCredential -Path $adPath -Prompt 'AD/LDAP bind credential (DOMAIN\user or user@domain)'; return
    }

    Test-Configuration
    Initialize-Tls
    if ($Config.ResolveLdapViaAD -and $Config.ADProvider -eq 'LDAP') {
        Add-Type -AssemblyName System.DirectoryServices -ErrorAction SilentlyContinue
        Write-Log "AD provider: LDAP (System.DirectoryServices) server='$($Config.ADServer)' ssl=$($Config.ADUseSsl) port=$($Config.ADPort)"
        if (-not (Test-LdapConnectivity -Server $Config.ADServer)) { $Config.ResolveLdapViaAD = $false }
    }
    elseif ($Config.ResolveLdapViaAD) {
        # The AD module builds the AD: PSDrive on import, which triggers DC discovery and can hang for minutes
        # on hardened servers. ADPS_LoadDefaultDrive=0 disables that; all queries then go to $Config.ADServer.
        Write-Log 'AD provider: ActiveDirectory module (ADWS TCP 9389)'
        if (-not $Config.ADLoadDefaultDrive) { $env:ADPS_LoadDefaultDrive = '0' }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            Import-Module ActiveDirectory -ErrorAction Stop -Verbose:$false
            Write-Log ("ActiveDirectory module loaded in {0:N1}s (ADServer='{1}')." -f $sw.Elapsed.TotalSeconds, $Config.ADServer)
            if ($Config.ADServer) {
                try {
                    $p = @{ ErrorAction = 'Stop'; Server = $Config.ADServer }
                    $null = Get-ADRootDSE @p
                    Write-Log "AD connectivity check OK against '$($Config.ADServer)'."
                } catch {
                    Write-Log "AD server '$($Config.ADServer)' is not reachable via ADWS (TCP 9389): $($_.Exception.Message). AD lookups disabled for this run." 'WARN'
                    $Config.ResolveLdapViaAD = $false
                }
            } else {
                Write-Log 'ADServer is empty - AD cmdlets will auto-discover a DC on first call; set ADServer if lookups are slow or fail.' 'WARN'
            }
        }
        catch { Write-Log "ActiveDirectory module could not be loaded: $($_.Exception.Message)" 'WARN'; $Config.ResolveLdapViaAD = $false }
    }

    # --- collect ---
    Connect-Pvwa
    $platformMap  = Get-PlatformPolicies
    # function output is unrolled by PowerShell - normalise to plain arrays once, here
    $accounts     = [object[]]@(Get-AllAccounts)
    $nonCompliant = [object[]]@(Get-NonCompliantAccounts -Accounts $accounts -PlatformMap $platformMap)

    $summary = [ordered]@{
        TotalAccounts    = $accounts.Length
        NonCompliant     = $nonCompliant.Length
        SafesAffected    = 0
        RecipientsMailed = 0
        MailsFailed      = 0
        Throttled        = 0
        Suppressed       = 0
        UnroutedSafes    = @()
    }
    $perRecipient = @{}   # mail -> @{ Accounts = List; Via = List }
    $onlySafes = [string[]]@($Config.NotifyOnlySafes | Where-Object { $_ })
    $safeRecipients = @{} # safe -> recipients hashtable (for the report)

    if ($nonCompliant.Length -eq 0) {
        Write-Log 'No non-compliant accounts found. Nothing to notify.'
    } else {
        # --- group by safe, resolve recipients ---
        $bySafe = @($nonCompliant | Group-Object Safe)
        $summary.SafesAffected = $bySafe.Count

        foreach ($g in $bySafe) {
            $safe = $g.Name
            Write-Log "Safe '$safe': $($g.Count) non-compliant account(s). Resolving members..."
            try {
                $recips = Get-SafeRecipients -SafeName $safe
            } catch {
                Write-Log "Failed to resolve members of safe '$safe': $($_.Exception.Message)" 'ERROR'
                $summary.UnroutedSafes += $safe
                continue
            }
            $safeRecipients[$safe] = $recips
            if ($recips.Count -eq 0) {
                Write-Log "Safe '$safe' has no notifiable members - accounts will be reported to admins only." 'WARN'
                $summary.UnroutedSafes += $safe
                continue
            }
            Write-Log "Safe '$safe': $($recips.Count) recipient(s): $(($recips.Keys | Sort-Object) -join ', ')"
            foreach ($mail in $recips.Keys) {
                if (-not $perRecipient.ContainsKey($mail)) {
                    $perRecipient[$mail] = @{ Accounts = (New-Object System.Collections.Generic.List[object]); Via = (New-Object System.Collections.Generic.List[string]) }
                }
                foreach ($a in $g.Group) { $perRecipient[$mail].Accounts.Add($a) }
                foreach ($v in $recips[$mail]) { if (-not $perRecipient[$mail].Via.Contains($v)) { $perRecipient[$mail].Via.Add($v) } }
            }
        }

        # --- throttle & send ---
        $state = Get-NotifyState
        $activeKeys = New-Object System.Collections.Generic.List[string]
        $todayStr = (Get-Date).ToString('yyyy-MM-dd')
        if (-not $Config.NotifyAccountOwners) {
            Write-Log 'PILOT MODE: NotifyAccountOwners = $false - owner notifications are suppressed, recipients are listed in the admin summary only.'
        } elseif ($onlySafes.Length -gt 0) {
            Write-Log "Staged rollout: owner notifications restricted to safe(s): $($onlySafes -join ', ')"
        }

        foreach ($mail in ($perRecipient.Keys | Sort-Object)) {
            $entry = $perRecipient[$mail]
            $toSend = New-Object System.Collections.Generic.List[object]
            foreach ($a in $entry.Accounts) {
                # owner-notification gate (pilot mode / staged rollout) - state is NOT touched for suppressed accounts
                if (-not $Config.NotifyAccountOwners) { $summary.Suppressed++; continue }
                if ($onlySafes.Length -gt 0 -and -not (Test-MatchesAny -Value $a.Safe -Exact $onlySafes -Patterns @())) { $summary.Suppressed++; continue }

                $key = "$mail|$($a.Id)"
                $activeKeys.Add($key)
                $send = $true
                if ($Config.ReNotifyEveryDays -gt 0 -and $state.ContainsKey($key)) {
                    try {
                        $last = [datetime]::ParseExact($state[$key], 'yyyy-MM-dd', $null)
                        if (((Get-Date).Date - $last.Date).TotalDays -lt $Config.ReNotifyEveryDays) { $send = $false }
                    } catch { }
                }
                if ($send) { $toSend.Add($a) } else { $summary.Throttled++ }
            }
            if ($toSend.Count -eq 0) { Write-Log "Recipient $mail : nothing to send ($($entry.Accounts.Count) account(s) suppressed or already notified)." 'DEBUG'; continue }

            $body = New-UserMailBody -Recipient $mail -Accounts $toSend.ToArray() -ViaMembers $entry.Via.ToArray()
            $ok = Send-Mail -To @($mail) -Cc @($Config.MailCc) -Subject $Config.MailSubject -HtmlBody $body
            if ($ok) {
                $summary.RecipientsMailed++
                if (-not $DryRun) { foreach ($a in $toSend) { $state["$mail|$($a.Id)"] = $todayStr } }
            } else {
                $summary.MailsFailed++
            }
        }
        if (-not $DryRun) {
            if ($Config.NotifyAccountOwners) { Save-NotifyState -State $state -ActiveKeys @($activeKeys) }
            else { Write-Log 'Pilot mode: notification state file left unchanged.' 'DEBUG' }
        }
    }

    $reportFile = Write-Report -NonCompliant $nonCompliant -RecipientMap $safeRecipients

    # --- admin summary ---
    $hasProblems = ($summary.MailsFailed -gt 0) -or (@($summary.UnroutedSafes).Count -gt 0) -or ($script:Warnings.Count -gt 0)
    if ($Config.SendAdminSummary -or $hasProblems) {
        $unroutedSafeList = [string[]]@($summary.UnroutedSafes)
        $allAccounts      = $nonCompliant
        $unroutedList     = New-Object System.Collections.Generic.List[object]
        foreach ($acc in $allAccounts) { if ($unroutedSafeList -contains $acc.Safe) { $unroutedList.Add($acc) } }
        $unroutedAccounts = $unroutedList.ToArray()
        $warnCount        = [int]$script:Warnings.Count

        $warnHtml = ''
        if ($warnCount -gt 0) {
            $items = [string[]]@($script:Warnings | Select-Object -First 100 | ForEach-Object { '<li>' + (ConvertTo-HtmlSafe $_) + '</li>' })
            $warnHtml = '<h3>Warnings (first 100)</h3><ul>' + [string]::Join('', $items) + '</ul>'
        }
        $unroutedHtml = ''
        if ($unroutedAccounts.Length -gt 0) { $unroutedHtml = '<h3>Non-compliant accounts in safes without notifiable members</h3>' + (New-AccountTableHtml -Accounts $unroutedAccounts) }
        $allHtml = '<p>No non-compliant accounts.</p>'
        if ($allAccounts.Length -gt 0) { $allHtml = '<h3>All non-compliant accounts</h3>' + (New-AccountTableHtml -Accounts $allAccounts) }

        $runStamp   = $script:RunStart.ToString('yyyy-MM-dd HH:mm:ss')
        $hostName   = [string]$env:COMPUTERNAME
        $elapsed    = [int]$script:StopWatch.Elapsed.TotalSeconds
        $dryTag     = ''; if ($DryRun) { $dryTag = ' <b>[DRY RUN]</b>' }
        $modeHtml   = ''
        if (-not $Config.NotifyAccountOwners) {
            $modeHtml = '<p style="background:#fff4ce;border:1px solid #e0b400;padding:8px 12px"><b>PILOT MODE</b> - owner notifications are disabled (NotifyAccountOwners = $false). The "Planned recipients" table shows who would have been notified.</p>'
        } elseif ($onlySafes.Length -gt 0) {
            $modeHtml = '<p style="background:#fff4ce;border:1px solid #e0b400;padding:8px 12px"><b>STAGED ROLLOUT</b> - owner notifications restricted to: ' + (ConvertTo-HtmlSafe ($onlySafes -join ', ')) + '</p>'
        }
        # planned recipients: safe -> recipients -> account count
        $planSb = New-Object System.Text.StringBuilder
        [void]$planSb.Append('<h3>Planned recipients per safe</h3><table style="border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:13px"><thead><tr style="background:#1f3b57;color:#fff">')
        foreach ($h in 'Safe','Non-compliant accounts','Owner mail','Recipients') { [void]$planSb.Append('<th style="padding:6px 8px;text-align:left;border:1px solid #ccc">' + $h + '</th>') }
        [void]$planSb.Append('</tr></thead><tbody>')
        $safeCounts = @{}
        foreach ($acc in $allAccounts) { if ($safeCounts.ContainsKey($acc.Safe)) { $safeCounts[$acc.Safe]++ } else { $safeCounts[$acc.Safe] = 1 } }
        foreach ($sn in ($safeCounts.Keys | Sort-Object)) {
            $rcpts = ''
            if ($safeRecipients.ContainsKey($sn) -and $safeRecipients[$sn].Count -gt 0) { $rcpts = ([string[]]@($safeRecipients[$sn].Keys | Sort-Object)) -join ', ' } else { $rcpts = '(none - admin only)' }
            $ownerMail = 'yes'
            if (-not $Config.NotifyAccountOwners) { $ownerMail = 'no (pilot)' }
            elseif ($onlySafes.Length -gt 0 -and -not (Test-MatchesAny -Value $sn -Exact $onlySafes -Patterns @())) { $ownerMail = 'no (staged)' }
            elseif ($rcpts -like '(none*') { $ownerMail = 'no (no recipients)' }
            [void]$planSb.Append('<tr><td style="padding:5px 8px;border:1px solid #ddd">' + (ConvertTo-HtmlSafe $sn) + '</td><td style="padding:5px 8px;border:1px solid #ddd">' + $safeCounts[$sn] + '</td><td style="padding:5px 8px;border:1px solid #ddd">' + $ownerMail + '</td><td style="padding:5px 8px;border:1px solid #ddd">' + (ConvertTo-HtmlSafe $rcpts) + '</td></tr>')
        }
        [void]$planSb.Append('</tbody></table>')
        $planHtml = ''; if ($allAccounts.Length -gt 0) { $planHtml = $planSb.ToString() }
        $pvwaHtml   = ConvertTo-HtmlSafe $Config.PvwaAddress
        $unroutedTx = ConvertTo-HtmlSafe ([string]::Join(', ', $unroutedSafeList))
        $reportHtml = ConvertTo-HtmlSafe ([string]$reportFile)
        $logHtml    = ConvertTo-HtmlSafe ([string]$script:LogFile)

        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append('<html><body style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#222">')
        [void]$sb.Append('<h2>CyberArk password compliance - run summary</h2>')
        [void]$sb.Append($modeHtml)
        [void]$sb.Append('<table style="font-size:14px">')
        [void]$sb.Append("<tr><td>Run time</td><td>$runStamp on $hostName (${elapsed}s)$dryTag</td></tr>")
        [void]$sb.Append("<tr><td>PVWA</td><td>$pvwaHtml</td></tr>")
        [void]$sb.Append("<tr><td>Accounts scanned</td><td>$($summary.TotalAccounts)</td></tr>")
        [void]$sb.Append("<tr><td>Non-compliant</td><td><b>$($summary.NonCompliant)</b> in $($summary.SafesAffected) safe(s)</td></tr>")
        [void]$sb.Append("<tr><td>Recipients mailed</td><td>$($summary.RecipientsMailed)</td></tr>")
        [void]$sb.Append("<tr><td>Mails failed</td><td>$($summary.MailsFailed)</td></tr>")
        [void]$sb.Append("<tr><td>Notifications throttled</td><td>$($summary.Throttled)</td></tr>")
        [void]$sb.Append("<tr><td>Notifications suppressed (pilot/staged)</td><td>$($summary.Suppressed)</td></tr>")
        [void]$sb.Append("<tr><td>Safes without recipients</td><td>$unroutedTx</td></tr>")
        [void]$sb.Append("<tr><td>Warnings</td><td>$warnCount</td></tr>")
        [void]$sb.Append("<tr><td>Report</td><td>$reportHtml</td></tr></table>")
        [void]$sb.Append($planHtml)
        [void]$sb.Append($unroutedHtml)
        [void]$sb.Append($warnHtml)
        [void]$sb.Append($allHtml)
        [void]$sb.Append("<p style=""color:#666;font-size:12px"">Log file: $logHtml</p></body></html>")
        $adminBody = $sb.ToString()

        $dryTagSubject = ''; if ($DryRun) { $dryTagSubject = ' [DRY RUN]' }
        if (-not $Config.NotifyAccountOwners) { $dryTagSubject += ' [PILOT]' }
        $adminSubject = '{0} - summary ({1} non-compliant, {2} warnings){3}' -f $Config.MailSubject, $summary.NonCompliant, $warnCount, $dryTagSubject
        Send-AdminMail -Subject $adminSubject -HtmlBody $adminBody
    }

    if ($summary.MailsFailed -gt 0 -and $summary.RecipientsMailed -eq 0 -and $perRecipient.Count -gt 0) { $script:ExitCode = 4 }
    elseif ($hasProblems) { $script:ExitCode = 5 }
    Write-Log ("Run finished: {0} accounts, {1} non-compliant, {2} recipients mailed, {3} failed, {4} throttled, {5} suppressed, {6} warnings, exit code {7}." -f `
        $summary.TotalAccounts, $summary.NonCompliant, $summary.RecipientsMailed, $summary.MailsFailed, $summary.Throttled, $summary.Suppressed, $script:Warnings.Count, $script:ExitCode)
}

try {
    Invoke-Main
} catch {
    $ex  = $_.Exception
    $msg = $ex.Message
    $script:ExitCode = if ($msg -like 'CONFIG:*') { 1 } elseif ($msg -like 'AUTH:*') { 2 } else { 3 }
    Write-Log "FATAL ($($ex.GetType().Name)): $msg" 'ERROR'
    Write-Log ('  ' + ($_.ScriptStackTrace -replace "`r?`n", ' <- ')) 'ERROR'
    if ($ex.StackTrace) {
        $netTrace = [string[]]($ex.StackTrace -split "`r?`n")
        $take = [math]::Min(12, $netTrace.Length)
        for ($ti = 0; $ti -lt $take; $ti++) { Write-Log ('  .NET ' + $netTrace[$ti].Trim()) 'ERROR' }
    }
    $adminList = [string[]]@($Config.AdminMail | Where-Object { $_ })
    if ($script:ExitCode -ne 1 -and $adminList.Length -gt 0) {
        $typeHtml  = ConvertTo-HtmlSafe $ex.GetType().Name
        $msgHtml   = ConvertTo-HtmlSafe $msg
        $hostName  = [string]$env:COMPUTERNAME
        $stamp     = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        $logHtml   = ConvertTo-HtmlSafe ([string]$script:LogFile)
        $traceHtml = ConvertTo-HtmlSafe ([string]$_.ScriptStackTrace)
        $body = '<html><body style="font-family:Segoe UI,Arial,sans-serif"><h2 style="color:#b00020">CyberArk compliance notifier FAILED</h2>' +
                "<p><b>$typeHtml</b>: $msgHtml</p><p>Host: $hostName<br/>Time: $stamp<br/>Log: $logHtml</p>" +
                "<pre style=""font-size:11px"">$traceHtml</pre></body></html>"
        $failSubject = $Config.MailSubject + ' - SCRIPT FAILURE'
        try { [void](Send-Mail -To $adminList -Subject $failSubject -HtmlBody $body -Retries 1 -IgnoreLimit) } catch { }
    }
} finally {
    Disconnect-Pvwa
    Write-Log "Exiting with code $script:ExitCode"
}
exit $script:ExitCode
