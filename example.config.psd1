@{
    # Example per-environment override file. Only keys listed here replace the
    # defaults inside the script. Use with:  -ConfigFile .\customer.psd1
    PvwaAddress          = 'https://pvwa.customer.local'
    AuthMethod           = 'CyberArk'          # CyberArk | LDAP | Windows
    AuditorUser          = 'svc_pam_audit'
    CredentialFile       = 'C:\PAM\Notify\pvwa.cred.xml'
    SkipCertificateCheck = $false

    SmtpServer           = 'smtp.customer.local'
    SmtpPort             = 25
    SenderMail           = 'cyberark-noreply@customer.local'
    AdminMail            = @('pam-team@customer.local')
    MailSubject          = '[CyberArk] Accounts requiring password change'

    FallbackMailDomain   = ''                  # e.g. 'customer.local'
    ADProvider           = 'LDAP'                  # LDAP (389/636, no RSAT) or ADModule (RSAT, ADWS 9389)
    ADServer             = 'dc01.customer.local'   # reachable DC or domain FQDN; recommended on hardened CPM/PVWA servers
    ADUseSsl             = $false                  # $true = LDAPS 636
    ADCredentialFile     = ''                      # optional; -SetADCredential when the task account cannot read AD
    ADDomainMap          = @{ 'customer' = 'customer.local' }   # CyberArk directory name -> AD FQDN
    ReNotifyEveryDays    = 1
    MaxMailsPerRun       = 500

    # Rollout control
    NotifyAccountOwners  = $false              # phase 1: $false = admins only (pilot); flip to $true to start mailing owners
    NotifyOnlySafes      = @()                 # phase 2 (optional): @('PAM-Team-Safe','Win-Admins-Safe') = mail owners of these safes only
                                               # phase 3: @() = everyone

    LogDirectory         = 'C:\PAM\Notify\Logs'
    ReportDirectory      = 'C:\PAM\Notify\Reports'
    StateFile            = 'C:\PAM\Notify\notify-state.json'
}
