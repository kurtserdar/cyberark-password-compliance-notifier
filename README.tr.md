# CyberArk Parola Uyumluluk Bildirimi

[English](README.md) | **Türkçe**

**CyberArk PAM Self-Hosted** için tek dosyalık bir PowerShell script'i. PVWA REST API üzerinden kasadaki tüm hesapları tarar, platformunda tanımlı parola değiştirme süresini aşmış (uyumsuz / non-compliant) hesapları bulur, bu hesapların bulunduğu safe'lerin üyelerini e-posta adreslerine çözer ve **her alıcıya tek bir birleşik mail** gönderir. Yöneticilere tam listeyle bir özet maili gider, her çalıştırmada CSV rapor yazılır.

Herhangi bir kurumda kullanılmak üzere tasarlandı: yapılandırma bloğunu düzenleyin (ya da müşteri başına bir `.psd1` dosyası verin), parolaları bir kez kaydedin, Windows Görev Zamanlayıcı ile zamanlayın.

## Özellikler

- **Platform bazlı uyumluluk kontrolü** – her platformun *Require password change every X days* değeri kullanılır; hiç değiştirilmemiş hesaplar oluşturulma tarihinden hesaplanır. İsteğe bağlı erken uyarı (`NotifyDaysBeforeDue`) ve CPM hatası raporlama.
- **Alıcı çözümleme** – yapılandırılan yetkilerden birine sahip safe üyeleri (varsayılan: Retrieve / Use / Update / Manage Safe). Kullanıcılar ve **iç içe gruplar** düz **LDAP (389/636, RSAT gerekmez)**, Vault kullanıcı kaydı ya da `kullanici@domain` fallback'i ile adrese çözülür.
- **Mail fırtınası yok** – kişi başına, tüm safe'lerini kapsayan tek mail; alıcı+hesap bazında tekrar bildirim sınırı (`ReNotifyEveryDays`); çalıştırma başına üst sınır (`MaxMailsPerRun`).
- **Kademeli açılış** – `NotifyAccountOwners = $false` (pilot: sadece adminler, *planlanan alıcılar* tablosuyla) ve `NotifyOnlySafes` (yalnızca seçili safe'lerin sahiplerine mail).
- **Admin özeti** – sayaçlar, alıcısı olmayan safe'ler, uyarılar, tam hesap tablosu, CSV raporunun yolu. Ölümcül hatalarda ayrı bir hata maili.
- **Sağlam** – parolalar DPAPI ile şifreli (`-SetCredential`, `-SetSmtpCredential`, `-SetADCredential`), TLS 1.2/1.3, 401'de otomatik yeniden giriş, 429/5xx'te üstel geri çekilmeli tekrar, `nextLink` sayfalama, Görev Zamanlayıcı için anlamlı exit code'lar, log rotasyonu.
- **Taşınabilir** – Windows PowerShell 5.1 ve PowerShell 7; PAM Self-Hosted 11.x – 14.x (v2 endpoint'ler, eski sürümler için fallback).

## Nasıl çalışır

```
PVWA girişi (CyberArk / LDAP / Windows auth)
   └─ Platforms/Targets ............ platform başına değişim süresi
   └─ Accounts (sayfalı) ........... lastModifiedTime + süre < bugün → uyumsuz
        └─ safe'e göre grupla
             └─ Safes/{safe}/Members  (yetki ve hariç tutma filtreleri)
                  └─ Kullanıcı → LDAP mail / Vault kaydı / fallback domain
                  └─ Grup      → LDAP iç içe üyeler → mail
   └─ alıcı başına tek HTML mail (sınırlı, üst limitli)
   └─ CSV rapor + admin özet maili
```

## Gereksinimler

| Öğe | Not |
|---|---|
| PowerShell 5.1+ olan Windows Server | PowerShell 7 de çalışır |
| Ağ | PVWA (443), SMTP, domain controller LDAP (389 ya da LDAPS için 636) |
| CyberArk kullanıcısı | Yerleşik **Auditors** grubunun üyesi (salt okunur; tüm safe'leri görür). Başka bir kullanıcı yalnızca *List* yetkisi olduğu safe'leri görür. |
| Task hesabı | Bir domain hesabı; LDAP'a entegre kimlik doğrulama için kullanılır. RSAT / ActiveDirectory modülü gerekmez. |
| SMTP | Anonim relay ya da kimlik doğrulamalı (STARTTLS desteklenir) |

## Hızlı başlangıç

1. `Send-CyberArkComplianceNotification.ps1` dosyasını sunucuya kopyalayın (örn. `C:\PAM\Notify\`).
2. Script'in başındaki `$Config` bloğunu düzenleyin **ya da** `example.config.psd1` dosyasını kopyalayıp doldurun ve `-ConfigFile` ile verin.
3. Parolaları **zamanlanmış görevi çalıştıracak Windows hesabıyla** kaydedin (DPAPI dosyayı kullanıcı + makineye bağlar):

   ```powershell
   powershell.exe -ExecutionPolicy Bypass -File .\Send-CyberArkComplianceNotification.ps1 -SetCredential       # PVWA auditor kullanıcısı
   powershell.exe -ExecutionPolicy Bypass -File .\Send-CyberArkComplianceNotification.ps1 -SetSmtpCredential   # sadece SmtpAuthenticate = $true ise
   ```

4. Prova çalıştırma – mail gönderilmez, her şey log'a ve CSV rapora yazılır:

   ```powershell
   powershell.exe -ExecutionPolicy Bypass -File .\Send-CyberArkComplianceNotification.ps1 -DryRun -Verbose
   ```

5. Gerçek çalıştırma:

   ```powershell
   powershell.exe -ExecutionPolicy Bypass -File .\Send-CyberArkComplianceNotification.ps1 [-ConfigFile .\musteri.psd1]
   ```

6. Görev Zamanlayıcı: *Program* `powershell.exe`, *Argümanlar* `-ExecutionPolicy Bypass -NonInteractive -File C:\PAM\Notify\Send-CyberArkComplianceNotification.ps1`, 3. adımdaki hesapla, *Run whether user is logged on or not*.

## Önerilen açılış planı

| Faz | Ayar | Etki |
|---|---|---|
| 1 – Pilot | `NotifyAccountOwners = $false` | Tam tarama, alıcılar çözülür, **sadece adminlere** mail. Özette *Planned recipients per safe* tablosu kime gidecek olduğunu gösterir. |
| 2 – Kademeli | `NotifyAccountOwners = $true`, `NotifyOnlySafes = @('Safe-A','Safe-B')` | Listedeki safe'lerin sahiplerine mail gider; kalanlar admin özetinde kalır. |
| 3 – Tam | `NotifyOnlySafes = @()` | Herkese. |

Sahip mailleri bastırılırken bildirim durum dosyasına dokunulmaz; ilk gerçek mail her zaman tam listeyi taşır.

## Yapılandırma referansı

Tüm anahtarlar `$Config` bloğundadır; herhangi biri `.psd1` dosyasından (`-ConfigFile`) ezilebilir.

### PVWA
| Anahtar | Varsayılan | Açıklama |
|---|---|---|
| `PvwaAddress` | – | `https://pvwa.example.com` (`/PasswordVault` olmadan) |
| `AuthMethod` | `CyberArk` | `CyberArk`, `LDAP` ya da `Windows` (IIS entegre auth, credential dosyası gerekmez) |
| `AuditorUser` | – | Vault/LDAP kullanıcı adı |
| `CredentialFile` | `pvwa.cred.xml` | `-SetCredential` ile oluşturulan DPAPI dosyası |
| `SkipCertificateCheck` | `$false` | Sadece lab |
| `ApiPageSize` / `ApiTimeoutSec` / `ApiRetryCount` / `ApiCallDelayMs` | 500 / 120 / 3 / 0 | Büyük ortamlar için ayar |

### Kapsam
| Anahtar | Açıklama |
|---|---|
| `IncludedSafes` | Doluysa yalnızca bu safe'ler |
| `ExcludedSafes`, `ExcludedSafePatterns` | Tam ad ve regex; varsayılanlar CyberArk sistem safe'lerini kapsar |
| `ExcludedPlatforms` | Yok sayılacak platform ID'leri |
| `OnlyCpmManagedAccounts` | Otomatik yönetimi kapalı hesapları atla |
| `IncludeCpmFailures` | Son CPM işlemi başarısız olan hesapları da raporla |
| `DefaultChangeDays` | Platformda süre yoksa kullanılır (0 = bu hesapları atla) |
| `NotifyDaysBeforeDue` | Süre dolmadan N gün önce uyar |

### Alıcılar / Active Directory
| Anahtar | Varsayılan | Açıklama |
|---|---|---|
| `RequiredPermissions` | Retrieve, Use, Update, ManageSafe | Üyenin bunlardan *herhangi biri* olmalı |
| `ExcludedMembers`, `ExcludedMemberPatterns` | CyberArk yerleşikleri | Asla bildirilmeyecek üyeler |
| `ResolveLdapViaAD` | `$true` | Kullanıcı/grupları AD'de çöz |
| `ADProvider` | `LDAP` | `LDAP` (System.DirectoryServices, 389/636) ya da `ADModule` (RSAT, ADWS 9389) |
| `ADServer` | `''` | DC ya da domain FQDN. **Sıkılaştırılmış sunucularda mutlaka doldurun.** |
| `ADUseSsl`, `ADPort`, `ADSearchBase`, `ADTimeoutSec` | – | LDAPS, Global Catalog (3268), base DN, sorgu zaman aşımı |
| `ADCredentialFile` | `''` | Yalnızca task hesabı AD'yi okuyamıyorsa (`-SetADCredential`) |
| `ADDomainMap` | `@{}` | CyberArk dizin adı → AD FQDN (çok domain) |
| `ExpandGroups`, `MaxGroupMembers` | `$true`, 200 | İç içe grup açma ve emniyet sınırı |
| `FallbackMailDomain` | `''` | Mail attribute yoksa `kullanici@domain` |

### Mail / açılış
| Anahtar | Varsayılan | Açıklama |
|---|---|---|
| `SmtpServer`, `SmtpPort`, `SmtpUseSsl`, `SmtpAuthenticate`, `SmtpCredentialFile` | – | STARTTLS için `SmtpUseSsl` |
| `SenderMail`, `SenderDisplayName`, `MailSubject`, `MailCc` | – | |
| `AdminMail`, `SendAdminSummary` | – | Özet alıcıları; `$false` = yalnızca sorun varsa |
| `NotifyAccountOwners` | `$true` | `$false` = pilot modu |
| `NotifyOnlySafes` | `@()` | Kademeli açılış |
| `ReNotifyEveryDays` | 1 | Alıcı + hesap bazında tekrar bildirim sınırı (0 = her zaman) |
| `MaxMailsPerRun` | 500 | Üst sınır (admin mailleri muaf) |
| `StateFile`, `LogDirectory`, `LogRetentionDays`, `ReportDirectory`, `ReportRetentionDays` | – | Bakım |

## Exit code'lar

| Kod | Anlamı |
|---|---|
| 0 | Başarılı |
| 1 | Yapılandırma / ön koşul hatası |
| 2 | PVWA kimlik doğrulama hatası |
| 3 | PVWA API ya da beklenmeyen ölümcül hata |
| 4 | Mail iletim hatası (hiçbir mail gönderilemedi) |
| 5 | Uyarılarla tamamlandı (bazı alıcı/hesaplar atlandı) |

## Sorun giderme

| Belirti | Sebep / çözüm |
|---|---|
| `LDAP connectivity FAILED ... An operations error occurred` | Bind anonim. Görevi domain hesabıyla çalıştırın; boş `ADCredentialFile` vermeyin. Entegre auth için v3.2'de düzeltildi. |
| `ADProvider = 'ADModule'` ile `Configuration OK` sonrası takılma | Sıkılaştırılmış sunucularda `Import-Module ActiveDirectory` takılır (DC keşfi / ADWS 9389 / CRL kontrolü). `ADProvider = 'LDAP'` (varsayılan) kullanın. |
| `No e-mail address found for user 'x'` | Kullanıcının `mail` attribute'u ve geçerli UPN'i yok; `FallbackMailDomain` verin ya da AD'yi düzeltin. Kullanılan LDAP filtresini görmek için `-Verbose`. |
| `Safe 'x' has no notifiable members` | Üyeler hariç tutulmuş (yerleşikler), gerekli yetkiye sahip değil ya da çözülemedi. Hesaplar admin özetinde listelenir. |
| `Mailbox unavailable. Unknown user` | SMTP sunucusu alıcı adresini reddediyor (lab'larda tipik). |
| `Credential file ... not found` | `-SetCredential` komutunu **aynı makinede, task hesabıyla** çalıştırın. |
| `Retrieved N accounts` beklenenden düşük | Auditor kullanıcısının bazı safe'lerde *List* yetkisi yok; **Auditors** grubuna ekleyin. |

## Güvenlik notları

- Script CyberArk'a karşı **salt okunurdur**; parola ya da hesap değiştirmez.
- Parolalar Windows DPAPI ile, task hesabı ve makineye bağlı olarak saklanır; başka yerde okunamaz.
- Üretimde `SkipCertificateCheck = $false` kalsın; bunun yerine PVWA sertifika zincirini sunucuda güvenilir yapın.
- `.gitignore` credential, log, rapor ve durum dosyalarını dışlar – asla commit etmeyin.

## Katkı

Issue ve pull request'ler memnuniyetle karşılanır. Issue'lara eklenen loglarda müşteri adı, sunucu adı ya da e-posta adresi bulundurmayın.

## Lisans

MIT – bkz. [LICENSE](LICENSE).
