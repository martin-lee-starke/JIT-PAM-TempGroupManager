# PLAN: Temporäre AD-Gruppenmitgliedschaften einrichten

> Basierend auf Microsoft Docs (Stand: April 2026)  
> Quellen: [Add-ADGroupMember](https://learn.microsoft.com/en-us/powershell/module/activedirectory/add-adgroupmember), [Enable-ADOptionalFeature](https://learn.microsoft.com/en-us/powershell/module/activedirectory/enable-adoptionalfeature), [MIM PAM Overview](https://learn.microsoft.com/en-us/microsoft-identity-manager/pam/privileged-identity-management-for-active-directory-domain-services)

---

## 1. Überblick: Zwei verschiedene Ansätze

Microsoft bietet zwei unterschiedliche PAM-Konzepte. Es ist wichtig, diese nicht zu verwechseln:

| Ansatz | Beschreibung | Empfehlung |
|---|---|---|
| **Native AD TTL-Mitgliedschaft** | AD-Optionales Feature in Windows Server 2016+, ein Cmdlet-Parameter. Kein zusätzlicher Server nötig. | ✅ Unser Ansatz |
| **MIM PAM (Microsoft Identity Manager)** | Vollständige Enterprise-Lösung mit Bastion-Forest, MIM-Server, Workflows. Sehr komplex. | Nur für isolierte Hochsicherheitsumgebungen ohne Internet |

> **Hinweis aus den Docs:** MIM PAM ist laut Microsoft **nicht empfohlen** für neue Deployments in internetverbundenen Umgebungen. Der native AD-TTL-Ansatz ist für die meisten On-Premises-Domains der richtige Weg.

---

## 2. Voraussetzungen

### 2.1 Domain Functional Level (DFL)

Der wichtigste Blocker: Das AD PAM Feature (und damit `-MemberTimeToLive`) benötigt **Windows Server 2016 Domain Functional Level** oder höher.

**Aktuellen DFL und FFL prüfen:**
```powershell
# Domain Functional Level anzeigen
(Get-ADDomain).DomainMode

# Forest Functional Level anzeigen
(Get-ADForest).ForestMode
```

**Mögliche Ausgaben und Bedeutung:**

| Wert | Bedeutung |
|---|---|
| `Windows2016Domain` / `7` | ✅ Kompatibel, PAM Feature nutzbar |
| `Windows2012R2Domain` / `6` | ❌ Zu alt, DFL muss angehoben werden |
| `Windows2012Domain` / `5` | ❌ Zu alt |
| `Windows2008R2Domain` / `4` | ❌ Zu alt |

**DFL anheben** (nur wenn nötig – NICHT rückgängig zu machen!):
```powershell
# Alle DCs müssen mindestens Windows Server 2016 laufen, bevor DFL angehoben wird!
# DFL auf 2016 anheben
Set-ADDomainMode -Identity "contoso.local" -DomainMode Windows2016Domain

# FFL auf 2016 anheben (optional, aber empfohlen)
Set-ADForestMode -Identity "contoso.local" -ForestMode Windows2016Forest
```

> ⚠️ **Warnung:** Das Anheben des DFL/FFL ist **irreversibel**. Vor dem Anheben sicherstellen, dass **alle** Domain Controller mindestens Windows Server 2016 laufen. Vorher ein AD-Backup erstellen!

### 2.2 FSMO-Rolleninhaber identifizieren

Das Aktivieren des PAM Features muss auf dem DC ausgeführt werden, der die **Domain Naming Master FSMO-Rolle** innehat (laut Microsoft Docs: "This operation must be performed on the domain controller that holds the domain naming master FSMO role").

```powershell
# Domain Naming Master (= wo Enable-ADOptionalFeature ausgeführt werden muss)
(Get-ADForest).DomainNamingMaster

# Alle FSMO-Rollen anzeigen
netdom query fsmo
```

### 2.3 Benötigte Berechtigungen

- Zum **Aktivieren des PAM Features**: Mitglied der Gruppe `Enterprise Admins` (Forest-weite Änderung)
- Zum **Hinzufügen/Entfernen von Mitgliedern**: `Write-Member`-Berechtigung auf der Zielgruppe (oder `Domain Admins`)
- Zum **Lesen von TTL-Mitgliedschaften**: Leseberechtigung auf die Gruppe

### 2.4 RSAT auf dem Admin-Rechner installieren

Das `ActiveDirectory` PowerShell-Modul muss auf dem Rechner vorhanden sein, von dem aus das Tool gestartet wird:

```powershell
# Windows 10/11 – als Administrator ausführen
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0

# Alternative: Über Windows Features (GUI)
# Einstellungen → Apps → Optionale Features → "RSAT: Active Directory Domain Services..."

# Prüfen ob Modul verfügbar ist
Get-Module -ListAvailable ActiveDirectory
```

---

## 3. Schritt-für-Schritt: AD PAM Feature aktivieren

### Schritt 1: Status prüfen (ist das Feature bereits aktiv?)

```powershell
# Auf jedem Domain-Mitgliedsrechner ausführbar
Get-ADOptionalFeature -Filter { Name -eq 'Privileged Access Management Feature' }
```

**Ausgabe wenn NICHT aktiv:**
```
DistinguishedName : CN=Privileged Access Management Feature,CN=Optional Features,...
EnabledScopes     : {}           # <-- leere Liste = nicht aktiv
FeatureGUID       : ec43ad02-...
Name              : Privileged Access Management Feature
```

**Ausgabe wenn AKTIV:**
```
DistinguishedName : CN=Privileged Access Management Feature,CN=Optional Features,...
EnabledScopes     : {CN=Partitions,CN=Configuration,DC=contoso,DC=local}  # <-- nicht leer
FeatureGUID       : ec43ad02-...
Name              : Privileged Access Management Feature
```

**Als Ja/Nein-Abfrage:**
```powershell
$feature = Get-ADOptionalFeature -Filter { Name -eq 'Privileged Access Management Feature' }
if ($feature.EnabledScopes.Count -gt 0) {
    Write-Host "PAM Feature ist AKTIV" -ForegroundColor Green
} else {
    Write-Host "PAM Feature ist NICHT aktiv" -ForegroundColor Red
}
```

### Schritt 2: Feature aktivieren

> Dieser Befehl muss **auf dem Domain Naming Master DC** oder per `-Server` Parameter gegen diesen DC ausgeführt werden. Als **Enterprise Admin**.

```powershell
# Variante A: Direkt auf dem Domain Naming Master DC ausführen
Enable-ADOptionalFeature `
    -Identity 'Privileged Access Management Feature' `
    -Scope ForestOrConfigurationSet `
    -Target 'contoso.local'

# Variante B: Von einem beliebigen Rechner aus, DC explizit angeben
Enable-ADOptionalFeature `
    -Identity 'Privileged Access Management Feature' `
    -Scope ForestOrConfigurationSet `
    -Target 'contoso.local' `
    -Server 'dc01.contoso.local'

# Mit Bestätigungsabfrage (für Produktion empfohlen)
Enable-ADOptionalFeature `
    -Identity 'Privileged Access Management Feature' `
    -Scope ForestOrConfigurationSet `
    -Target 'contoso.local' `
    -Confirm
```

**Parameter-Erklärung:**

| Parameter | Wert | Bedeutung |
|---|---|---|
| `-Identity` | `'Privileged Access Management Feature'` | Name des Features (exakt so) |
| `-Scope` | `ForestOrConfigurationSet` | Forest-weite Aktivierung |
| `-Target` | FQDN der Domain / Forest | z.B. `contoso.local` |
| `-Server` | DC-Name oder IP | Sollte der Domain Naming Master sein |

> ⚠️ **Wichtig:** Das Aktivieren des Features ist **nicht rückgängig zu machen**. Es gibt kein `Disable-ADOptionalFeature` für PAM.

### Schritt 3: Aktivierung bestätigen

```powershell
# Kurze Prüfung
$f = Get-ADOptionalFeature -Filter { Name -eq 'Privileged Access Management Feature' }
$f.EnabledScopes  # Sollte jetzt einen Eintrag enthalten

# Detailliertere Prüfung
Get-ADOptionalFeature -Identity 'Privileged Access Management Feature' -Properties *
```

### Schritt 4: Replikation abwarten

Das Feature wird forest-weit repliziert. In größeren Umgebungen mit mehreren DCs kurz warten oder Replikation erzwingen:

```powershell
# Replikation sofort anstoßen
repadmin /syncall /AdeP

# Replikationsstatus prüfen
repadmin /showrepl
```

---

## 4. Verwendung: Temporäre Mitgliedschaften verwalten

Nach der Aktivierung stehen folgende Cmdlets zur Verfügung:

### 4.1 Benutzer mit Ablaufzeit hinzufügen

```powershell
# Für 4 Stunden
Add-ADGroupMember `
    -Identity "ServerAdmins" `
    -Members "max.muster" `
    -MemberTimeToLive (New-TimeSpan -Hours 4)

# Für 2 Tage
Add-ADGroupMember `
    -Identity "VPN-Users" `
    -Members "anna.schmidt" `
    -MemberTimeToLive (New-TimeSpan -Days 2)

# Für 30 Minuten (Test)
Add-ADGroupMember `
    -Identity "TestGroup" `
    -Members "testuser" `
    -MemberTimeToLive (New-TimeSpan -Minutes 30)

# Mit Distinguished Name (präziser)
Add-ADGroupMember `
    -Identity "CN=ServerAdmins,OU=Groups,DC=contoso,DC=local" `
    -Members "CN=Max Muster,OU=Users,DC=contoso,DC=local" `
    -MemberTimeToLive (New-TimeSpan -Hours 8)

# Mehrere Benutzer gleichzeitig
Add-ADGroupMember `
    -Identity "TempAccess" `
    -Members "user1","user2","user3" `
    -MemberTimeToLive (New-TimeSpan -Hours 2)
```

**New-TimeSpan Optionen:**

```powershell
New-TimeSpan -Minutes 30      # 30 Minuten
New-TimeSpan -Hours 4         # 4 Stunden
New-TimeSpan -Days 1          # 1 Tag
New-TimeSpan -Hours 8 -Minutes 30  # 8h 30min
(Get-Date "18:00") - (Get-Date)    # Bis heute 18:00 Uhr
```

### 4.2 TTL-Mitgliedschaften einer Gruppe anzeigen

```powershell
# Alle Mitglieder mit TTL anzeigen (inkl. verbleibende Sekunden)
Get-ADGroup -Identity "ServerAdmins" -Properties member -ShowMemberTimeToLive |
    Select-Object -ExpandProperty member

# Ausgabeformat:
# <TTL=14397,CN=Max Muster,OU=Users,DC=contoso,DC=local>  ← TTL-Mitglied (Sekunden verbleibend)
# CN=Domain Admins,CN=Users,DC=contoso,DC=local            ← normales dauerhaftes Mitglied
```

**TTL-Mitglieder übersichtlich auflisten:**
```powershell
function Get-TTLGroupMembers {
    param([string]$GroupName)
    
    $group = Get-ADGroup -Identity $GroupName -Properties member -ShowMemberTimeToLive
    $group.member | ForEach-Object {
        if ($_ -match '^<TTL=(\d+),(.+)>$') {
            $ttlSec = [int]$Matches[1]
            $dn     = $Matches[2]
            $user   = Get-ADUser -Identity $dn -Properties DisplayName
            [PSCustomObject]@{
                Benutzer   = $user.DisplayName
                Konto      = $user.SamAccountName
                VerbleibendSekunden = $ttlSec
                LäuftAbUm  = (Get-Date).AddSeconds($ttlSec).ToString("dd.MM.yyyy HH:mm")
            }
        }
    }
}

Get-TTLGroupMembers -GroupName "ServerAdmins" | Format-Table -AutoSize
```

### 4.3 Alle temporären Mitgliedschaften domain-weit finden

```powershell
# Alle Gruppen mit TTL-Mitgliedern auflisten (langsam bei vielen Gruppen)
Get-ADGroup -Filter * -Properties member -ShowMemberTimeToLive | ForEach-Object {
    $group = $_
    $ttlMembers = $group.member | Where-Object { $_ -match '^<TTL=' }
    if ($ttlMembers) {
        foreach ($m in $ttlMembers) {
            if ($m -match '^<TTL=(\d+),(.+)>$') {
                [PSCustomObject]@{
                    Gruppe     = $group.Name
                    MitgliedDN = $Matches[2]
                    TTL_Sek    = [int]$Matches[1]
                    LäuftAb    = (Get-Date).AddSeconds([int]$Matches[1])
                }
            }
        }
    }
}
```

### 4.4 Mitglied manuell (vorzeitig) entfernen

```powershell
# Normale Entfernung (mit Bestätigungsabfrage)
Remove-ADGroupMember -Identity "ServerAdmins" -Members "max.muster"

# Ohne Bestätigungsabfrage (für Scripts)
Remove-ADGroupMember -Identity "ServerAdmins" -Members "max.muster" -Confirm:$false
```

---

## 5. Technische Hintergründe

### 5.1 Wie funktioniert die automatische Entfernung?

Laut Microsoft Docs:

> "an expired link is evaluated in real time by the Security Accounts Manager (SAM). Even though the **addition** of a group member needs to be replicated by the DC that receives the access request, the **removal** of a group member is evaluated instantaneously on any DC."

Das bedeutet:
- **Hinzufügen**: Wird über AD-Replikation verteilt → es gibt eine kurze Replikationslatenz (~15 Sekunden bis Minuten je nach Topologie)
- **Ablauf/Entfernen**: Wird vom SAM in Echtzeit auf jedem DC ausgewertet → sofort wirksam ohne Replikation

Der abgelaufene Link wird beim nächsten Zugriffsversuch des Benutzers erkannt. Es läuft **kein** Scheduled Task oder Hintergrundprozess – der SAM prüft den TTL beim Token-/Kerberos-Request.

### 5.2 Kerberos und Token-Lifetime

Ein bereits ausgestelltes Kerberos-Ticket (TGT) des Benutzers ist noch für dessen Lifetime gültig (~10 Stunden Standard). Das bedeutet:

- Wenn ein Benutzer bereits eingeloggt ist und ein Token für die Ressource hat, verliert er den Zugriff erst beim **nächsten Login oder Token-Renewal**
- Für sofortige Wirkung: Benutzer abmelden oder `klist purge` ausführen

```powershell
# Kerberos-Tickets des Benutzers auf seinem Rechner leeren (als der Benutzer ausführen)
klist purge

# Oder erzwungener Token-Reset (als Admin)
Invoke-Command -ComputerName "user-pc" -ScriptBlock { klist purge }
```

### 5.3 Wie wird der TTL im AD gespeichert?

Technisch wird die TTL im `member`-Attribut der Gruppe als spezielles DN-Format gespeichert:
```
<TTL=14400,CN=Max Muster,OU=Users,DC=contoso,DC=local>
```

- `TTL=14400` = verbleibende Sekunden (dynamisch, zählt auf jedem DC herunter)
- Der Rest ist der normale Distinguished Name des Mitglieds
- Ohne `-ShowMemberTimeToLive` werden nur normale DNs angezeigt

---

## 6. Gruppentypen und -bereiche (Referenz)

TTL-Mitgliedschaften funktionieren mit allen AD-Gruppentypen. Zur Referenz:

| Gruppenbereich | Mitglieder aus | Verwendbar in |
|---|---|---|
| **Domain Local** | Alle Domains, Universal- und Global-Gruppen | Nur der eigenen Domain |
| **Global** | Nur der eigenen Domain | Alle Domains im Forest |
| **Universal** | Alle Domains im Forest | Alle Domains im Forest |

| Gruppenkategorie | Verwendung |
|---|---|
| **Security** | Zugriffssteuerung (ACLs), Gruppenrichtlinien |
| **Distribution** | E-Mail-Verteilerlisten (kein Sicherheitskontext) |

> Für temporäre Zugriffssteuerung immer **Security**-Gruppen verwenden.

---

## 7. Logging und Auditing

### 7.1 Windows Event Log

AD-Gruppenänderungen werden im Sicherheitsprotokoll der Domain Controller geloggt:

```powershell
# Events auf dem DC auslesen
Get-EventLog -LogName Security -InstanceId 4728,4729,4732,4733 -Newest 50 |
    Select-Object TimeGenerated, EventID, Message | Format-List
```

**Relevante Event IDs:**

| Event ID | Bedeutung |
|---|---|
| `4728` | Mitglied zu globaler Sicherheitsgruppe hinzugefügt |
| `4729` | Mitglied aus globaler Sicherheitsgruppe entfernt |
| `4732` | Mitglied zu lokaler Sicherheitsgruppe hinzugefügt |
| `4733` | Mitglied aus lokaler Sicherheitsgruppe entfernt |
| `4756` | Mitglied zu universeller Sicherheitsgruppe hinzugefügt |
| `4757` | Mitglied aus universeller Sicherheitsgruppe entfernt |

### 7.2 Auditing aktivieren (falls noch nicht aktiv)

Damit die Events tatsächlich geloggt werden, muss Auditing auf den DCs konfiguriert sein:

```powershell
# Per GPO: Computer Configuration > Policies > Windows Settings >
#   Security Settings > Advanced Audit Policy Configuration >
#   Account Management > Audit Security Group Management = Success, Failure

# Oder via Befehlszeile auf dem DC:
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable

# Status prüfen
auditpol /get /subcategory:"Security Group Management"
```

---

## 8. Bekannte Einschränkungen (aus den Microsoft Docs)

1. **Read-Only Domain Controller (RODC):** `Add-ADGroupMember` und `Enable-ADOptionalFeature` funktionieren **nicht** mit RODCs. Immer gegen einen beschreibbaren DC ausführen.

2. **AD-Snapshots:** Die Cmdlets funktionieren **nicht** gegen AD-Snapshots.

3. **Kerberos-Token-Latenz:** Bereits ausgestellte Tokens bleiben bis zu ihrem Ablauf gültig (~10h). Sofortige Wirkung nur durch Token-Purge.

4. **Replikationslatenz beim Hinzufügen:** Neue Mitgliedschaft muss erst auf alle DCs repliziert werden, bevor der Benutzer überall Zugriff hat.

5. **Feature nicht deaktivierbar:** Das PAM Feature kann nach der Aktivierung nicht mehr deaktiviert werden.

6. **MemberTimeToLive Minimum:** Laut Docs muss der Wert > 0 sein. Negativ oder 0 wird nicht akzeptiert.

7. **Gruppen-Nesting mit TTL:** TTL-Mitgliedschaften funktionieren, wenn ein Benutzer direkt einer Gruppe hinzugefügt wird. Beim verschachtelten Nesting (Gruppe A in Gruppe B) wird die TTL der äußeren Mitgliedschaft berücksichtigt.

---

## 9. Troubleshooting

### Problem: `Add-ADGroupMember -MemberTimeToLive` schlägt fehl

```
Add-ADGroupMember: The server does not support the control
```
**Ursache:** PAM Feature ist nicht aktiviert oder der DC unterstützt kein Windows Server 2016 DFL.  
**Lösung:** Schritte 1–3 dieser Anleitung durchführen.

---

### Problem: TTL-Mitgliedschaften werden in `Get-ADGroup` nicht angezeigt

**Symptom:** `Get-ADGroup -Properties member` zeigt keine Benutzer, obwohl sie hinzugefügt wurden.  
**Ursache:** Ohne `-ShowMemberTimeToLive` werden TTL-Mitglieder ausgeblendet.  
**Lösung:**
```powershell
# Falsch:
Get-ADGroup "ServerAdmins" -Properties member

# Richtig:
Get-ADGroup "ServerAdmins" -Properties member -ShowMemberTimeToLive
```

---

### Problem: Feature-Aktivierung schlägt fehl

```
Enable-ADOptionalFeature: The operation failed because the DC is not the Domain Naming Master
```
**Lösung:** Den Befehl direkt auf dem Domain Naming Master ausführen oder `-Server` angeben:
```powershell
$namingMaster = (Get-ADForest).DomainNamingMaster
Enable-ADOptionalFeature `
    -Identity 'Privileged Access Management Feature' `
    -Scope ForestOrConfigurationSet `
    -Target 'contoso.local' `
    -Server $namingMaster
```

---

### Problem: Keine Berechtigung

```
Enable-ADOptionalFeature: Insufficient access rights to perform the operation
```
**Ursache:** Der ausführende Account ist kein Mitglied von `Enterprise Admins`.  
**Lösung:** Als Enterprise Admin ausführen oder RunAs:
```powershell
$cred = Get-Credential "CONTOSO\EnterpriseAdmin"
Enable-ADOptionalFeature `
    -Identity 'Privileged Access Management Feature' `
    -Scope ForestOrConfigurationSet `
    -Target 'contoso.local' `
    -Credential $cred
```

---

### Problem: DFL kann nicht angehoben werden

```
Set-ADDomainMode: The domain functional level cannot be raised to the requested value
```
**Ursache:** Mindestens ein DC läuft noch mit einer älteren Windows Server Version.  
**Lösung:**
```powershell
# Alle DCs und ihre OS-Versionen anzeigen
Get-ADDomainController -Filter * | Select-Object Name, OperatingSystem, OperatingSystemVersion
```
Alle DCs auf mindestens Windows Server 2016 aktualisieren.

---

## 10. Checkliste für die Einrichtung

```
[ ] 1. Alle DCs sind auf Windows Server 2016 oder neuer aktualisiert
[ ] 2. AD-Backup vor Änderungen erstellt
[ ] 3. Domain Functional Level ≥ Windows2016Domain geprüft/angehoben
[ ] 4. Forest Functional Level ≥ Windows2016Forest geprüft/angehoben (optional, empfohlen)
[ ] 5. Domain Naming Master DC identifiziert
[ ] 6. Enterprise Admin-Konto für die Aktivierung bereit
[ ] 7. PAM Feature auf dem Domain Naming Master aktiviert
[ ] 8. Feature-Aktivierung bestätigt (EnabledScopes nicht leer)
[ ] 9. Replikation auf alle DCs abgewartet / erzwungen
[10] 10. RSAT auf Admin-Workstations installiert
[11] 11. Testmitgliedschaft mit kurzer TTL (1 Minute) erfolgreich hinzugefügt
[12] 12. Automatisches Ablaufen der Testmitgliedschaft bestätigt
[13] 13. Auditing auf DCs aktiviert und Events geprüft
[14] 14. TempGroupManager.ps1 auf Admin-Workstations verteilt/getestet
```

---

## 11. Referenzen (Microsoft Docs)

| Thema | URL |
|---|---|
| PAM Übersicht (MIM) | https://learn.microsoft.com/en-us/microsoft-identity-manager/pam/privileged-identity-management-for-active-directory-domain-services |
| Add-ADGroupMember | https://learn.microsoft.com/en-us/powershell/module/activedirectory/add-adgroupmember |
| Enable-ADOptionalFeature | https://learn.microsoft.com/en-us/powershell/module/activedirectory/enable-adoptionalfeature |
| Get-ADOptionalFeature | https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adoptionalfeature |
| Get-ADGroup (-ShowMemberTimeToLive) | https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adgroup |
| Least Privilege Administrative Models | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models |
| PAM Deploy Step 1 (CORP Domain) | https://learn.microsoft.com/en-us/microsoft-identity-manager/pam/step-1-prepare-corp-domain |
