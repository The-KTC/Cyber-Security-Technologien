# Handout: Kerberos (Authentifizierung)

**Thema:** Kerberos - Netzwerk-Authentifizierungsprotokoll  
**Datum:** September 2025  
**Bearbeiter:** Ihr Name  

---

## 1. Grundlagen von Kerberos

### Definition
**Kerberos:** Ein netzwerkbasiertes Authentifizierungsprotokoll, das symmetrische Schlüsselkryptographie und vertrauenswürdige Drittparteien (KDC) verwendet, um sichere Authentifizierung ohne Passwortübertragung zu ermöglichen[177][180]

### Historischer Hintergrund
- **Entwickelt:** MIT (Massachusetts Institute of Technology) in den 1980er Jahren
- **Benannt nach:** Kerberos, dem dreiköpfigen Höllenhund der griechischen Mythologie, der die Unterwelt bewacht[180]
- **Drei Köpfe:** Repräsentieren Client, Key Distribution Center (KDC) und Server[180]
- **Standard:** RFC 4120 (Kerberos V5), Microsoft-Implementation seit Windows 2000[182]

### Grundprinzipien
1. **Single Sign-On (SSO):** Benutzer authentifiziert sich einmal und erhält Zugang zu allen autorisierten Services[177]
2. **Shared Secrets:** Keine Passwortübertragung über das Netzwerk[183]
3. **Tickets:** Zeitlich begrenzte kryptographische Token für Authentifizierung[177][180]
4. **Mutual Authentication:** Sowohl Client als auch Server können sich gegenseitig authentifizieren[186]

---

## 2. Kerberos-Architektur & Komponenten

### Key Distribution Center (KDC)
**Das KDC ist der zentrale Bestandteil von Kerberos:**[197][203]

#### Authentication Server (AS)
- **Funktion:** Erste Authentifizierung des Clients
- **Input:** Benutzeranmeldedaten (Username/Password)
- **Output:** Ticket Granting Ticket (TGT)
- **Database:** Verwendet Active Directory als Benutzerdatenbank[203]

#### Ticket Granting Server (TGS)
- **Funktion:** Ausstellung von Service Tickets
- **Input:** Gültiges TGT + Service-Anfrage
- **Output:** Service Ticket für spezifischen Dienst
- **Validation:** Überprüft TGT-Gültigkeit vor Ticket-Ausstellung[198]

#### KDC-Architektur in Windows
```
Domain Controller
├── Local Security Authority (LSA)
├── Key Distribution Center (KDC)
│   ├── Authentication Server (AS)
│   └── Ticket Granting Server (TGS)
├── Active Directory Database
└── Global Catalog (für Domain-Referrals)
```

### Kerberos Realm
- **Definition:** Administrative Domain für Kerberos-Authentifizierung
- **Naming:** Typischerweise DNS-Domain in Großbuchstaben (z.B. EXAMPLE.COM)
- **Trust:** Cross-Domain-Authentication über Realm-Trusts möglich[189]

---

## 3. Kerberos-Tickets & Kryptographie

### Ticket-Typen

#### Ticket Granting Ticket (TGT)
**Eigenschaften:**[178][201][204]
- **Lebensdauer:** Typisch 10 Stunden (Standard Windows)
- **Verschlüsselung:** Mit krbtgt-Account-Hash verschlüsselt
- **Inhalt:** Benutzer-ID, Domain, Gültigkeitsdauer, Session Key
- **Verwendung:** Berechtigung zur Anfrage von Service Tickets

#### Service Ticket (ST)
**Eigenschaften:**[178][198]
- **Lebensdauer:** Typisch 10 Stunden oder bis Service-Ende
- **Verschlüsselung:** Mit Service-Account-Hash verschlüsselt
- **Inhalt:** Benutzer-ID, Service-SPN, Session Key, PAC-Daten
- **Verwendung:** Direkter Zugang zu spezifischem Service

### Privileged Attribute Certificate (PAC)
**PAC-Komponente in Windows Kerberos:**[216][219][225]

#### Zweck und Funktionalität
- **Authorization Data:** Enthält Benutzerberechtigungen und Gruppenmitgliedschaften
- **Performance:** Eliminiert zusätzliche AD-Abfragen für Authorization
- **Sicherheit:** Kryptographisch signiert zur Verhinderung von Manipulationen

#### PAC-Inhalte
```
PAC-Struktur:
├── KERB_VALIDATION_INFO
│   ├── User SID
│   ├── Group SIDs (GroupIds)
│   └── User Privileges
├── PAC_REQUESTOR (seit 2021-Update)
│   └── User SID für TGT-Validation
├── PAC_CLIENT_INFO
└── PAC_SIGNATURE_DATA
```

**Microsoft 2021 Update (KB5008380):**[219][234]
- **Neue PAC_REQUESTOR-Struktur:** Zusätzliche Validierung gegen Golden Ticket Attacks
- **SID-Validierung:** KDC überprüft Username gegen SID im PAC_REQUESTOR
- **Backward Compatibility:** Dreiphasiges Rollout (Audit → Warning → Enforcement)

---

## 4. Kerberos-Authentifizierungsprozess

### Phase 1: Authentication Server Request (AS_REQ/AS_REP)

**Client → Authentication Server:**[178][180]
1. **AS_REQ:** Client sendet Username + verschlüsselten Timestamp
   - **Verschlüsselung:** Mit NTLM-Hash des Benutzer-Passworts
   - **Timestamp:** Aktueller Zeitstempel (±5 Min Toleranz)

2. **AS_REP:** Authentication Server antwortet mit:
   - **TGT:** Verschlüsselt mit krbtgt-Hash
   - **Session Key:** Für TGS-Kommunikation, verschlüsselt mit User-Hash

### Phase 2: Ticket Granting Server Request (TGS_REQ/TGS_REP)

**Client → Ticket Granting Server:**[178][198]
1. **TGS_REQ:** Client fordert Service Ticket an
   - **TGT:** Vom AS erhaltenes TGT
   - **Authenticator:** Username + Timestamp, verschlüsselt mit Session Key
   - **SPN:** Service Principal Name des gewünschten Services

2. **TGS_REP:** TGS antwortet mit:
   - **Service Ticket:** Verschlüsselt mit Service-Account-Hash
   - **Service Session Key:** Für Client-Service-Kommunikation

### Phase 3: Application Server Request (AP_REQ/AP_REP)

**Client → Application Server:**[178]
1. **AP_REQ:** Client sendet Service Request
   - **Service Ticket:** Vom TGS erhalten
   - **Authenticator:** Username + Timestamp, verschlüsselt mit Service Session Key

2. **AP_REP (optional):** Server bestätigt Authentifizierung
   - **Mutual Authentication:** Server beweist seine Identität
   - **Encrypted Response:** Mit Service Session Key verschlüsselt

### Vollständiger Ablauf
```
1. Client → AS: AS_REQ (Username, encrypted timestamp)
2. AS → Client: AS_REP (TGT, session key)
3. Client → TGS: TGS_REQ (TGT, authenticator, SPN)
4. TGS → Client: TGS_REP (service ticket, service session key)
5. Client → Service: AP_REQ (service ticket, authenticator)
6. Service → Client: AP_REP (optional mutual auth)
```

---

## 5. Kerberos-Delegation

### Delegation-Typen

#### Unconstrained Delegation
**Charakteristika:**[220][223][226]
- **Funktionsweise:** Service erhält Kopie des Client-TGT
- **Berechtigung:** Service kann Client zu JEDEM anderen Service impersonieren
- **Flag:** TRUSTED_FOR_DELEGATION im User Account Control
- **Risiko:** Höchstes Sicherheitsrisiko - Domain-weite Berechtigung

#### Constrained Delegation (Klassisch)
**Charakteristika:**[217][220][223]
- **Einschränkung:** Service kann nur zu vordefinierten Services delegieren
- **Konfiguration:** msDS-AllowedToDelegateTo-Attribut am delegierenden Account
- **Protokoll:** Service for User to Proxy (S4U2Proxy)
- **Sicherheit:** Reduziertes Risiko durch Service-Einschränkung

#### Resource-Based Constrained Delegation (RBCD)
**Charakteristika:**[217][220][229]
- **Kontrolle:** Ziel-Resource kontrolliert, wer zu ihr delegieren darf
- **Konfiguration:** msDS-AllowedToActOnBehalfOfOtherIdentity am Ziel-Service
- **Administration:** Service-Admin statt Domain-Admin kann konfigurieren
- **Flexibilität:** Cross-Domain-Delegation möglich

### Delegation-Vergleich
| **Typ** | **Kontrolle** | **Scope** | **Konfiguration** | **Risiko** |
|---------|---------------|-----------|-------------------|------------|
| **Unconstrained** | Keine | Domain-weit | Domain Admin | ⚠️ Sehr hoch |
| **Constrained** | Service-Liste | Begrenzt | Domain Admin | 🔶 Mittel |
| **RBCD** | Resource-Admin | Flexibel | Service Admin | ✅ Niedrig |

---

## 6. Keytab-Dateien & Linux-Integration

### Keytab-Grundlagen
**Definition:**[221][233]
- **Keytab:** Datei mit Kerberos Principals und entsprechenden Verschlüsselungsschlüsseln
- **Zweck:** Passwordlose Authentifizierung für Services und Scripts
- **Format:** Standardisiert, plattformübergreifend verwendbar

### Keytab-Erstellung

#### Windows (ktpass)
```cmd
ktpass /princ HTTP/webserver.example.com@EXAMPLE.COM 
       /pass ServicePassword123! 
       /ptype KRB5_NT_PRINCIPAL 
       /crypto AES256-SHA1 
       /out webservice.keytab
       /mapuser EXAMPLE\webservice
```

#### Linux (msktutil)
```bash
msktutil -c -b "CN=COMPUTERS" \
         -s HTTP/webserver.example.com \
         -k /etc/webservice/service.keytab \
         --computer-name webserver \
         --upn HTTP/webserver.example.com \
         --server dc01.example.com \
         --enctypes 24
```

### Service Principal Names (SPN)
**SPN-Format:** `service/hostname.domain.com@REALM`[221][230]

**Häufige SPN-Services:**
- **HTTP:** Webservices (`HTTP/web.example.com@EXAMPLE.COM`)
- **CIFS:** File Shares (`CIFS/fileserver.example.com@EXAMPLE.COM`)
- **SQL:** Database Services (`MSSQLSvc/db.example.com:1433@EXAMPLE.COM`)
- **LDAP:** Directory Services (`LDAP/dc.example.com@EXAMPLE.COM`)

---

## 7. Kerberos-Sicherheit & Angriffe

### Golden Ticket Attack
**Funktionsweise:**[178][181][202][205]

#### Voraussetzungen
- **Domain Admin Zugriff:** Erforderlich zum Extrahieren des krbtgt-Hash
- **Domain-Informationen:** Domain SID, FQDN, krbtgt-Hash

#### Angriffsverlauf
1. **Hash-Extraktion:** krbtgt NTLM-Hash mittels Mimikatz extrahieren
2. **Ticket-Fälschung:** Gefälschtes TGT mit beliebigen Berechtigungen erstellen
3. **Persistenz:** TGT-Lebensdauer auf Jahre setzen
4. **Domain-Zugriff:** Unbeschränkter Zugang zu allen Domain-Services

#### Erkennungsmerkmale
- **Event ID 4768:** Ungewöhnliche TGT-Requests
- **Lange Ticket-Lebensdauer:** Tickets mit ungewöhnlicher Gültigkeit
- **Verschlüsselungstypen:** Abweichende Encryption-Algorithmen
- **PAC_REQUESTOR:** Fehlende oder falsche PAC_REQUESTOR-Struktur (seit 2021)

### Silver Ticket Attack
**Funktionsweise:**[181][187][199][207][210]

#### Charakteristika
- **Service-spezifisch:** Gefälschtes Service Ticket für spezifischen Dienst
- **Service-Hash:** Benötigt nur Hash des Service-Accounts
- **Stealth:** Keine KDC-Kommunikation nach Ticket-Erstellung
- **Begrenzt:** Zugriff nur auf kompromittierten Service

#### Angriffsverlauf
1. **Service-Hash:** Hash des Service-Accounts extrahieren
2. **Ticket-Fälschung:** TGS-Ticket für spezifischen Service fälschen
3. **Service-Zugriff:** Direkter Zugang ohne KDC-Validierung
4. **Lateral Movement:** Nutzen für weitere Compromise-Versuche

#### Schutzmaßnahmen
- **PAC-Validation:** Service-seitige PAC-Überprüfung aktivieren
- **Monitoring:** Ungewöhnliche Service-Zugriffe überwachen
- **Account-Rotation:** Regelmäßiger Wechsel von Service-Account-Passwörtern
- **Least Privilege:** Minimale Berechtigungen für Service-Accounts

---

## 8. Aktuelle Kerberos-Entwicklungen (2025)

### Microsoft Updates

#### CVE-2025-26647 (April 2025)
**Kerberos Authentication Vulnerability:**[179][188]
- **Problem:** Insufficient Input Validation in Kerberos PKINIT
- **CVSS Score:** 8.8 (High)
- **Auswirkung:** Privilege Escalation ohne Authentifizierung
- **Schutz:** AllowNtAuthPolicyBypass Registry Key

#### Windows Server 2025 Issues
**KDC-Probleme:**[185]
- **Symptom:** DefaultDomainSupportedEncTypes wird ignoriert
- **Registry Fix:** Konfiguration in alternativen Registry-Pfad erforderlich
- **Workaround:** `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters`

#### PAC Validation Protocol (April 2025)
**Änderungen:**[192][196]
- **Kompatibilitätsmodus:** Seit 8. April 2025 abgeschaltet
- **Legacy Support:** Windows XP/2003-Unterstützung entfernt
- **Security Enhancement:** Verstärkte PAC-Validierung

### Encryption & Modern Security

#### Unterstützte Verschlüsselungsalgorithmen
**Standard-Algorithmen:**[179][185]
- **AES256-CTS-HMAC-SHA1-96:** Preferred modern encryption
- **AES128-CTS-HMAC-SHA1-96:** Alternative modern encryption
- **RC4-HMAC:** Legacy, sollte vermieden werden
- **DES:** Deprecated, unsicher

#### Zeit-Synchronisation
**NTP-Anforderungen:**[180][191]
- **Toleranz:** Maximal 5 Minuten Zeitabweichung
- **Synchronisation:** Automatische Zeitsynchronisation empfohlen
- **Fehlerquelle:** Häufige Ursache für Kerberos-Authentifizierungsprobleme

---

## 9. Kerberos vs. andere Protokolle

### Kerberos vs. NTLM

| **Aspekt** | **Kerberos** | **NTLM** |
|------------|-------------|----------|
| **Authentifizierung** | Ticket-basiert | Challenge-Response |
| **Mutual Auth** | ✅ Ja | ❌ Nein |
| **Network Traffic** | Reduziert (Tickets) | Höher (DC-Queries) |
| **SSO Support** | ✅ Nativ | ⚠️ Begrenzt |
| **Security** | ✅ Höher | ⚠️ Niedriger |
| **Legacy Support** | Windows 2000+ | Alle Windows-Versionen |

### Kerberos vs. moderne Protokolle

#### vs. OAuth 2.0/OpenID Connect
- **Kerberos:** Intranet, Enterprise-Umgebungen
- **OAuth:** Internet, Cloud-Services, APIs
- **Gemeinsamkeit:** Token-basierte Authentifizierung

#### vs. SAML
- **Kerberos:** Network-Level Authentication
- **SAML:** Web-basierte Federation
- **Integration:** Kerberos kann als Identity Provider für SAML dienen

---

## 10. Best Practices & Härtung

### KDC-Sicherheit
**Domain Controller Protection:**
- **Physical Security:** Sichere Aufbewahrung der Domain Controller
- **Network Segmentation:** Isolierung kritischer Kerberos-Services
- **Access Control:** Minimale Admin-Berechtigungen
- **Monitoring:** Kontinuierliche Überwachung von KDC-Aktivitäten

### Ticket-Management
**Ticket Security:**
- **Lebensdauer:** Angemessene Ticket-Gültigkeitsdauer konfigurieren
- **Renewal:** Automatische Ticket-Renewal implementieren
- **Cleanup:** Regelmäßige Bereinigung abgelaufener Tickets
- **Caching:** Sichere Ticket-Speicherung auf Client-Systemen

### Service-Account-Management
**Account Hardening:**
- **Strong Passwords:** Komplexe, lange Passwörter für Service-Accounts
- **Regular Rotation:** Regelmäßiger Passwort-Wechsel (90-180 Tage)
- **Least Privilege:** Minimale Berechtigungen für Service-Accounts
- **SPN Management:** Korrekte SPN-Zuordnung und -Verwaltung

### Monitoring & Detection
**Security Monitoring:**
- **Event Logging:** Aktivierung relevanter Kerberos-Events
- **Anomaly Detection:** Erkennung ungewöhnlicher Authentifizierungsmuster
- **Ticket Analysis:** Überwachung von Ticket-Eigenschaften und -Lebenszeiten
- **Cross-Correlation:** Verknüpfung von Kerberos-Events mit anderen Security-Logs

---

## 11. Troubleshooting & Häufige Probleme

### Zeitsynchronisationsprobleme
**Symptome:**
- KRB_AP_ERR_SKEW Fehler
- Authentifizierung schlägt sporadisch fehl
- Event ID 4 (Zeitsynchronisationsfehler)

**Lösungen:**
- NTP-Konfiguration überprüfen
- w32time-Service auf allen Systemen konfigurieren
- Zeitabweichung zwischen Client und DC prüfen

### SPN-Probleme
**Symptome:**
- KRB_AP_ERR_PRINCIPAL_UNKNOWN
- Service nicht über Kerberos erreichbar
- Fallback auf NTLM-Authentifizierung

**Lösungen:**
- SPN-Registrierung mit setspn.exe überprüfen
- Doppelte SPN-Einträge beseitigen
- Service-Account-Zuordnung validieren

### PAC-Validierungsfehler
**Symptome:**
- KRB_AP_ERR_MODIFIED (since 2021 update)
- Authentifizierung schlägt bei modernisierten DCs fehl
- Event ID 45 (PAC validation errors)

**Lösungen:**
- PAC_REQUESTOR-Struktur in Tools aktualisieren
- Legacy-Compatibility-Modus temporär aktivieren
- KB5008380-Updates auf allen DCs installieren

---

## 12. Klausur-relevante Formeln & Definitionen

### Wichtige Akronyme
- **AS:** Authentication Server
- **TGS:** Ticket Granting Server  
- **KDC:** Key Distribution Center
- **TGT:** Ticket Granting Ticket
- **ST:** Service Ticket
- **PAC:** Privileged Attribute Certificate
- **SPN:** Service Principal Name
- **RBCD:** Resource-Based Constrained Delegation

### Kerberos-Nachrichtentypen
- **AS_REQ/AS_REP:** Authentication Server Request/Reply
- **TGS_REQ/TGS_REP:** Ticket Granting Server Request/Reply  
- **AP_REQ/AP_REP:** Application Server Request/Reply

### Zeitbeziehungen
- **Ticket Lifetime:** Standard 10 Stunden für TGT und Service Tickets
- **Clock Skew Tolerance:** Maximum 5 Minuten Zeitabweichung
- **Renewal Period:** TGT-Renewal möglich bis zu 7 Tage (konfigurarbar)

### Verschlüsselungshierarchie
```
User Password → NTLM Hash → Client Authentication
krbtgt Password → krbtgt Hash → TGT Encryption  
Service Password → Service Hash → Service Ticket Encryption
```

---

## 13. Prüfungstipps

### Häufige Klausurfragen
1. **Kerberos-Ablauf:** Schritt-für-Schritt AS_REQ → AS_REP → TGS_REQ → TGS_REP → AP_REQ
2. **Ticket-Typen:** TGT vs. Service Ticket - Unterschiede und Verwendungszweck
3. **PAC-Funktion:** Authorization vs. Authentication, PAC-Inhalte
4. **Delegation-Arten:** Unconstrained vs. Constrained vs. RBCD
5. **Angriffsmethoden:** Golden Ticket vs. Silver Ticket - Voraussetzungen und Auswirkungen
6. **Keytab-Verwendung:** Linux-Integration, SPN-Konzept
7. **Troubleshooting:** Zeitsynchronisation, SPN-Probleme, PAC-Validation

### Berechnungsaufgaben (selten)
- **Ticket-Lifetime-Berechnung:** Gültigkeitsdauer-Berechnungen
- **Zeit-Toleranz:** Clock-Skew-Szenarien
- **Delegation-Ketten:** Multi-Hop-Delegation-Analysen

### Vergleichstabellen auswendig lernen
- Kerberos vs. NTLM Eigenschaften
- Delegation-Typen und ihre Sicherheitsimplikationen
- Ticket-Typen und ihre Charakteristika

### Aktuelle Entwicklungen 2025
- CVE-2025-26647 und Schutzmaßnahmen
- Windows Server 2025 KDC-Änderungen  
- PAC_REQUESTOR-Update und Auswirkungen
- Modern Authentication-Integration

---

**Quellen:** MIT Kerberos Documentation, Microsoft Official Documentation, RFC 4120, Kerberos Security Research 2025, Windows Server 2025 Release Notes, CVE-2025-26647 Security Advisory