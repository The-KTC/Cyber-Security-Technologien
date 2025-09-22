# Vorlesung: TOTP (Time-based One-Time Password)
## Zeitbasierte Einmalpasswörter in der modernen Authentifizierung

---

## Vorlesungsplan (90 Minuten)

### 1. Einführung & Motivation (10 Min)
### 2. Historischer Kontext & Standards (15 Min)
### 3. Technische Grundlagen & Algorithmus (25 Min)
### 4. Implementierung & Praxisanwendung (20 Min)
### 5. Sicherheitsanalyse & Bedrohungsmodell (15 Min)
### 6. Zukunftsausblick & Diskussion (5 Min)

---

## 1. Einführung & Motivation

### Das Problem der traditionellen Authentifizierung

**Warum reichen Passwörter allein nicht mehr aus?**

**Aktuelle Bedrohungslage 2025:**
- **Über 15 Milliarden** gestohlene Zugangsdaten im Darknet verfügbar[64]
- **80%** aller Cyberangriffe beginnen mit kompromittierten Passwörtern
- **Credential Stuffing** Angriffe nutzen automatisiert geleakte Passwort-Datenbanken
- **Phishing** wird durch KI-Tools immer raffinierter und schwerer erkennbar

### Zwei-Faktor-Authentifizierung als Lösung

**Die drei Authentifizierungsfaktoren:**
1. **Wissen** (Something you know): Passwort, PIN
2. **Besitz** (Something you have): Smartphone, Token, Chipkarte
3. **Identität** (Something you are): Biometrie, Verhalten

**2FA kombiniert mindestens zwei dieser Faktoren**[64]

### TOTP in Zahlen

**Verbreitung und Effektivität:**
- **99,9%** weniger erfolgreiche Account-Übernahmen mit 2FA[64]
- **Über 90%** aller großen Online-Services unterstützen TOTP
- **30 Sekunden** Standard-Gültigkeitsdauer für TOTP-Codes[67]
- **6 Stellen** typische Code-Länge für optimale Benutzerfreundlichkeit

### Lernziele der Vorlesung

Nach dieser Vorlesung können Sie:
- Den TOTP-Algorithmus mathematisch verstehen und implementieren
- RFC 6238 Spezifikationen erläutern und anwenden
- Sicherheitsstärken und -schwächen von TOTP bewerten
- TOTP-Systeme konfigurieren und troubleshooten
- Alternative 2FA-Verfahren vergleichen und einordnen

---

## 2. Historischer Kontext & Standards

### Die Evolution der Einmalpasswörter

#### Von mechanischen Codebüchern zu digitalen Tokens

**1940er-1980er: Mechanische Verfahren**
- Einmalcodebücher in der Militärkommunikation
- Physische Code-Wheels und Lookup-Tabellen
- Problem: Logistik und Verteilung der Codes

**1990er: Erste digitale Tokens**
- RSA SecurID (1987): Hardware-basierte OTP-Generation
- Synchrone Token mit fest programmierten Algorithmen
- Problem: Proprietäre Standards, hohe Kosten

**2000er: Standardisierung beginnt**
- Initiative for Open Authentication (OATH) gegründet 2004
- Bedarf nach interoperablen, offenen Standards
- Mobile Geräte werden allgegenwärtig

### RFC-Entwicklung: Von HOTP zu TOTP

#### HOTP - Der Grundstein (RFC 4226, 2005)

**HMAC-based One-Time Password:**[102]
- **Funktionsprinzip:** Zählerbasierte OTP-Generierung
- **Algorithmus:** `HOTP(K,C) = Truncate(HMAC-SHA-1(K,C))`
- **Problem:** Synchronisation zwischen Client und Server schwierig

**Zähler-Synchronisationsprobleme:**
- Client und Server müssen identischen Zähler haben
- Bei verlorenen/nicht verwendeten Codes gerät System "out of sync"
- Manuelle Resynchronisation nötig

#### TOTP - Die zeitbasierte Lösung (RFC 6238, 2011)

**Entwicklungsmotivation:**[67][68]
- **Automatische Synchronisation** durch gemeinsame Zeitbasis
- **Benutzerfreundlichkeit:** Codes verfallen automatisch
- **Skalierbarkeit:** Keine manuelle Synchronisation nötig

**Technische Verbesserungen:**
- Zeit als "beweglicher Faktor" statt Zähler
- Standardisierte Zeitintervalle (30 Sekunden)
- Toleranzfenster für Netzwerklatenz und Zeitabweichungen

### OATH Initiative & Standardisierung

**Initiative for Open Authentication (OATH):**[65][67]
- **Gegründet:** 2004 von VeriSign, Vasco, ActivIdentity
- **Ziel:** Offene Standards für starke Authentifizierung
- **Heute:** Über 100 Mitgliedsunternehmen weltweit

**OATH-Standards:**
- **HOTP:** RFC 4226 (Hash-based OTP)
- **TOTP:** RFC 6238 (Time-based OTP)
- **OCRA:** RFC 6287 (Challenge-Response Algorithm)
- **DSKPP:** RFC 6063 (Key Provisioning Protocol)

---

## 3. Technische Grundlagen & Algorithmus

### Mathematische Fundamente

#### Unix-Zeit als zeitliche Basis

**Unix-Timestamp:**[67][68]
- **Definition:** Sekunden seit 1. Januar 1970, 00:00:00 UTC
- **Beispiel:** 22. September 2025, 13:10 CEST = 1727001000 Unix-Zeit
- **Vorteil:** Plattformunabhängige, eindeutige Zeitrepresentation

**Zeitschritt-Berechnung:**
```
T = floor((Current Unix Time - T0) / X)
```
- **T0:** Startzeitpunkt (meist 0)
- **X:** Zeitschrittgröße (meist 30 Sekunden)
- **T:** Zeitschrittwert für HMAC-Berechnung

#### HMAC - Hash-based Message Authentication Code

**HMAC-Funktionsweise:**[102][109]
```
HMAC(K, M) = H((K ⊕ opad) || H((K ⊕ ipad) || M))
```
- **K:** Geheimer Schlüssel (Secret Key)
- **M:** Nachricht (hier: Zeitschritt T)
- **H:** Hash-Funktion (SHA-1, SHA-256, SHA-512)
- **opad/ipad:** Äußere/innere Padding-Konstanten
- **⊕:** XOR-Operation, || : Konkatenation

### Der TOTP-Algorithmus im Detail

#### Schritt-für-Schritt-Berechnung

**1. Zeitschritt berechnen:**
```python
import time
T0 = 0  # Unix-Epoche
X = 30  # Zeitintervall in Sekunden
current_time = int(time.time())
T = (current_time - T0) // X
```

**2. Zeitschritt in Bytes konvertieren:**
```python
import struct
time_bytes = struct.pack('>Q', T)  # 8 Bytes, Big-Endian
```

**3. HMAC berechnen:**
```python
import hmac
import hashlib
secret_key = b'geheimer_schluessel'
hash_value = hmac.new(secret_key, time_bytes, hashlib.sha1).digest()
```

**4. Dynamic Truncation:**[68]
```python
offset = hash_value[-1] & 0x0F
truncated_hash = (
    (hash_value[offset] & 0x7F) << 24 |
    (hash_value[offset + 1] & 0xFF) << 16 |
    (hash_value[offset + 2] & 0xFF) << 8 |
    (hash_value[offset + 3] & 0xFF)
)
```

**5. Modulo-Operation für finale Code-Länge:**
```python
digits = 6
totp_code = truncated_hash % (10 ** digits)
formatted_code = f"{totp_code:0{digits}d}"
```

#### Vollständige Python-Implementation

```python
import hmac
import hashlib
import struct
import time
import base64

def generate_totp(secret, timestamp=None, period=30, digits=6):
    """
    Generiert TOTP-Code nach RFC 6238
    
    Args:
        secret: Base32-encodierter Secret Key
        timestamp: Unix-Timestamp (None = aktuelle Zeit)
        period: Zeitintervall in Sekunden
        digits: Anzahl Stellen des Codes
    
    Returns:
        TOTP-Code als String
    """
    if timestamp is None:
        timestamp = int(time.time())
    
    # Secret von Base32 dekodieren
    key = base64.b32decode(secret.upper() + '=' * (-len(secret) % 8))
    
    # Zeitschritt berechnen
    counter = timestamp // period
    
    # Counter zu 8-Byte Big-Endian konvertieren
    counter_bytes = struct.pack('>Q', counter)
    
    # HMAC-SHA1 berechnen
    mac = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    
    # Dynamic Truncation
    offset = mac[-1] & 0x0F
    truncated = (
        (mac[offset] & 0x7F) << 24 |
        (mac[offset + 1] & 0xFF) << 16 |
        (mac[offset + 2] & 0xFF) << 8 |
        (mac[offset + 3] & 0xFF)
    )
    
    # Finale Code-Generierung
    code = truncated % (10 ** digits)
    return f"{code:0{digits}d}"

# Beispiel-Verwendung
secret = "JBSWY3DPEHPK3PXP"  # Base32-codiert
current_code = generate_totp(secret)
print(f"TOTP-Code: {current_code}")
```

### Hash-Funktionen in TOTP

#### SHA-1 vs. SHA-2 vs. SHA-3

**SHA-1 (Standard):**[68][73]
- **Output:** 160 Bit (20 Bytes)
- **Status:** Deprecated für neue Anwendungen, aber TOTP noch sicher
- **Grund:** TOTP nutzt nur Truncation, nicht Kollisionsresistenz

**SHA-256 (Empfohlen):**
- **Output:** 256 Bit (32 Bytes)
- **Sicherheit:** Höhere Resistenz gegen Angriffe
- **Kompatibilität:** Nicht alle Authenticator-Apps unterstützen es

**SHA-512 (Zukunftssicher):**
- **Output:** 512 Bit (64 Bytes)
- **Performance:** Langsamer, aber sicherster Ansatz
- **Anwendung:** Hochsicherheitsumgebungen

#### Auswirkung der Hash-Funktion auf Sicherheit

**Warum ist SHA-1 bei TOTP noch akzeptabel?**
- TOTP verwendet nur **Truncation**, nicht **Kollisionsresistenz**
- **Preimage-Resistenz** von SHA-1 ist weiterhin ausreichend
- **Secret** ist bereits unbekannt, zusätzlicher Schutz durch Zeitfenster

---

## 4. Implementierung & Praxisanwendung

### QR-Code-Format für TOTP-Setup

#### Google Authenticator URI-Schema

**Standard-Format:**[92]
```
otpauth://totp/LABEL?secret=SECRET&issuer=ISSUER&algorithm=ALGORITHM&digits=DIGITS&period=PERIOD
```

**Parameter-Erklärung:**
- **LABEL:** Account-Bezeichnung (meist E-Mail)
- **SECRET:** Base32-encodierter geheimer Schlüssel
- **ISSUER:** Service-Name für bessere Übersicht
- **ALGORITHM:** SHA1, SHA256, SHA512
- **DIGITS:** 6 oder 8 Stellen
- **PERIOD:** Zeitintervall (meist 30)

**Beispiel-URI:**
```
otpauth://totp/john.doe@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30
```

#### QR-Code-Generierung in der Praxis

**Mit Python und qrcode-Bibliothek:**
```python
import qrcode
import base64
import secrets

# Sicheren Secret generieren
secret_bytes = secrets.token_bytes(20)  # 160 Bit
secret_b32 = base64.b32encode(secret_bytes).decode('utf-8')

# URI erstellen
label = "user@example.com"
issuer = "MyService"
uri = f"otpauth://totp/{label}?secret={secret_b32}&issuer={issuer}"

# QR-Code generieren
qr = qrcode.QRCode(version=1, box_size=10, border=5)
qr.add_data(uri)
qr.make(fit=True)

img = qr.make_image(fill_color="black", back_color="white")
img.save("totp_setup.png")
```

### Beliebte TOTP-Implementierungen

#### Mobile Authenticator-Apps

**1. Microsoft Authenticator:**[88]
- **Besonderheiten:** Cloud-Backup, Push-Notifications für Microsoft-Konten
- **Plattformen:** iOS, Android
- **Features:** Biometrische Entsperrung, Offline-Funktionalität

**2. Google Authenticator:**
- **Verbreitung:** Am weitesten verbreitet
- **Nachteile:** Kein Cloud-Backup (bis 2023), minimale Features
- **Vorteile:** Einfachheit, universelle Unterstützung

**3. 2FAS (Empfohlen 2025):**[91]
- **Besonderheiten:** Open-Source, iCloud-Sync, Import/Export
- **Sicherheit:** Lokale Verschlüsselung, keine Telemetrie
- **Features:** Backup-Funktionen, Icon-Anpassung

**4. Ente Auth:**[91]
- **Focus:** Privacy-first, E2E-Verschlüsselung
- **Features:** Cross-Platform-Sync, Open-Source
- **Zielgruppe:** Datenschutz-bewusste Nutzer

#### Hardware-Token

**YubiKey OATH-TOTP:**
- **Kapazität:** Bis zu 32 TOTP-Credentials
- **Interface:** USB, NFC, Lightning
- **Software:** YubiKey Authenticator (Desktop/Mobile)

**REINER SCT Authenticator:**[98]
- **Besonderheit:** Deutsche Hardware-Lösung
- **Features:** Display, Tastatur, sichere Element-Speicherung
- **Zielgruppe:** Hochsicherheitsanwendungen

### Enterprise-Integration

#### TOTP in Unternehmenssystemen

**Active Directory Federation Services (ADFS):**
- TOTP als zusätzlicher Authentifizierungsfaktor
- Integration mit Windows Hello for Business
- Conditional Access Policies

**SAML/OAuth2 Integration:**
- TOTP als MFA-Step in SSO-Flows
- Claims-based Authentication mit TOTP-Verification
- API-basierte TOTP-Validierung

#### Automatisierung und DevOps

**Problem der manuellen TOTP-Eingabe:**[66]
- Shared Accounts benötigen automatisierten TOTP-Zugriff
- CI/CD-Pipelines können nicht manuell Codes eingeben
- Team-basierte Services brauchen zentrale TOTP-Verwaltung

**Lösungsansätze:**
- **TOTP-APIs:** Programmatischer Zugriff auf TOTP-Generierung
- **Vault-Integration:** HashiCorp Vault für TOTP-Secret-Management
- **Browser-Automation:** Automatisches Ausfüllen von TOTP-Codes

### Secret-Management & Security

#### Sichere Secret-Generierung

**Kryptographisch sichere Zufallszahlen:**
```python
import secrets
import base64

# 160-Bit Secret (RFC 6238 Minimum)
secret_bytes = secrets.token_bytes(20)
secret_base32 = base64.b32encode(secret_bytes).decode()

# 256-Bit für erhöhte Sicherheit
secret_256 = secrets.token_bytes(32)
secret_256_base32 = base64.b32encode(secret_256).decode()
```

**Entropie-Betrachtungen:**
- **Minimum:** 160 Bit (RFC 6238)[68]
- **Empfohlen:** 256 Bit für Zukunftssicherheit
- **Hardware-RNG:** Für Hochsicherheitsanwendungen bevorzugt

#### Secret-Speicherung und -Übertragung

**Server-seitige Speicherung:**
- **Verschlüsselung:** AES-256 mit Hardware Security Modules
- **Salting:** Zusätzliche Randomisierung pro Benutzer
- **Access Control:** Minimale Berechtigungen für TOTP-Services

**Client-seitige Sicherheit:**
- **Secure Element:** Hardware-basierte Speicherung
- **Keychain/KeyStore:** OS-bereitgestellte sichere Speicher
- **App-Sandboxing:** Isolation von TOTP-Secrets

---

## 5. Sicherheitsanalyse & Bedrohungsmodell

### Stärken von TOTP

#### Positive Sicherheitseigenschaften

**1. Zeitbasierte Gültigkeit:**[64][76]
- **Automatisches Ablaufen:** Codes sind nur 30 Sekunden gültig
- **Replay-Resistenz:** Alte Codes können nicht wiederverwendet werden
- **Zeitfenster-Begrenzung:** Angreifer haben sehr kleine Attack-Window

**2. Offline-Generierung:**[73]
- **Keine Netzwerkabhängigkeit:** Token funktioniert ohne Internet
- **Man-in-the-Middle-Resistenz:** Kein Übertragungskanal für Codes
- **Verfügbarkeit:** Funktioniert auch bei Netzwerkausfällen

**3. Standardisierung:**[65][67]
- **Interoperabilität:** RFC 6238 gewährleistet Kompatibilität
- **Herstellerunabhängigkeit:** Wechsel zwischen Apps/Tokens möglich
- **Open Standard:** Keine Vendor-Lock-ins

**4. Skalierbarkeit:**
- **Keine zentrale Infrastruktur:** Jeder Client generiert eigenständig
- **Low Latency:** Keine Server-Kommunikation für Code-Generierung
- **Cost-Effective:** Minimale Infrastruktur-Anforderungen

### Schwachstellen und Angriffsvektoren

#### 1. Phishing-Vulnerabilität

**Das fundamentale Problem:**[104]
- **TOTP ist NICHT phishing-resistent**
- **Real-Time Phishing:** Codes können in Echtzeit weitergeleitet werden
- **30-Sekunden-Fenster:** Ausreichend Zeit für automatisierte Weiterleitung

**Praktische Angriffsmethoden:**
```
Angreifer <- Phishing-Site -> Opfer -> TOTP-Code eingeben
    |                                        ^
    v                                        |
Legitimer Service <- Code weiterleiten ------+
```

**Tools für automatisiertes TOTP-Phishing:**[104]
- **Modlishka:** Reverse-Proxy für Google-Services
- **EvilProxy:** Universal Phishing-as-a-Service
- **Muraena:** Open-Source Phishing Framework

#### 2. Secret-Kompromittierung

**Angriffsvektoren auf das Shared Secret:**
- **QR-Code Screenshots:** Nutzer speichern Setup-QR-Codes unsicher
- **App-Extraction:** Root/Jailbreak ermöglicht Secret-Zugriff
- **Backup-Probleme:** Unverschlüsselte Cloud-Backups
- **Social Engineering:** Support-Calls zur Secret-Zurücksetzung

**Auswirkungen:**
- **Dauerhafter Zugriff:** Secret-Kompromittierung = permanente Kontrolle
- **Unsichtbare Übernahme:** Angreifer können parallel Codes generieren
- **Schwierige Erkennung:** Legitime Codes funktionieren weiterhin

#### 3. Zeit-Synchronisationsprobleme

**Clock Drift bei Hardware-Token:**[103][114]
- **Interne Uhren** driften über Zeit auseinander
- **Temperatureinflüsse** beeinflussen Quarz-Oszillatoren
- **Batterie-Schwankungen** können Taktfrequenz ändern

**Lösungsansätze für Out-of-Sync-Probleme:**
```python
def validate_totp_with_window(user_code, secret, window=1):
    """
    Validiert TOTP-Code mit Toleranzfenster
    window=1 bedeutet ±30 Sekunden Toleranz
    """
    current_time = int(time.time())
    
    for i in range(-window, window + 1):
        test_time = current_time + (i * 30)
        expected_code = generate_totp(secret, test_time)
        if user_code == expected_code:
            return True, i  # True + Zeitversatz
    
    return False, None
```

#### 4. SIM-Swapping und SMS-Fallbacks

**Das gefährliche Backup-Problem:**[14]
- Viele Services bieten **SMS als TOTP-Fallback**
- **SIM-Swapping** kompromittiert SMS-basierte Backups
- **Schwächstes Glied:** Sicherheit sinkt auf SMS-Niveau

**BSI-Empfehlung 2024:**[93]
- **SMS-TAN:** Nur bei separaten Geräten akzeptabel
- **TOTP-Apps:** Mittlere Sicherheit, für normale Anwendungen geeignet
- **Hardware-Token:** Höchste Sicherheit, phishing-resistent

### Bedrohungsmodell-Analyse

#### Angreifer-Kategorien

**1. Opportunistische Angreifer:**
- **Fähigkeiten:** Phishing-Kits, gestohlene Passwort-Listen
- **TOTP-Schutz:** ✅ Sehr effektiv (99%+ Schutzwirkung)
- **Reason:** Keine Zeit für Real-Time-Attacks

**2. Zielgerichtete Angreifer:**
- **Fähigkeiten:** Custom Phishing, Social Engineering
- **TOTP-Schutz:** ⚠️ Begrenzt effektiv
- **Methoden:** Real-Time-Phishing, Support-Calls

**3. Staatliche Akteure:**
- **Fähigkeiten:** Zero-Days, Hardware-Zugriff, Massenüberwachung
- **TOTP-Schutz:** ❌ Unzureichend
- **Angriffsmethoden:** Gerätekompromittierung, Krypto-Angriffe

#### Risiko-Matrix für TOTP

| **Bedrohung** | **Wahrscheinlichkeit** | **Impact** | **TOTP-Schutz** |
|---------------|------------------------|------------|------------------|
| **Passwort-Wiederverwendung** | Hoch | Mittel | ✅ Sehr gut |
| **Credential Stuffing** | Hoch | Mittel | ✅ Sehr gut |
| **Generic Phishing** | Mittel | Mittel | ✅ Gut |
| **Targeted Phishing** | Niedrig | Hoch | ⚠️ Begrenzt |
| **SIM-Swapping** | Niedrig | Hoch | ✅ Gut* |
| **Device Compromise** | Sehr niedrig | Sehr hoch | ❌ Schlecht |

*Nur wenn keine SMS-Fallbacks aktiviert sind

### Vergleich mit anderen 2FA-Methoden

#### TOTP vs. Hardware-Token (FIDO2/WebAuthn)

**FIDO2-Vorteile:**[93][104]
- **Phishing-resistent:** Cryptographic binding an Domain
- **Keine Shared Secrets:** Public-Key-Kryptographie
- **Hardware-Security:** Secure Elements, Tamper-Resistance

**TOTP-Vorteile:**
- **Universelle Unterstützung:** 90%+ aller Services
- **Kosten:** Software-basiert, keine Hardware nötig
- **Benutzerfreundlichkeit:** Bekannte User Experience

#### TOTP vs. Push-Notifications

**Push-Notification-Vorteile:**
- **Benutzerfreundlichkeit:** Ein Tap zur Bestätigung
- **Context-Awareness:** Standort, Geräteinformationen
- **Rich Notifications:** Zusätzliche Sicherheitsinformationen

**TOTP-Vorteile:**
- **Offline-Funktionalität:** Keine Netzwerkabhängigkeit
- **Standardisierung:** Herstellerunabhängig
- **Privacy:** Keine Metadaten an Service übertragen

---

## 6. Zukunftsausblick & Diskussion

### TOTP in der Post-Password-Ära

#### Passkeys als TOTP-Nachfolger?

**WebAuthn/FIDO2-Standards:**
- **Cryptographic Binding:** Phishing-Resistenz durch Design
- **Biometric Integration:** Nahtlose Benutzerfreundlichkeit
- **Platform Support:** Native Unterstützung in Browsern/OS

**TOTP-Rolle in der Transition:**
- **Bridge Technology:** Übergang zu passwordlosen Systemen
- **Fallback-Mechanism:** Backup für Passkey-Probleme
- **Legacy Support:** Millionen bestehender Implementierungen

#### Quantum-Computing-Bedrohungen

**SHA-1/SHA-256 vs. Quantum-Angriffe:**
- **Grover's Algorithm:** Quadratische Beschleunigung für Hash-Suche
- **Effektive Sicherheit:** 160-Bit SHA-1 → 80-Bit gegen Quantencomputer
- **Zeithorizont:** 15-20 Jahre bis praktikable Quantencomputer

**Post-Quantum TOTP:**
- **SHA-3/BLAKE3:** Quantum-resistente Hash-Funktionen
- **Increased Secret Size:** 256-512 Bit für Quantum-Sicherheit
- **Hybrid Approaches:** TOTP + Post-Quantum-Cryptography

### Best Practices für verschiedene Anwendungsszenarien

#### Consumer-Anwendungen
**Empfohlenes Setup:**
- **TOTP-App:** 2FAS oder Microsoft Authenticator
- **Backup-Codes:** Sicher in Passwort-Manager speichern
- **Regelmäßige Updates:** Apps und Betriebssystem aktuell halten

#### Unternehmens-Umgebungen
**Enterprise-Anforderungen:**
- **Centralized Management:** TOTP-Secret-Verwaltung über Identity Providers
- **Compliance:** Audit-Logs für TOTP-Generierung und -Validierung
- **Incident Response:** Prozesse für kompromittierte TOTP-Secrets

#### Hochsicherheits-Anwendungen
**Zusätzliche Maßnahmen:**
- **Hardware Security Modules:** Für Secret-Speicherung
- **Time Source Validation:** Sichere NTP-Synchronisation
- **Multi-layered Defense:** TOTP + biometrische Faktoren + Hardware-Token

### Abschließende Diskussion

#### Diskussionsfragen für die Gruppe

**1. Technische Aspekte:**
- Warum ist Clock Drift bei TOTP problematischer als bei HOTP?
- Wie würden Sie TOTP gegen Quantum-Computing-Angriffe härten?

**2. Benutzerfreundlichkeit:**
- Ist die 30-Sekunden-Gültigkeit optimal, oder sollten Intervalle angepasst werden?
- Wie kann man TOTP für ältere oder technisch weniger versierte Nutzer zugänglicher machen?

**3. Sicherheitsabwägungen:**
- Wann ist TOTP ausreichend, wann sollte auf Hardware-Token gewechselt werden?
- Wie bewerten Sie das Risiko von QR-Code-Screenshots vs. die Convenience für Nutzer?

**4. Zukunftsperspektiven:**
- Wird TOTP in 10 Jahren noch relevant sein, oder vollständig durch Passkeys ersetzt?
- Welche Rolle sollte TOTP in einer Zero-Trust-Architektur spielen?

### Praktische Übung: TOTP-Code-Berechnung

**Gegeben:**
- Secret (Base32): `JBSWY3DPEHPK3PXP`
- Unix-Zeit: 1727001000 (22. September 2025, 13:10 CEST)
- Zeitintervall: 30 Sekunden

**Aufgabe:** Berechnen Sie manuell den TOTP-Code
1. Zeitschritt: T = floor(1727001000 / 30) = 57566700
2. HMAC-SHA1(Secret, 57566700) berechnen
3. Dynamic Truncation anwenden
4. Modulo 10^6 für 6-stelligen Code

**Lösung und Verifikation in der nächsten Übungseinheit!**

---

**Vielen Dank für Ihre Aufmerksamkeit!**

### Weiterführende Ressourcen
- **RFC 6238:** Vollständige TOTP-Spezifikation
- **OATH Toolkit:** Open-Source TOTP-Implementierungen
- **Google Authenticator PAM:** Linux-Integration
- **Microsoft Authenticator API:** Enterprise-Integration

### Nächste Vorlesung
**Thema:** "FIDO2/WebAuthn - Die Zukunft der passwordlosen Authentifizierung"
**Inhalt:** Cryptographic protocols, Hardware security modules, Passkey-Implementation

---

*Diese Vorlesung basiert auf RFC 6238, aktueller TOTP-Forschung und Praxiserfahrungen aus der Industrie 2025.*