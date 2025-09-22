# Handout: Passkeys (Authentifizierung)

**Thema:** Passkeys - Die Zukunft der passwordlosen Authentifizierung  
**Datum:** September 2025  
**Bearbeiter:** Ihr Name  

---

## 1. Grundlagen von Passkeys

### Definition
**Passkeys:** Kryptographische Schlüsselpaare basierend auf FIDO2/WebAuthn-Standards, die traditionelle Passwörter für sichere, phishing-resistente Authentifizierung ersetzen[119][122][130]

### Technische Grundlagen
- **Public-Key-Kryptographie:** Asymmetrische Verschlüsselung mit Schlüsselpaar
- **Private Key:** Bleibt sicher auf dem Gerät (Secure Enclave, TPM, TEE)
- **Public Key:** Wird auf dem Server des Services gespeichert
- **Challenge-Response-Protokoll:** Mathematischer Beweis der Identität ohne Geheimnisübertragung

### Standards-Stack
**FIDO2:** Oberster Standard der FIDO Alliance[139][142]
- **WebAuthn:** W3C Web-API für Browser-Integration[122][142]
- **CTAP (Client-to-Authenticator Protocol):** Kommunikation zwischen Client und Authenticator[139][142]

**Protokoll-Hierarchie:**
```
FIDO2
├── WebAuthn (Web Authentication API)
└── CTAP (Client-to-Authenticator Protocol)
    ├── CTAP 1.0 (U2F-kompatibel)
    └── CTAP 2.1 (aktuell, mit erweiterten Features)
```

---

## 2. Funktionsweise von Passkeys

### Registration-Prozess
1. **Gerät generiert Schlüsselpaar:** Private Key bleibt lokal, Public Key an Server
2. **Biometrische Verifikation:** Touch ID, Face ID, Windows Hello oder PIN
3. **Sichere Speicherung:** Private Key in Hardware Security Module (HSM)
4. **Server-Registrierung:** Public Key und Metadaten werden serverseitig gespeichert

### Authentication-Prozess
1. **Challenge vom Server:** Zufälliger String zur Signierung
2. **Biometrische Freigabe:** Benutzer authentifiziert sich lokal
3. **Challenge-Signierung:** Private Key signiert Challenge kryptographisch
4. **Verifikation:** Server prüft Signatur mit gespeichertem Public Key
5. **Domain-Binding:** Passkey funktioniert nur für registrierte Domain

### Mathematische Grundlagen
**Asymmetrische Kryptographie (RSA/ECDSA):**
- **Schlüsselgenerierung:** (Public Key, Private Key) = KeyGen(Sicherheitsparameter)
- **Signierung:** Signature = Sign(Private_Key, Challenge)
- **Verifikation:** Valid = Verify(Public_Key, Challenge, Signature)

---

## 3. Passkey-Typen

### Device-Bound Passkeys (Hardware-gebunden)
**Eigenschaften:**
- **Höchste Sicherheit:** Private Key kann Gerät niemals verlassen
- **Hardware-Attestation:** Kryptographischer Nachweis der Hardware-Sicherheit
- **Keine Synchronisation:** Ein Passkey pro Gerät

**Anwendungsfälle:**
- Hochsicherheitsumgebungen (Banking, Regierung)[147]
- Enterprise-Administratoren[150]
- Compliance-kritische Anwendungen

### Synced Passkeys (Synchronisierte Passkeys)
**Eigenschaften:**
- **Automatische Synchronisation:** Über iCloud, Google Password Manager, etc.
- **Cross-Device-Verfügbarkeit:** Ein Passkey auf allen Geräten des Ökosystems
- **Benutzerfreundlichkeit:** Nahtlose Nutzung auf mehreren Geräten

**Technische Implementation:**
- **Ende-zu-Ende-Verschlüsselung:** Private Keys verschlüsselt in der Cloud
- **Ecosystem-Abhängigkeit:** Apple (iCloud), Google (Password Manager), Microsoft (geplant)
- **Automatische Wiederherstellung:** Bei Geräteverlust über Cloud-Account

---

## 4. Hardware Security Module Integration

### Apple Secure Enclave
**Technische Spezifikationen:**[143][149]
- **Dedizierte Hardware:** Isolierter Subsystem-Prozessor
- **Biometric-Integration:** Touch ID, Face ID, Optic ID
- **Key-Storage:** Private Keys verlassen niemals die Secure Enclave
- **Attestation:** Hardware-Nachweis der Schlüsselherkunft

### Android TEE (Trusted Execution Environment)
**Implementation:**
- **Hardware-backed Keystore:** Schlüssel in sicherer Hardware
- **StrongBox:** Dediziertes HSM (ab Android 9)
- **Biometric-APIs:** Fingerprint, Face, Iris Integration

### Windows TPM (Trusted Platform Module)
**Features:**
- **Windows Hello Integration:** Biometrische Authentifizierung
- **Platform Attestation:** Gerätenachweis über TPM
- **Credential Guard:** Schutz vor Pass-the-Hash-Angriffen

---

## 5. Cross-Platform-Synchronisation

### Aktuelle Ökosystem-Unterstützung (Stand 2025)

| **Anbieter** | **Geräte** | **Cross-Platform** | **Synchronisation** |
|--------------|------------|-------------------|-------------------|
| **Apple** | iOS, macOS, iPadOS | ❌ Nur Apple-Ökosystem | iCloud Keychain |
| **Google** | Android, Chrome | ✅ Windows, macOS, Android | Password Manager |
| **Microsoft** | Windows | 🚧 In Entwicklung | Geplant für 2025 |

### Google's Cross-Platform-Durchbruch 2024
**Innovation:** Erste plattformübergreifende Passkey-Synchronisation[163]
- **Chrome 129+:** Passkeys in "Google Password Manager" statt "Chrome Profile"
- **Unterstützung:** Windows, macOS, Android (iOS noch nicht verfügbar)
- **Technologie:** Secure cloud sync mit Ende-zu-Ende-Verschlüsselung

### Limitations & Herausforderungen
**Platform Lock-In:**[158][166]
- Apple: Funktioniert nur innerhalb des Apple-Ökosystems
- Google: Beste plattformübergreifende Lösung, aber Chrome-abhängig
- Microsoft: Noch keine Cloud-Synchronisation verfügbar

---

## 6. Sicherheitsanalyse

### Stärken von Passkeys

#### 1. Phishing-Resistenz
**Domain-Binding:** Passkeys sind kryptographisch an die registrierte Domain gebunden[120][123]
- **Unmögliche Weiterleitung:** Funktioniert nicht auf Phishing-Seiten
- **Origin-Verifikation:** WebAuthn prüft automatisch die Domain
- **Schutz vor Proxy-Angriffen:** Selbst sophisticated Phishing-Tools versagen

#### 2. Credential-Theft-Resistenz
**Keine geteilten Geheimnisse:**[126][129]
- **Server-Breach-Schutz:** Nur nutzlose Public Keys auf Servern gespeichert
- **Keylogger-Resistenz:** Keine Tastatureingaben erforderlich
- **Replay-Angriffe:** Challenge-Response verhindert Wiederverwendung

#### 3. Benutzerfreundlichkeit
**Nahtlose Authentifizierung:**[120][126]
- **Biometrische Integration:** Touch ID, Face ID, Fingerprint
- **Keine Passwort-Fatigue:** Nichts zu merken oder einzutippen
- **Schnellere Anmeldung:** 63,8% Erfolgsrate vs. 13,8% bei Passwörtern (Google-Studie)

### Schwächen und Risiken

#### 1. Account Recovery-Herausforderungen
**Geräteverlust-Problem:**[144][159][169]
- **Catastrophic Loss:** Verlust aller Geräte = Kontoverlust
- **Recovery-Komplexität:** Aufwändige Backup-Mechanismen erforderlich
- **User Education:** Benutzer verstehen Recovery-Prozesse oft nicht

#### 2. Ecosystem Lock-In
**Vendor-Abhängigkeit:**[158][164]
- **Migration-Probleme:** Wechsel zwischen Ökosystemen schwierig
- **Standard-Fragmentierung:** Inkompatible Implementierungen
- **Business Continuity:** Abhängigkeit von Big Tech-Anbietern

#### 3. Enterprise-Herausforderungen
**Implementation-Komplexität:**[141][164]
- **Legacy-System-Integration:** Alte Systeme unterstützen WebAuthn nicht
- **Shared Workstation-Probleme:** 31% der Unternehmen nennen dies als Hürde
- **Management-Overhead:** Neue Prozesse für IT-Abteilungen

---

## 7. Enterprise-Adoption (Stand 2025)

### Adoption-Statistiken
**FIDO Alliance Report 2025:**[141][150][161]
- **87%** der US/UK-Unternehmen haben Passkeys implementiert oder sind dabei
- **47%** nutzen Mix aus Device-bound und Synced Passkeys
- **82%** berichten positive Auswirkungen auf User Experience
- **90%** sehen moderate bis starke Sicherheitsverbesserungen

### Enterprise-Benefits
**Quantifizierte Vorteile:**[150]
- **77%** Reduktion der Helpdesk-Anrufe
- **73%** Verbesserung der Produktivität
- **56%** Reduktion der Passwort-Nutzung (von 76%)
- **PayPal:** 70% Reduktion von Account-Takeover-Versuchen[120]

### Implementation-Barrieren
**Haupthindernisse für Nicht-Adopters:**[161][164]
- **43%** Implementierungskopmplexität
- **33%** Kostenbedenken
- **31%** Shared Workstation-Nutzung
- **29%** Unklarheit über Implementation

---

## 8. Account Recovery & Backup-Strategien

### Backup-Methoden

#### 1. Multiple Passkey Registration
**Best Practice:** Registrierung mehrerer Passkeys pro Account[159][169]
- **Verschiedene Geräte:** Smartphone, Laptop, Hardware-Token
- **Verschiedene Ökosysteme:** Apple + Google als Redundanz
- **Hardware Security Keys:** YubiKey als Ultimate Backup

#### 2. Recovery Codes
**Implementation:** Einmalige Backup-Codes bei Passkey-Setup[162]
- **Offline-Speicherung:** Physisch sicher aufbewahren
- **Einmalige Verwendung:** Jeder Code nur einmal nutzbar
- **Secure Generation:** Kryptographisch sichere Zufallsgenerierung

#### 3. Alternative Authentication-Faktoren
**Fallback-Mechanismen:**[165][167]
- **Email Magic Links:** Temporäre Zugangscodes per E-Mail
- **SMS OTP:** Als letzter Ausweg (weniger sicher)
- **Security Questions:** Zusätzliche Verifikation
- **Admin Override:** Enterprise-Umgebungen mit IT-Support

### Circle Smart Account Recovery (Beispiel)
**Two-Phase Recovery-System:**[162]
1. **Registration Phase:** EOA (Externally Owned Account) als Recovery Key
2. **Recovery Phase:** Neuer Passkey-Generierung via Recovery Key

---

## 9. Privacy & Datenschutz

### Biometric Data Protection
**Local Processing Only:**[146]
- **Never Leaves Device:** Biometrische Daten verlassen niemals das Gerät
- **Hardware Isolation:** Secure Enclave/TPM-Schutz
- **No Server Storage:** Keine biometrischen Daten auf Servern
- **Challenge-Response:** Nur kryptographische Signaturen übertragen

### DSGVO-Konformität
**Privacy by Design:**
- **Data Minimization:** Nur notwendige Public Keys gespeichert
- **Purpose Limitation:** Schlüssel nur für Authentifizierung verwendbar
- **User Consent:** Explizite Einwilligung für Passkey-Erstellung
- **Right to Deletion:** Passkey-Löschung jederzeit möglich

---

## 10. Zukunftsausblick 2025-2027

### Industry Trends
**Microsoft's Vision:** "Passkeys replace passwords almost entirely (and we hope this happens soon)"[152]
- **2025:** Major banks embracing passkeys[125][152]
- **2025:** Windows-synced passkeys introduction[152]
- **2027:** Dominant form of authentication (Expert-Prognose)[152]

### Technical Developments
**Post-Quantum Security:**[145]
- **FIDO2 CTAP 2.1:** Potentiell post-quantum-sichere Primitive
- **Hybrid Approaches:** Klassische + Post-Quantum-Kryptographie
- **Future-Proofing:** Algorithmus-Agnostische Implementierungen

### Adoption Predictions
**FIDO Alliance Projections:**[125]
- **End 2025:** 1 in 4 der Top-1000 Websites bieten Passkeys
- **Über 1 Milliarde** Menschen haben mindestens einen Passkey aktiviert
- **15+ Milliarden** Online-Accounts unterstützen Passkeys

---

## 11. Praktische Implementierung

### WebAuthn API Grundlagen
**Registration (JavaScript):**
```javascript
const credential = await navigator.credentials.create({
  publicKey: {
    challenge: challengeFromServer,
    rp: { name: "Example Corp", id: "example.com" },
    user: { id: userID, name: "user@example.com", displayName: "John Doe" },
    pubKeyCredParams: [{ alg: -7, type: "public-key" }],
    authenticatorSelection: {
      authenticatorAttachment: "platform", // oder "cross-platform"
      userVerification: "required"
    }
  }
});
```

**Authentication (JavaScript):**
```javascript
const assertion = await navigator.credentials.get({
  publicKey: {
    challenge: challengeFromServer,
    allowCredentials: [{ id: credentialId, type: "public-key" }],
    userVerification: "required"
  }
});
```

### Server-Side Verification
**Schritte zur Signature-Verifikation:**
1. Challenge-Validierung (Replay-Schutz)
2. Origin-Verifikation (Domain-Binding)
3. Public Key Signature-Verifikation
4. Counter-Verifikation (falls vorhanden)
5. User Verification Flag-Prüfung

---

## 12. Klausur-relevante Definitionen

### Wichtige Begriffe
- **FIDO2:** Oberster Standard für passwordlose Authentifizierung (WebAuthn + CTAP)
- **WebAuthn:** W3C Web API für Public-Key-Credentials in Browsern
- **CTAP:** Client-to-Authenticator Protocol für Hardware-Token-Kommunikation
- **Attestation:** Kryptographischer Hardware-/Software-Nachweis
- **User Verification:** Biometrische oder PIN-basierte lokale Benutzerverifikation
- **Cross-Device Authentication (CDA):** Passkey-Nutzung auf anderen Geräten via QR/Bluetooth

### Sicherheitsmodelle
- **Phishing-Resistenz:** Domain-Binding verhindert Credential-Diebstahl
- **Device-bound:** Private Key kann Hardware niemals verlassen
- **Synced:** Encrypted cloud backup für Cross-Device-Verfügbarkeit
- **Hardware Attestation:** Kryptographischer Nachweis der Schlüssel-Herkunft

---

## 13. Prüfungstipps

### Häufige Klausurfragen
1. **FIDO2-Architektur:** WebAuthn vs. CTAP Unterschiede erklären
2. **Challenge-Response-Protokoll:** Mathematische Schritte der Authentifizierung
3. **Phishing-Resistenz:** Technische Gründe für Domain-Binding
4. **Hardware Security:** Secure Enclave, TPM, TEE Funktionsweisen
5. **Recovery-Strategien:** Backup-Methoden und ihre Sicherheitsimplikationen
6. **Enterprise-Adoption:** Benefits, Barrieren und Lösungsansätze

### Berechnungsaufgaben (selten, aber möglich)
- **Key-Pair-Generierung:** RSA/ECDSA Parameter-Berechnung
- **Challenge-Response-Zeit:** Timeout-Berechnungen für WebAuthn
- **Adoption-ROI:** Kosten-Nutzen-Analyse von Passkey-Implementation

### Vergleichstabellen lernen
- **Passkeys vs. Passwords:** Sicherheit, UX, Implementation
- **Device-bound vs. Synced:** Trade-offs zwischen Sicherheit und Convenience
- **Ökosystem-Vergleich:** Apple vs. Google vs. Microsoft Features

### Aktuelle Entwicklungen 2025
- Google's Cross-Platform-Synchronisation
- Microsoft's geplante Windows-Passkey-Sync
- NIST's WebAuthn-Mandate für US-Behörden
- Banking-Industry-Adoption (PSD2-Compliance)

---

**Quellen:** FIDO Alliance Standards, WebAuthn W3C Specification, Apple/Google/Microsoft Documentation, FIDO Alliance Enterprise Reports 2025, aktuelle Passkey-Sicherheitsstudien