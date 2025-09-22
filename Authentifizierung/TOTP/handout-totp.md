# Handout: TOTP (Time-based One-Time Password)

**Thema:** TOTP-Authentifizierung  
**Datum:** September 2025  
**Bearbeiter:** Ihr Name  

---

## 1. Grundlagen von TOTP

### Definition
**TOTP (Time-based One-Time Password):** Algorithmus zur Erzeugung zeitlich limitierter Einmalkennwörter für die Zwei-Faktor-Authentifizierung, standardisiert als **RFC 6238** (Mai 2011)

### Historische Entwicklung
- **2005:** HOTP (RFC 4226) - Zählerbasierte Einmalpasswörter
- **2011:** TOTP (RFC 6238) - Zeitbasierte Weiterentwicklung von HOTP
- **Entwickelt von:** Initiative For Open Authentication (OATH)
- **Standardisiert durch:** Internet Engineering Task Force (IETF)

### Funktionsprinzip
TOTP kombiniert zwei Faktoren zu einem Einmalpasswort:
1. **Shared Secret (K):** Geheimer Schlüssel zwischen Client und Server
2. **Zeit (T):** Aktuelle Uhrzeit in 30-Sekunden-Intervallen

**Grundformel:** `TOTP = HOTP(K, T)`

---

## 2. Mathematische Grundlagen

### Zeit-Berechnung
```
T = floor((Current Unix Time - T0) / X)
```
- **T0:** Start-Zeitpunkt (meist 0 = 1. Januar 1970)
- **X:** Zeitintervall (Standard: 30 Sekunden)
- **T:** Zeitschritt-Wert für HMAC-Berechnung

### HMAC-Algorithmus
**TOTP = HMAC-SHA(K, T) mod 10^d**

- **K:** Shared Secret (Base32-codiert)
- **T:** Zeitschritt (8-Byte Big-Endian)
- **SHA:** Hash-Funktion (SHA-1, SHA-256, SHA-512)
- **d:** Stellenanzahl (meist 6, selten 8)

### Implementierungsdetails
1. **Unix-Zeit** durch 30 teilen → Zeitschritt T
2. **HMAC** berechnen mit Secret K und Zeit T
3. **Dynamic Truncation** auf 4 Bytes
4. **Modulo 10^6** für 6-stelligen Code

---

## 3. Technische Spezifikationen

### RFC 6238 Anforderungen
**R1:** Zugang zu aktueller Unix-Zeit erforderlich
**R2:** Shared Secret zwischen Prover und Verifier
**R3:** Verwendung von HOTP als Basis-Algorithmus
**R4:** Gleiche Zeitschritt-Größe (X) für beide Parteien
**R5:** Eindeutiger Secret pro Benutzer
**R6:** Zufällige Secret-Generierung empfohlen
**R7:** Sichere Speicherung der Secrets

### Standard-Parameter
- **Zeitintervall:** 30 Sekunden (empfohlen)
- **Code-Länge:** 6 Stellen (Standard), 8 Stellen (optional)
- **Hash-Algorithmus:** SHA-1 (Standard), SHA-256/SHA-512 (optional)
- **Toleranzfenster:** ±1 Zeitschritt (±30 Sekunden)

### Secret-Format
- **Länge:** 160 Bit (20 Bytes) minimum
- **Encoding:** Base32 für QR-Codes
- **Beispiel:** `JBSWY3DPEHPK3PXP` (Google Authenticator Format)

---

## 4. TOTP vs. andere Verfahren

### TOTP vs. HOTP
| **Aspekt** | **TOTP** | **HOTP** |
|------------|----------|----------|
| **Basis** | Zeit | Zähler |
| **Synchronisation** | Zeitserver | Manuell |
| **Gültigkeit** | 30 Sekunden | Bis zur Nutzung |
| **Out-of-Sync** | Zeitprobleme | Zählerprobleme |
| **Benutzerfreundlichkeit** | Höher | Niedriger |

### TOTP vs. SMS
| **Kriterium** | **TOTP** | **SMS** |
|---------------|----------|---------|
| **Sicherheit** | Hoch | Mittel |
| **Phishing-Resistenz** | Nein | Nein |
| **SIM-Swapping** | Resistent | Anfällig |
| **Offline-Fähigkeit** | Ja | Nein |
| **Kosten** | Keine | Potentiell |

---

## 5. Implementierung & Anwendung

### QR-Code Format (Google Authenticator)
```
otpauth://totp/Label?secret=SECRET&issuer=ISSUER&algorithm=SHA1&digits=6&period=30
```

**Parameter:**
- **Label:** Account-Bezeichnung (z.B. "user@example.com")
- **Secret:** Base32-codierter geheimer Schlüssel
- **Issuer:** Dienst-Name (z.B. "Google", "GitHub")
- **Algorithm:** SHA1, SHA256, SHA512
- **Digits:** 6 oder 8
- **Period:** Zeitintervall in Sekunden (Standard: 30)

### Beliebte TOTP-Apps
**Empfohlene Authenticator-Apps 2025:**
1. **Microsoft Authenticator:** Cloud-Backup, Push-Notifications
2. **Google Authenticator:** Weit verbreitet, einfach
3. **2FAS:** Open-Source, iCloud-Sync
4. **Ente Auth:** Privacy-fokussiert, E2E-verschlüsselt
5. **Authy:** Multi-Device-Sync (wird eingestellt)

### Hardware-Token
- **YubiKey:** OATH-TOTP Standard
- **RSA SecurID:** Proprietäres System
- **REINER SCT Authenticator:** Deutsche Hardware-Lösung

---

## 6. Sicherheitsaspekte

### Stärken von TOTP
- **Zeitbasierte Gültigkeit:** Codes verfallen automatisch
- **Offline-Generierung:** Keine Netzwerkverbindung nötig
- **Standardisiert:** RFC 6238, herstellerunabhängig
- **Weit verbreitet:** Unterstützt von 90%+ der 2FA-Services

### Schwachstellen & Risiken

#### 1. Nicht Phishing-resistent
- **Problem:** Code kann in Echtzeit weitergeleitet werden
- **Angriff:** Modlishka, EvilProxy für automatisiertes Phishing
- **Zeitfenster:** 30 Sekunden reichen für schnelle Weiterleitung

#### 2. Secret-Kompromittierung
- **Backup-Probleme:** Screenshots von QR-Codes unsicher
- **App-Extraktion:** Root/Jailbreak ermöglicht Secret-Zugriff
- **Cloud-Sync:** Unverschlüsselte Backups anfällig

#### 3. Zeit-Synchronisationsprobleme
- **Clock Drift:** Zeitabweichung zwischen Client/Server
- **Network Latency:** Verzögerung bei der Übertragung
- **Toleranzfenster:** Balance zwischen Sicherheit und Usability

---

## 7. Angriffsvektoren & Schutzmaßnahmen

### Häufige Angriffe
**1. Real-Time Phishing**
- **Methode:** Proxy-Server fängt TOTP in Echtzeit ab
- **Schutz:** Phishing-Awareness, URL-Überprüfung

**2. SIM-Swapping (bei SMS-Fallback)**
- **Methode:** Übernahme der Telefonnummer
- **Schutz:** Keine SMS als Backup verwenden

**3. Malware (OTP-Bots)**
- **Methode:** Malware stiehlt SMS/Push-Nachrichten
- **Schutz:** Sichere Apps verwenden, keine SMS-OTP

**4. Social Engineering**
- **Methode:** Nutzer zur Code-Preisgabe verleiten
- **Schutz:** Aufklärung, niemals Codes weitergeben

### BSI-Bewertung (2024)
**TOTP-Apps:** ⚠️ Mittlere Sicherheit
- **Stärken:** Offline, weit verbreitet
- **Schwächen:** Nicht phishing-resistent, Secret-Kompromittierung
- **Empfehlung:** Für normale Anwendungen geeignet

---

## 8. Best Practices

### Für Benutzer
**Einrichtung:**
- Backup-Codes vor TOTP-Setup sichern
- QR-Code niemals als Screenshot speichern
- Secret nur in verschlüsselten Passwort-Managern ablegen

**Täglicher Gebrauch:**
- Apps regelmäßig updaten
- Zeiteinstellungen automatisch synchronisieren
- Mehrere Authenticator-Apps für Redundanz

**Bei Problemen:**
- Zeitsynchronisation überprüfen (NTP)
- Toleranzfenster beachten (±30 Sekunden)
- Backup-Codes für Notfall bereithalten

### Für Entwickler
**Implementation:**
- RFC 6238 strikt befolgen
- Secret-Länge: mindestens 160 Bit
- Toleranzfenster: maximal ±1 Zeitschritt
- Rate-Limiting gegen Brute-Force

**Sicherheit:**
- Secrets niemals in Logs ausgeben
- Sichere Zufallsgenerierung verwenden
- Time-based replay protection implementieren
- HTTPS für alle TOTP-bezogenen APIs

---

## 9. Synchronisationsprobleme

### Häufige Ursachen
1. **Clock Drift:** Interne Uhren laufen auseinander
2. **Zeitzonenprobleme:** Falsche Zeitzone eingestellt
3. **Netzwerklatenz:** Verzögerung bei der Übertragung
4. **Hardware-Alterung:** Quarz-Oszillatoren werden ungenau

### Lösungsansätze
**Automatische Synchronisation:**
- Server erkennt Zeitversatz automatisch
- Funktioniert bei voreilenden Tokens
- Bei nachgehenden Tokens schwierig zu unterscheiden

**Manuelle Synchronisation:**
- Zwei aufeinanderfolgende OTPs eingeben
- Server berechnet Zeitversatz
- Präzise, aber benutzerunfreundlich

**Erweiterte Toleranzfenster:**
- ±2 oder ±3 Zeitschritte akzeptieren
- Reduziert Usability-Probleme
- Verringert Sicherheit geringfügig

---

## 10. Klausur-relevante Formeln & Definitionen

### Wichtige Formeln
**Zeitschritt-Berechnung:**
```
T = floor((Unix_Time - T0) / 30)
```

**TOTP-Generierung:**
```
TOTP = HMAC-SHA1(K, T) mod 10^6
```

**QR-Code URI:**
```
otpauth://totp/LABEL?secret=SECRET&issuer=ISSUER
```

### Definitionen für die Klausur
- **RFC 6238:** IETF-Standard für TOTP (Mai 2011)
- **Shared Secret:** Geheimer 160-Bit-Schlüssel (Base32-codiert)
- **Zeitschritt:** 30-Sekunden-Intervall seit Unix-Epoche
- **Dynamic Truncation:** Verkürzung des HMAC auf 4 Bytes
- **Clock Drift:** Zeitabweichung zwischen Token und Server
- **Toleranzfenster:** Akzeptierte Zeitabweichung (±30s)

### Berechnungsbeispiel
**Gegeben:** Unix-Zeit = 1695374400, Secret = "JBSWY3DPEHPK3PXP"
1. **T = floor(1695374400 / 30) = 56512480**
2. **HMAC-SHA1(Secret, 56512480) = [Byte-Array]**
3. **Dynamic Truncation + mod 10^6 = 123456**

---

## 11. Prüfungstipps

### Häufige Klausurfragen
1. **TOTP-Algorithmus:** Schritt-für-Schritt-Berechnung
2. **Sicherheitsvergleich:** TOTP vs. SMS vs. Hardware-Token
3. **Synchronisationsprobleme:** Ursachen und Lösungen
4. **RFC 6238 Anforderungen:** R1-R7 aufzählen und erklären
5. **QR-Code-Format:** Parameter erläutern
6. **Angriffsvektoren:** Phishing, Secret-Kompromittierung
7. **Best Practices:** Sichere Implementation und Nutzung

### Lernstrategie
- **Verstehen der Zeitberechnung:** Unix-Zeit, Zeitschritte
- **HMAC-Prinzip:** Hash-based Message Authentication
- **Praktische Anwendung:** QR-Code-Setup verstehen
- **Sicherheitsbewertung:** Stärken/Schwächen argumentieren

### Rechenaufgaben vorbereiten
- Zeitschritt-Berechnung mit verschiedenen Unix-Zeiten
- TOTP-Code-Validierung in Toleranzfenstern
- Clock-Drift-Berechnungen
- Secret-Entropie und Sicherheitsbewertung

---

**Quellen:** RFC 6238, BSI 2FA-Bewertung, OATH Initiative, Microsoft/Google Authenticator Dokumentation, aktuelle TOTP-Sicherheitsstudien 2025