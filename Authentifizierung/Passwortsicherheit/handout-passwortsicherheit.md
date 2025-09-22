# Handout: Passwortsicherheit & Authentifizierung

**Thema:** Passwortsicherheit (Authentifizierung)  
**Datum:** September 2025  
**Bearbeiter:** Ihr Name  

---

## 1. Grundlagen der Passwortsicherheit

### Definition Authentifizierung
- **Authentifizierung:** Prozess zur Überprüfung der Identität eines Benutzers
- **Authentifizierungsfaktoren:** Drei Kategorien
  - **Wissen** (etwas, was man weiß): Passwort, PIN
  - **Besitz** (etwas, was man hat): Smartphone, Token, Chipkarte
  - **Biometrie** (etwas, was man ist): Fingerabdruck, Gesichtserkennung

### Warum sind starke Passwörter wichtig?
- **80% aller Cyberangriffe** basieren auf kompromittierten Passwörtern
- Schwache Passwörter können **innerhalb von Sekunden** geknackt werden
- Hardware-Entwicklung: 20% **jährliche Steigerung** der Brute-Force-Kapazitäten

---

## 2. Kriterien für sichere Passwörter

### Mindestanforderungen 2025
- **Länge:** Mindestens 12 Zeichen (besser 13+ Zeichen)
- **Komplexität:** Kombination aus:
  - Großbuchstaben (A-Z)
  - Kleinbuchstaben (a-z)
  - Zahlen (0-9)
  - Sonderzeichen (!@#$%&*)

### Das Längen-Prinzip
- **"Die Länge ist das, was zählt!"**
- Längere Passwörter sind **exponentiell schwerer** zu knacken
- Beispiel: "mecodia rockt das Internet!" = ~1 Quintilliarde Jahre Rechenzeit

### Was vermeiden?
- **Persönliche Informationen:** Namen, Geburtsdaten, Adressen
- **Einfache Muster:** 123456, abcdef, qwertz
- **Wörterbuchbegriffe:** Standard-Wörter ohne Variation
- **Wiederverwendung:** Gleiches Passwort für mehrere Konten

---

## 3. Methoden zur Passwort-Erstellung

### 1. Satz-Trick (Empfohlen)
- **Beispiel:** "Heute Nachmittag um 16:30 Uhr gehe ich ins Fußballtraining!"
- **Resultat:** HNu16:30giiF!
- **Vorteil:** Leicht merkbar, hohe Sicherheit

### 2. Wort-Trick
- **Methode:** Drei unzusammenhängende Wörter verbinden
- **Beispiel:** FußballPasswortsicherheitBaum
- **Vorteil:** Sehr lang, schwer zu erraten

### 3. Leetspeak-Methode
- **Prinzip:** Buchstaben durch Zahlen/Sonderzeichen ersetzen
- **Beispiel:** Passwortsicherheit → Pa§sw0rts/ch3rhe1t
- **Anwendung:** E→3, S→§, I→1, O→0

### 4. Passwort-Variationen
- **Basis-Passwort** + **Service-Kürzel**
- **Beispiel:** HNu16:30giiF! für Amazon → HNu16:30giiF!Ama
- **Vorteil:** Einzigartigkeit bei Merkbarkeit

---

## 4. Zwei-Faktor-Authentifizierung (2FA)

### Definition & Funktionsweise
- **2FA:** Kombination zweier **unabhängiger** Authentifizierungsfaktoren
- **Schutz:** Selbst bei Passwort-Kompromittierung bleibt Zugang verwehrt
- **Effektivität:** Verhindert **99,9%** der kontobasierten Angriffe

### 2FA-Methoden im Vergleich

| **Methode** | **Sicherheit** | **Benutzerfreundlichkeit** | **Kosten** |
|-------------|----------------|---------------------------|------------|
| **SMS/Telefon** | Mittel | Hoch | Niedrig |
| **Authenticator-Apps** | Hoch | Mittel | Niedrig |
| **Hardware-Token** | Sehr hoch | Mittel | Mittel-Hoch |
| **Biometrische Verfahren** | Hoch | Sehr hoch | Hoch |

### Empfohlene Authenticator-Apps
- Microsoft Authenticator
- Google Authenticator
- privacyIDEA Authenticator

---

## 5. Passwort-Manager

### Vorteile
- **Automatische Generierung** sicherer Passwörter
- **Sichere Speicherung** mit Verschlüsselung
- **Einzigartiges Passwort** für jeden Service
- **Automatisches Ausfüllen** von Login-Daten

### Top-Empfehlungen 2025
1. **1Password:** Premium-Features, beste Benutzerfreundlichkeit
2. **Bitwarden:** Open-Source, kostenlose Version verfügbar
3. **NordPass:** Moderne Oberfläche, Zero-Knowledge-Architektur
4. **Keeper:** Testsieger, bestes Gesamtpaket

---

## 6. Biometrische Authentifizierung

### Vorteile
- **Einzigartig:** Biologische Merkmale schwer zu fälschen
- **Benutzerfreundlich:** Keine Passwörter merken nötig
- **Schnell:** Reibungslose Authentifizierung

### Nachteile & Risiken
- **Unveränderlich:** Bei Kompromittierung nicht "zurücksetzbar"
- **Datenschutz:** DSGVO-konforme Speicherung erforderlich
- **KI-Angriffe:** Deepfakes können Gesichtserkennung täuschen
- **Physische Veränderungen:** Verletzungen, Alter können Probleme verursachen

---

## 7. Schutz vor Phishing-Angriffen

### Erkennungsmerkmale
- **Dringlichkeit:** "Sofort handeln" Aufforderungen
- **Verdächtige Links:** Unbekannte URLs, Tippfehler in Domains
- **Rechtschreibfehler:** Unprofessionelle Sprache
- **Ungewöhnliche Absender:** Gefälschte E-Mail-Adressen

### Schutzmaßnahmen
- **2FA aktivieren:** Zusätzlicher Schutz bei gestohlenen Passwörtern
- **URL-Überprüfung:** Immer Adressleiste kontrollieren
- **Lesezeichen verwenden:** Für wichtige Login-Seiten
- **Regelmäßige Schulungen:** Awareness-Training

---

## 8. Klausur-relevante Definitionen

**Multi-Faktor-Authentifizierung (MFA):** Authentifizierungsverfahren mit mehr als zwei Faktoren

**Brute-Force-Angriff:** Systematisches Ausprobieren aller möglichen Passwort-Kombinationen

**Phishing:** Social Engineering-Angriff zur Erlangung von Zugangsdaten

**Zero-Knowledge-Architektur:** System, bei dem der Anbieter keinen Zugriff auf Nutzerdaten hat

**DMARC/SPF/DKIM:** E-Mail-Authentifizierungsstandards gegen Spoofing

---

## 9. Prüfungstipps

### Häufige Klausurfragen
1. **Berechnung der Passwort-Kombinationen** bei gegebener Länge/Zeichensatz
2. **Vergleich verschiedener 2FA-Methoden** (Vor-/Nachteile)
3. **Bewertung von Passwort-Beispielen** nach Sicherheitskriterien
4. **Identifikation von Phishing-Merkmalen**
5. **DSGVO-Aspekte** bei biometrischen Daten

### Lernempfehlung
- **Verstehen statt auswendig lernen:** Prinzipien der Passwortsicherheit
- **Praktische Anwendung:** Eigene sichere Passwörter erstellen
- **Aktuelle Zahlen merken:** 80% Cyberangriffe, 99,9% 2FA-Schutz

---

**Quellen:** BSI Deutschland, Verizon Data Breach Report 2025, Microsoft Security Research, aktuelle Studien zur Passwortsicherheit