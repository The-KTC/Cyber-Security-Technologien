# Interaktive Übung: Passwort-Security-Challenge
## Gemeinsam lernen durch praktische Anwendung

---

## Übungskonzept (60 Minuten)

**Ziel:** Teilnehmende durch praktische Übungen für Passwortsicherheit sensibilisieren und gemeinsam sichere Authentifizierungsstrategien entwickeln.

**Format:** Mix aus Gruppenarbeit, praktischen Demonstrationen und interaktiven Challenges

**Teilnehmerzahl:** 15-30 Personen

---

## Phase 1: Ice-Breaker "Passwort-Mythen" (10 Minuten)

### Aktivität: Mythos oder Wahrheit?
**Durchführung:**
1. Teilnehmende stehen in der Mitte des Raums
2. Bei "Mythos" gehen sie nach links, bei "Wahrheit" nach rechts
3. Nach jeder Aussage kurze Erklärung der richtigen Antwort

### Aussagen zum Bewerten:

**1. "Ein 8-stelliges Passwort mit Zahlen kann in 15 Minuten geknackt werden"**
- ✅ **Wahrheit:** Mit moderner Hardware möglich[1]
- **Lerneffekt:** Länge ist entscheidender als bisher gedacht

**2. "Regelmäßiger Passwort-Wechsel erhöht die Sicherheit"**
- ❌ **Mythos:** Führt oft zu schwächeren Passwörtern (NIST-Empfehlung)
- **Lerneffekt:** Starke, einzigartige Passwörter sind wichtiger als häufige Wechsel

**3. "2FA verhindert 99,9% aller Account-Übernahmen"**
- ✅ **Wahrheit:** Microsoft-Studie bestätigt dies[46]
- **Lerneffekt:** 2FA ist extrem effektiv

**4. "Biometrische Daten können wie Passwörter geändert werden"**
- ❌ **Mythos:** Sind unveränderlich[47][50]
- **Lerneffekt:** Datenschutz-Risiken verstehen

**5. "Passwort-Manager sind unsicherer als das Merken von Passwörtern"**
- ❌ **Mythos:** Manager ermöglichen viel stärkere Passwörter[42]
- **Lerneffekt:** Vorurteile abbauen

---

## Phase 2: Gruppen-Challenge "Sicheres Passwort erstellen" (15 Minuten)

### Vorbereitung:
- **4-5 Gruppen** zu je 4-6 Personen
- Jede Gruppe erhält verschiedene Materialien:
  - Würfel (für Zufallspasswörter)
  - Zettel und Stifte
  - Timer

### Challenge 1: Der Satz-Trick (5 Minuten)
**Aufgabe:** Jede Gruppe erstellt mit der Satz-Methode ein sicheres Passwort

**Anleitung:**
1. Überlegen Sie sich einen persönlichen, aber nicht privaten Satz
2. Verwenden Sie die Anfangsbuchstaben + Zahlen/Sonderzeichen
3. Testen Sie die Merkbarkeit in der Gruppe

**Beispiel-Kategorien für Gruppen:**
- **Gruppe 1:** Film-/Serien-Zitate
- **Gruppe 2:** Liedtexte
- **Gruppe 3:** Sprichwörter/Redewendungen
- **Gruppe 4:** Sport-/Hobby-Bezug
- **Gruppe 5:** Reise-/Traum-Bezug

**Muster-Lösung:**
- Satz: "Ich schaue jeden Freitag um 20:15 Uhr Tatort & trinke dabei 2 Bier!"
- Passwort: "IsjFu20:15T&td2B!"

### Challenge 2: Passwort-Variationen (5 Minuten)
**Aufgabe:** Entwickeln Sie aus Ihrem Basis-Passwort Variationen für verschiedene Services

**System:**
- Basis-Passwort + erste 3 Buchstaben des Service-Namens
- Diskutieren Sie Vor- und Nachteile dieses Systems

### Challenge 3: Sicherheits-Bewertung (5 Minuten)
**Aufgabe:** Bewerten Sie die Passwörter der anderen Gruppen
- **Kriterien:** Länge, Komplexität, Merkbarkeit, Einzigartigkeit
- **Punktesystem:** 1-5 Punkte pro Kriterium

---

## Phase 3: Praktische Demonstration "2FA-Setup" (15 Minuten)

### Live-Demo: Authenticator-App einrichten
**Benötigte Technik:**
- Laptop/Beamer für Präsentation
- Test-Account (z.B. Microsoft oder Google)
- Smartphone mit installierter Authenticator-App

### Schritt-für-Schritt Demo:
**1. Account-Einstellungen öffnen** (2 Min)
- Navigation zu Sicherheitseinstellungen
- 2FA-Option finden und aktivieren

**2. Authenticator-App verwenden** (5 Min)
- QR-Code scannen
- Backup-Codes anzeigen und Wichtigkeit erklären
- Ersten Test-Login durchführen

**3. Verschiedene 2FA-Methoden vergleichen** (5 Min)
**Interaktive Abstimmung:** "Welche Methode würden Sie nutzen?"

| Methode | Sicherheit | Benutzerfreundlichkeit | Kosten |
|---------|------------|------------------------|---------|
| SMS | 🟡 Mittel | 🟢 Sehr hoch | 🟢 Kostenlos |
| Authenticator-App | 🟢 Hoch | 🟡 Mittel | 🟢 Kostenlos |
| Hardware-Token | 🟢 Sehr hoch | 🟡 Mittel | 🔴 30-50€ |
| Biometrie | 🟡 Hoch* | 🟢 Sehr hoch | 🟡 In Gerät |

**Diskussionspunkte:**
- Wann ist welche Methode am besten geeignet?
- Wie gehen Sie mit Backup-Situationen um?

### Hands-On Aktivität (3 Min)
**Auftrag:** "Richten Sie 2FA für einen Ihrer wichtigen Accounts ein"
- Teilnehmende mit Smartphones können direkt mitmachen
- Unterstützung durch Sitznachbarn ("Buddy-System")

---

## Phase 4: Rollenspiel "Phishing-Detective" (15 Minuten)

### Vorbereitung:
**Echte Phishing-E-Mails sammeln** (anonymisiert) oder realistische Beispiele erstellen

### Aktivität 1: E-Mail-Analyse (8 Minuten)
**Setup:**
- Jede Gruppe erhält 2-3 verschiedene E-Mails (Mix aus echt und Phishing)
- **Aufgabe:** Identifizieren Sie Phishing-Versuche und begründen Sie Ihre Entscheidung

**Beispiel-E-Mails:**

**E-Mail 1 (Phishing):**
```
Von: amazone-security@amazon-protection.net
Betreff: DRINGEND: Ihr Konto wurde gesperrt!!!

Sehr geehrte Kunden,

wir haben verdächtige Aktivitäten in ihrem Konto festgestellt.
Klicken Sie sofort hier um ihr Konto zu entsperren:
www.amazon-account-verification.net/login

Sie haben nur 24 Stunden Zeit!

Ihr Amazon Team
```

**Erkennungsmerkmale:**
- Falsche Domain (amazon-protection.net)
- Rechtschreibfehler ("ihrem", "ihr")
- Zeitdruck
- Verdächtige URL

**E-Mail 2 (Legitim):**
```
Von: account-update@amazon.com
Betreff: Ihre Bestellung #123-456789 wurde versandt

Hallo Max Mustermann,

Ihre Bestellung wurde heute versandt.
Verfolgen Sie Ihre Sendung hier: [Button: Sendung verfolgen]

Lieferadresse:
Musterstraße 123, 12345 Musterstadt

Vielen Dank für Ihren Einkauf!
Ihr Amazon-Team
```

### Aktivität 2: Phishing-Simulation (7 Minuten)
**Durchführung:**
1. **Freiwillige/r** spielt Phishing-Anrufer
2. **Andere Person** ist potentielles Opfer
3. **Gruppe** beobachtet und notiert Manipulation-Techniken

**Szenario-Beispiele:**
- **"Microsoft-Support" ruft an:** Computer sei infiziert
- **"Bank-Mitarbeiter":** Karte wurde missbraucht, PIN bestätigen
- **"IT-Abteilung":** Passwort-Update erforderlich

**Reflexion:**
- Welche psychologischen Tricks wurden verwendet?
- Wie hätte man den Angriff erkennen können?
- Was sind angemessene Reaktionen?

---

## Phase 5: Gemeinsamer Aktionsplan (5 Minuten)

### Aktivität: "Security-Vorsätze"
**Jede/r Teilnehmende schreibt auf einen Zettel:**

1. **Eine Sache, die ich HEUTE umsetze:**
   - Beispiele: "2FA für Gmail aktivieren", "Passwort-Manager installieren"

2. **Eine Sache, die ich diese WOCHE umsetze:**
   - Beispiele: "Alle schwachen Passwörter ersetzen", "Familie über Phishing aufklären"

3. **Eine Sache, die ich LANGFRISTIG plane:**
   - Beispiele: "Biometrische Systeme kritisch bewerten", "Passkeys ausprobieren"

### Freiwillige Sharing-Runde (3 Minuten)
- Teilnehmende teilen ihre wichtigsten Erkenntnisse
- Sammeln von konkreten nächsten Schritten

### Buddy-System etablieren (2 Minuten)
- Teilnehmende finden sich zu Zweier-Teams
- Austausch von Kontaktdaten für gegenseitige Unterstützung
- Vereinbarung eines Check-ins nach 2 Wochen

---

## Zusatz-Aktivitäten (falls Zeit übrig)

### Bonus-Challenge 1: Passwort-Stärke schätzen
**Material:** Verschiedene Passwort-Beispiele auf Karten
**Aufgabe:** Sortieren Sie nach geschätzter Knack-Zeit
**Auflösung:** Mit Online-Tool (howsecureismypassword.net) testen

### Bonus-Challenge 2: 2FA-Methoden-Matching
**Material:** Karten mit verschiedenen Situationen und 2FA-Methoden
**Aufgabe:** Ordnen Sie die optimale 2FA-Methode zu:
- Online-Banking → Hardware-Token
- Social Media → Authenticator-App
- Arbeitsplatz-PC → Biometrische Anmeldung + PIN

### Bonus-Challenge 3: Sicherheits-Mythen Interview
**Durchführung:**
- Ein/e Teilnehmende/r ist "Sicherheits-Experte/in"
- Andere stellen Fragen zu Passwort-Mythen
- Expertin/Experte muss Mythen von Fakten trennen

---

## Materialien-Checkliste

### Für die Durchführung benötigt:
- [ ] **Flipchart** und Marker für Gruppenarbeit
- [ ] **Timer** oder Stoppuhr
- [ ] **Würfel** für Zufalls-Passwort-Generierung
- [ ] **Zettel und Stifte** für alle Teilnehmenden
- [ ] **Laptop und Beamer** für Demonstrationen
- [ ] **Smartphone** mit verschiedenen Authenticator-Apps
- [ ] **WLAN-Zugang** für praktische Übungen
- [ ] **Ausgedruckte E-Mail-Beispiele** (je 3-4 Kopien)
- [ ] **Klebepunkte** für Abstimmungen

### Digitale Hilfsmittel:
- [ ] **Test-Accounts** für 2FA-Demo (Gmail, Microsoft)
- [ ] **Passwort-Stärke-Checker** (howsecureismypassword.net)
- [ ] **QR-Code-Generator** für eigene Beispiele
- [ ] **Phishing-Beispiele** (aus aktuellen Sammlungen)

---

## Lernerfolgs-Messung

### Abschließende Mini-Umfrage (optional):
**1. Wissen-Test (3 Multiple-Choice-Fragen):**
- Was macht ein Passwort am sichersten? (a) Komplexität (b) Länge (c) Häufige Änderung
- Wie viele Account-Übernahmen verhindert 2FA? (a) 50% (b) 90% (c) 99,9%
- Was ist das größte Problem bei biometrischen Daten? (a) Ungenauigkeit (b) Kosten (c) Unwiderruflichkeit

**2. Selbsteinschätzung (1-5 Skala):**
- Wie sicher fühlen Sie sich jetzt beim Erstellen von Passwörtern?
- Wie wahrscheinlich werden Sie 2FA aktivieren?
- Wie gut können Sie Phishing-Versuche erkennen?

**3. Feedback zur Übung:**
- Was war am hilfreichsten?
- Was könnte verbessert werden?
- Würden Sie die Übung weiterempfehlen?

---

## Moderations-Tipps

### Für eine erfolgreiche Durchführung:
1. **Energie hoch halten:** Kurze Pausen zwischen den Phasen
2. **Alle einbeziehen:** Ruhigere Teilnehmende gezielt ansprechen
3. **Praxis fokussieren:** Weniger Theorie, mehr Hands-On
4. **Fehler erlauben:** Lernen aus Fehlern ist besonders wertvoll
5. **Zeitmanagement:** Lieber eine Aktivität weniger, aber dafür gründlich

### Schwierige Situationen meistern:
- **"Ist doch alles übertrieben":** Mit konkreten Schadensfällen argumentieren
- **Technische Probleme:** Immer Plan B bereit haben (Screenshots statt Live-Demo)
- **Verschiedene Vorerfahrungen:** Buddy-System nutzen (Erfahrene helfen Anfängern)

### Erfolgs-Indikatoren:
- Teilnehmende setzen während der Übung konkrete Maßnahmen um
- Angeregte Diskussionen zwischen den Teilnehmenden
- Konkrete Fragen zu individuellen Situationen
- Positive Rückmeldungen zur Praxisrelevanz

---

**Diese Übung macht Passwortsicherheit erlebbar und motiviert zu konkreten Verbesserungen der persönlichen Cyber-Hygiene!**