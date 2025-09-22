# Interaktive Übung: TOTP-Labor
## Hands-On Workshop zu Time-based One-Time Passwords

---

## Übungskonzept (90 Minuten)

**Ziel:** Teilnehmende erlernen TOTP durch praktische Implementierung, Experimente und Problemlösung mit realen Szenarien.

**Format:** Progressive Labs mit steigendem Schwierigkeitsgrad, Pair Programming und gemeinsame Problemlösung

**Teilnehmerzahl:** 12-20 Personen (Laptop erforderlich)

**Voraussetzungen:** Grundkenntnisse Python, Smartphone mit Authenticator-App

---

## Lab-Setup & Vorbereitung (10 Minuten)

### Benötigte Tools
**Für jeden Teilnehmenden:**
- Laptop mit Python 3.8+
- Smartphone mit installierter Authenticator-App:
  - **Empfohlen:** 2FAS, Microsoft Authenticator, Google Authenticator
- **Code-Editor:** VS Code, PyCharm oder ähnlich
- **Internet-Zugang:** Für Package-Installation

### Python-Environment Setup
```bash
# Virtuelle Umgebung erstellen
python -m venv totp_lab
source totp_lab/bin/activate  # Linux/Mac
# totp_lab\Scripts\activate   # Windows

# Benötigte Packages installieren
pip install qrcode[pil] pyotp cryptography
```

### Lab-Repository clonen
```bash
git clone https://github.com/totp-lab/exercises.git
cd totp-lab
```

*Hinweis: Repository wird für die Übung bereitgestellt mit Starter-Code und Test-Cases*

---

## Phase 1: TOTP-Grundlagen verstehen (20 Minuten)

### Lab 1.1: Zeit-Mathematik verstehen (8 Min)

**Aufgabe:** Implementieren Sie die zeitbasierte Komponente von TOTP

```python
import time
from datetime import datetime

def unix_to_timestep(unix_time, period=30, t0=0):
    """
    Konvertiert Unix-Zeit zu TOTP-Zeitschritt
    
    Args:
        unix_time: Unix-Timestamp
        period: Zeitintervall in Sekunden
        t0: Start-Zeit (meist 0)
    
    Returns:
        Zeitschritt-Wert
    """
    # TODO: Implementieren Sie die Zeitschritt-Berechnung
    pass

# Test-Cases
test_times = [
    (1695374400, "22.09.2025 00:00:00"),  # Genau auf Zeitgrenze
    (1695374415, "22.09.2025 00:00:15"),  # Mitte des Zeitfensters
    (1695374429, "22.09.2025 00:00:29"),  # Ende des Zeitfensters
    (1695374430, "22.09.2025 00:00:30"),  # Nächstes Zeitfenster
]

print("=== Zeitschritt-Tests ===")
for unix_time, readable in test_times:
    timestep = unix_to_timestep(unix_time)
    print(f"{readable}: Unix={unix_time} → T={timestep}")
```

**Erwartete Ausgabe:**
```
22.09.2025 00:00:00: Unix=1695374400 → T=56512480
22.09.2025 00:00:15: Unix=1695374415 → T=56512480  # Gleicher Timestep!
22.09.2025 00:00:29: Unix=1695374429 → T=56512480  # Immer noch gleich
22.09.2025 00:00:30: Unix=1695374430 → T=56512481  # Neuer Timestep
```

**Lernziel:** Verstehen, dass TOTP-Codes innerhalb des 30-Sekunden-Fensters identisch sind.

### Lab 1.2: HMAC-Berechnung implementieren (12 Min)

**Aufgabe:** Implementieren Sie den HMAC-Teil des TOTP-Algorithmus

```python
import hmac
import hashlib
import struct
import base64

def calculate_hmac(secret_b32, timestep, algorithm='sha1'):
    """
    Berechnet HMAC für TOTP
    
    Args:
        secret_b32: Base32-encodierter Secret
        timestep: Zeitschritt-Wert
        algorithm: Hash-Algorithmus ('sha1', 'sha256', 'sha512')
    
    Returns:
        HMAC-Bytes
    """
    # TODO: Implementieren Sie HMAC-Berechnung
    # Hinweise:
    # 1. Secret von Base32 dekodieren
    # 2. Zeitschritt zu 8-Byte Big-Endian konvertieren
    # 3. HMAC mit gewähltem Algorithmus berechnen
    pass

# Test mit bekannten Werten
SECRET = "JBSWY3DPEHPK3PXP"  # Base32 für "Hello World!"
TIMESTEP = 56512480

mac_bytes = calculate_hmac(SECRET, TIMESTEP)
print(f"HMAC-Bytes: {mac_bytes.hex()}")
print(f"HMAC-Länge: {len(mac_bytes)} Bytes")

# Verschiedene Hash-Algorithmen testen
for algo in ['sha1', 'sha256', 'sha512']:
    mac = calculate_hmac(SECRET, TIMESTEP, algo)
    print(f"{algo.upper()}: {len(mac)} Bytes → {mac.hex()[:16]}...")
```

**Gruppendiskussion:** Warum werden unterschiedliche Hash-Algorithmen unterschiedlich lange Outputs haben?

### Lab 1.3: Dynamic Truncation verstehen (Bonus)

**Für schnelle Gruppen:**
```python
def dynamic_truncation(hmac_bytes):
    """
    Implementiert RFC 6238 Dynamic Truncation
    """
    # TODO: Implementieren Sie die Truncation
    # 1. Letztes Byte als Offset (nur niedrigste 4 Bits)
    # 2. 4 aufeinanderfolgende Bytes ab Offset extrahieren
    # 3. Höchstes Bit löschen (für positive Zahl)
    # 4. Als 32-Bit Integer zurückgeben
    pass
```

---

## Phase 2: Praktische TOTP-Implementation (25 Minuten)

### Lab 2.1: Vollständiger TOTP-Generator (15 Min)

**Pair Programming Aufgabe:** Arbeiten Sie zu zweit an der Implementierung

```python
import time

class TOTPGenerator:
    def __init__(self, secret_b32, algorithm='sha1', digits=6, period=30):
        self.secret = secret_b32
        self.algorithm = algorithm
        self.digits = digits
        self.period = period
    
    def generate_totp(self, timestamp=None):
        """
        Generiert TOTP-Code für gegebene Zeit
        """
        if timestamp is None:
            timestamp = int(time.time())
        
        # TODO: Implementieren Sie die vollständige TOTP-Generierung
        # Nutzen Sie Ihre Funktionen aus Phase 1
        
        # 1. Zeitschritt berechnen
        # 2. HMAC berechnen  
        # 3. Dynamic Truncation
        # 4. Modulo 10^digits für finale Code-Länge
        pass
    
    def get_current_code(self):
        """Aktueller TOTP-Code"""
        return self.generate_totp()
    
    def get_time_remaining(self):
        """Sekunden bis zum nächsten Code"""
        current_time = int(time.time())
        return self.period - (current_time % self.period)

# Test Ihrer Implementierung
totp = TOTPGenerator("JBSWY3DPEHPK3PXP")

print("=== TOTP-Generator Test ===")
print(f"Aktueller Code: {totp.get_current_code()}")
print(f"Zeit bis neuer Code: {totp.get_time_remaining()}s")

# Historische Codes testen (mit bekannten Zeitstempeln)
test_vectors = [
    (59, "94287082"),           # RFC 6238 Test Vector 1
    (1111111109, "07081804"),   # RFC 6238 Test Vector 2
    (1111111111, "14050471"),   # RFC 6238 Test Vector 3
]

print("\n=== RFC 6238 Test Vectors ===")
for timestamp, expected in test_vectors:
    generated = totp.generate_totp(timestamp)
    status = "✅ PASS" if generated == expected else "❌ FAIL"
    print(f"T={timestamp}: Expected {expected}, Got {generated} {status}")
```

### Lab 2.2: QR-Code-Generation für App-Setup (10 Min)

**Aufgabe:** Erstellen Sie QR-Codes für Authenticator-App-Setup

```python
import qrcode
import secrets
import base64

class TOTPService:
    def __init__(self, service_name="TOTP-Lab"):
        self.service_name = service_name
        self.users = {}
    
    def enroll_user(self, username, email=None):
        """
        Erstellt neuen TOTP-Account für Benutzer
        """
        # TODO: Implementieren Sie User-Enrollment
        # 1. Sicheren Secret generieren
        # 2. TOTP-Generator erstellen
        # 3. QR-Code-URI generieren
        # 4. QR-Code als Bild speichern
        pass
    
    def generate_qr_uri(self, username, secret):
        """
        Erstellt otpauth:// URI für QR-Code
        """
        # TODO: Implementieren Sie URI-Generierung
        # Format: otpauth://totp/LABEL?secret=SECRET&issuer=ISSUER
        pass
    
    def verify_user_code(self, username, user_code):
        """
        Verifiziert TOTP-Code eines Benutzers
        """
        # TODO: Code-Verifikation implementieren
        # Beachten Sie Toleranzfenster!
        pass

# Service initialisieren und testen
service = TOTPService("Python-TOTP-Lab")

# Neuen Benutzer registrieren
username = input("Geben Sie einen Benutzernamen ein: ")
qr_file = service.enroll_user(username, f"{username}@totp-lab.local")

print(f"QR-Code gespeichert als: {qr_file}")
print("Scannen Sie den QR-Code mit Ihrer Authenticator-App!")

# Warten auf User-Input für Code-Test
input("Drücken Sie Enter, wenn Sie den QR-Code gescannt haben...")

while True:
    user_code = input("Geben Sie den aktuellen TOTP-Code ein (oder 'quit'): ")
    if user_code.lower() == 'quit':
        break
    
    is_valid = service.verify_user_code(username, user_code)
    if is_valid:
        print("✅ Code ist gültig!")
    else:
        print("❌ Code ist ungültig - versuchen Sie es erneut!")
```

---

## Phase 3: Problemlösung & Debugging (20 Minuten)

### Lab 3.1: Zeit-Synchronisations-Probleme (10 Min)

**Szenario:** Ein TOTP-System hat Synchronisationsprobleme

```python
import random
import time

class RealisticTOTPValidator:
    def __init__(self, secret, tolerance_window=1):
        self.secret = secret
        self.tolerance_window = tolerance_window
        self.totp_gen = TOTPGenerator(secret)
    
    def validate_with_tolerance(self, user_code, timestamp=None):
        """
        Validiert TOTP mit Toleranzfenster
        
        Returns:
            (is_valid, time_offset)
        """
        if timestamp is None:
            timestamp = int(time.time())
        
        # TODO: Implementieren Sie Toleranz-Validierung
        # Testen Sie Codes für aktuelle Zeit ± tolerance_window * 30s
        pass

# Simuliere Zeit-Drift-Probleme
def simulate_clock_drift():
    """Simuliert verschiedene Clock-Drift-Szenarien"""
    secret = "JBSWY3DPEHPK3PXP"
    validator = RealisticTOTPValidator(secret)
    
    current_time = int(time.time())
    
    # Verschiedene Drift-Szenarien
    drift_scenarios = [
        (0, "Perfekte Synchronisation"),
        (15, "15s voraus"),
        (-15, "15s zurück"),  
        (45, "45s voraus (nächstes Zeitfenster)"),
        (-45, "45s zurück (vorheriges Zeitfenster)"),
        (90, "90s voraus (zu weit auseinander)"),
    ]
    
    print("=== Clock Drift Simulation ===")
    for drift, description in drift_scenarios:
        drifted_time = current_time + drift
        totp_gen = TOTPGenerator(secret)
        code = totp_gen.generate_totp(drifted_time)
        
        is_valid, offset = validator.validate_with_tolerance(code, current_time)
        status = "✅ AKZEPTIERT" if is_valid else "❌ ABGELEHNT"
        
        print(f"{description}: Code {code} → {status}")
        if is_valid:
            print(f"   Erkannter Zeitversatz: {offset * 30}s")

# Test ausführen
simulate_clock_drift()
```

**Diskussion:** Welche Toleranzfenster sind für verschiedene Anwendungsfälle angemessen?

### Lab 3.2: Sicherheits-Audit Challenge (10 Min)

**Aufgabe:** Finden Sie Sicherheitsprobleme in diesem Code

```python
# WARNUNG: Dieser Code enthält absichtliche Sicherheitslücken!
import hashlib
import random

class InsecureTOTPSystem:
    def __init__(self):
        self.users = {}
        self.used_codes = []  # Global verwendete Codes
    
    def register_user(self, username, password):
        # Schwacher Secret-Generator
        secret = hashlib.md5(f"{username}{password}".encode()).hexdigest()[:16]
        self.users[username] = {
            'secret': secret,
            'password': password  # Klartext-Speicherung!
        }
        print(f"Secret für {username}: {secret}")  # Secret ausgeben!
        return secret
    
    def authenticate(self, username, password, totp_code):
        user = self.users.get(username)
        if not user:
            return False
        
        # Unsichere Passwort-Prüfung
        if user['password'] != password:
            return False
        
        # Schwache TOTP-Validierung
        expected = self.generate_simple_totp(user['secret'])
        
        # Replay-Schutz mit globaler Liste (schlecht!)
        if totp_code in self.used_codes:
            print("Code bereits verwendet!")
            return False
        
        if totp_code == expected:
            self.used_codes.append(totp_code)
            return True
        
        return False
    
    def generate_simple_totp(self, secret):
        # Vereinfachter TOTP ohne Zeitbasis
        current_minute = int(time.time()) // 60  # Minute statt 30s
        simple_hash = hashlib.md5(f"{secret}{current_minute}".encode()).hexdigest()
        return simple_hash[:6]

# Challenge: Identifizieren Sie alle Sicherheitsprobleme!
```

**Gruppenaufgabe (5 Min):** Listen Sie alle gefundenen Sicherheitsprobleme auf

**Gemeinsame Lösung (5 Min):** Diskussion der Probleme und Lösungsansätze

---

## Phase 4: Advanced Topics & Real-World-Szenarien (15 Minuten)

### Lab 4.1: Enterprise-TOTP mit Rate-Limiting (8 Min)

**Aufgabe:** Implementieren Sie ein produktionstaugliches TOTP-System

```python
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta

class EnterpriseTOTPSystem:
    def __init__(self):
        self.users = {}
        self.rate_limits = defaultdict(deque)  # Username → Timestamp-Queue
        self.used_tokens = defaultdict(set)    # Username → Set verwendeter Tokens
        
        # Konfiguration
        self.max_attempts = 5          # Max Versuche pro Minute
        self.window_size = 60          # Rate-Limit-Fenster (Sekunden)
        self.token_lifetime = 300      # Wie lange Tokens "verbraucht" bleiben
    
    def is_rate_limited(self, username):
        """
        Prüft ob Benutzer rate-limited ist
        """
        now = time.time()
        attempts = self.rate_limits[username]
        
        # TODO: Implementieren Sie Rate-Limiting
        # 1. Alte Attempts außerhalb des Fensters entfernen
        # 2. Prüfen ob aktuelle Attempts < max_attempts
        pass
    
    def cleanup_used_tokens(self, username):
        """
        Entfernt abgelaufene verwendete Tokens
        """
        # TODO: Implementieren Sie Token-Cleanup
        # Entfernen Sie Tokens älter als token_lifetime
        pass
    
    def secure_totp_validate(self, username, code):
        """
        Sichere TOTP-Validierung mit allen Schutzmaßnahmen
        """
        # TODO: Implementieren Sie sichere Validierung
        # 1. Rate-Limiting prüfen
        # 2. Token-Replay-Schutz
        # 3. Code validieren mit Toleranzfenster
        # 4. Verwendete Tokens tracken
        pass

# Test des Systems
enterprise = EnterpriseTOTPSystem()

# Simuliere Rate-Limiting-Angriff
print("=== Rate-Limiting-Test ===")
# TODO: Testen Sie das Rate-Limiting durch viele schnelle Versuche
```

### Lab 4.2: Multi-Algorithm-TOTP-Support (7 Min)

**Aufgabe:** Erweitern Sie TOTP für verschiedene Hash-Algorithmen

```python
import hashlib

class MultiAlgorithmTOTP:
    SUPPORTED_ALGORITHMS = {
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512,
        'md5': hashlib.md5,  # Nur zu Testzwecken!
    }
    
    def __init__(self, secret, algorithm='sha1', digits=6, period=30):
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Algorithmus {algorithm} nicht unterstützt")
        
        self.secret = secret
        self.algorithm = algorithm
        self.digits = digits
        self.period = period
    
    def generate_code(self, timestamp=None):
        """
        Generiert TOTP mit konfigurierbarem Algorithmus
        """
        # TODO: Implementieren Sie Multi-Algorithm-Support
        pass

# Vergleiche verschiedene Algorithmen
algorithms = ['sha1', 'sha256', 'sha512']
secret = "JBSWY3DPEHPK3PXP"
current_time = int(time.time())

print("=== Multi-Algorithm-Vergleich ===")
for algo in algorithms:
    totp = MultiAlgorithmTOTP(secret, algorithm=algo)
    code = totp.generate_code(current_time)
    print(f"{algo.upper()}: {code}")
```

---

## Phase 5: Kreative Challenge & Präsentation (Bonus - 10 Minuten)

### Final Challenge: TOTP-Innovationen

**Aufgabe (für schnelle Gruppen):** Implementieren Sie eine der folgenden Erweiterungen:

#### Option A: Visual TOTP
```python
# Erstellen Sie QR-Codes die sich alle 30s ändern
def generate_visual_totp(secret):
    """Generiert QR-Code mit aktuellem TOTP-Code"""
    pass
```

#### Option B: Audio-TOTP
```python
# Text-to-Speech für sehbeeinträchtigte Nutzer
def speak_totp_code(secret):
    """Spricht TOTP-Code aus"""
    pass
```

#### Option C: Backup-System
```python
# Encrypted TOTP-Secret-Backup
def create_encrypted_backup(secrets_dict, passphrase):
    """Erstellt verschlüsseltes Backup aller TOTP-Secrets"""
    pass
```

### Präsentation & Demo (10 Min)

**Jede Gruppe (2-3 Personen) präsentiert:**
- Was haben Sie implementiert?
- Welche Probleme sind aufgetreten?
- Was haben Sie über TOTP-Sicherheit gelernt?
- Live-Demo ihrer Lösung

---

## Wrap-Up & Reflexion (10 Minuten)

### Lessons Learned Sammlung

**Gemeinsame Diskussion:**
1. **Was war überraschend?** Häufige Antwort: Zeitstempel-Mathematik ist trickreicher als erwartet
2. **Größte Herausforderung?** Meist: Correct Implementation der Dynamic Truncation
3. **Sicherheits-Insights?** Clock-Drift-Probleme und Replay-Attacks

### Best Practices Summary

**Aus den Labs gelernt:**
- **Secret-Management:** Niemals Secrets in Logs oder auf Console ausgeben
- **Toleranzfenster:** Balance zwischen Sicherheit und Usability
- **Rate-Limiting:** Essential für produktive Systeme
- **Zeitynchronisation:** NTP ist kritisch für TOTP-Systeme

### Real-World-Anwendung

**Take-Aways für die Praxis:**
1. **Verwenden Sie etablierte Bibliotheken:** PyOTP, otplib, etc.
2. **Testen Sie mit RFC-Testvektoren:** Gewährleistet Kompatibilität
3. **Implementieren Sie Monitoring:** Track TOTP-Failures und Clock-Drift
4. **Educate Users:** QR-Code-Security und Backup-Strategien

### Weiterführende Challenges

**Für zu Hause:**
- Implementieren Sie HOTP (Counter-based OTP)
- Erstellen Sie eine TOTP-Browser-Extension
- Bauen Sie ein TOTP-Hardware-Token mit Arduino
- Analysieren Sie TOTP-Apps auf Sicherheitslücken

---

## Troubleshooting Guide

### Häufige Probleme & Lösungen

**Problem: "Codes funktionieren nicht mit echter App"**
- **Lösung:** Überprüfen Sie Base32-Encoding und Padding
- **Test:** Verwenden Sie bekannte Test-Vectors aus RFC 6238

**Problem: "Zeit-Synchronisation funktioniert nicht"**
- **Lösung:** `int(time.time())` vs. `time.time()` - verwenden Sie Ganzzahlen
- **Debug:** Ausgabe der Timestep-Berechnung

**Problem: "HMAC-Ergebnisse stimmen nicht überein"**
- **Lösung:** Big-Endian vs. Little-Endian bei Zeitstempel-Konvertierung
- **Fix:** `struct.pack('>Q', timestep)` für Big-Endian

**Problem: "QR-Codes werden nicht erkannt"**
- **Lösung:** URI-Format-Probleme - alle Parameter URL-encoded?
- **Test:** URI manuell in Authenticator-App eingeben

### Code-Repository

**Alle Lösungen verfügbar unter:**
```
https://github.com/totp-lab/solutions
├── phase1_basics/
├── phase2_implementation/  
├── phase3_debugging/
├── phase4_advanced/
└── bonus_challenges/
```

**Evaluation & Feedback:**
- Post-Workshop-Umfrage: "Was hat funktioniert, was nicht?"
- Code-Review der Implementierungen
- Follow-Up-Session nach 2 Wochen

---

**Diese Übung macht TOTP von der Theorie zur Praxis erlebbar und schafft tiefes Verständnis für die Sicherheitsaspekte zeitbasierter Authentifizierung!**