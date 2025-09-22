# Handout: Tokens (Authentifizierung)

**Thema:** Token-basierte Authentifizierung - Moderne Sicherheitsarchitekturen  
**Datum:** September 2025  
**Bearbeiter:** Ihr Name  

---

## 1. Grundlagen der Token-basierten Authentifizierung

### Definition
**Token-basierte Authentifizierung:** Ein Sicherheitsverfahren, bei dem kryptographische Token anstelle von Passwörtern für die Verifizierung von Identitäten und die Autorisierung von Ressourcenzugriffen verwendet werden[245][247]

### Historische Entwicklung
- **Traditional Sessions:** Server-seitige Session-Speicherung, limitierte Skalierbarkeit
- **Stateless Tokens:** Client-seitige Token-Speicherung, verbesserte Skalierbarkeit[245][242]
- **OAuth 2.0 (2012):** Standardisierung von Authorization Frameworks
- **JWT (RFC 7519, 2015):** JSON Web Token als universeller Standard[248][254]
- **Modern Era (2025):** Integration von PKCE, Token Binding, Zero Trust[280][289]

### Grundprinzipien
1. **Stateless Authentication:** Server speichert keine Session-Informationen[242][245]
2. **Cryptographic Security:** Tokens sind kryptographisch signiert oder verschlüsselt[248][251]
3. **Time-Limited Access:** Tokens haben begrenzte Gültigkeitsdauer[240][249]
4. **Granular Authorization:** Tokens enthalten spezifische Berechtigungen[242][259]

---

## 2. Token-Typen & Implementierungen

### JSON Web Tokens (JWT)
**JWT-Struktur (RFC 7519):**[239][248][251]

#### Header
```json
{
  "alg": "HS256",    // Signatur-Algorithmus
  "typ": "JWT"       // Token-Typ
}
```

#### Payload (Claims)
```json
{
  "iss": "auth.example.com",     // Issuer
  "sub": "user123",              // Subject
  "exp": 1672531200,             // Expiration Time
  "iat": 1672527600,             // Issued At
  "aud": "api.example.com",      // Audience
  "scope": "read write"          // Authorization Scope
}
```

#### Signature
```
HMACSHA256(
  base64UrlEncode(header) + "." + 
  base64UrlEncode(payload),
  secret
)
```

**JWT-Eigenschaften:**
- **Self-Contained:** Alle Informationen im Token enthalten[239][242]
- **Portable:** Plattformunabhängig, Base64URL-kodiert[245][251]
- **Scalable:** Keine Server-seitige Session-Speicherung erforderlich[242]
- **Secure:** Kryptographisch signiert (JWS) oder verschlüsselt (JWE)[248]

### Bearer Tokens
**Bearer Token-Charakteristika:**[241][244][247]

#### Definition & Verwendung
- **Bearer:** "Gewähre Zugang dem Inhaber dieses Tokens"[241]
- **HTTP-Standard:** RFC 6750, ursprünglich für OAuth 2.0[241]
- **Authorization Header:** `Authorization: Bearer <token>`[239][244]
- **Stateless:** Server benötigt keine Token-Datenbank[244][247]

#### Implementierung
```http
POST /api/token HTTP/1.1
Host: auth.example.com
Content-Type: application/json

{
  "client_id": "app123",
  "client_secret": "secret456",
  "grant_type": "client_credentials"
}
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}
```

**API-Zugriff:**
```http
GET /api/user HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### OAuth 2.0 Token-Ecosystem
**OAuth 2.0 Token-Typen:**[240][243][246]

#### Access Tokens
- **Zweck:** Kurzfristiger Ressourcenzugriff (typisch 1-2 Stunden)[240][252]
- **Format:** Oft JWT, kann aber opaque strings sein[246]
- **Scope:** Definierte Berechtigungen für spezifische Ressourcen[243]
- **Transport:** Bearer Token in Authorization Header[241][244]

#### Refresh Tokens
- **Zweck:** Erneuerung abgelaufener Access Tokens ohne Re-Authentication[240][249]
- **Lebensdauer:** Länger als Access Tokens (Tage bis Monate)[240][252]
- **Security:** Sicherere Speicherung, oft mit Rotation[246][249]
- **Flow:** Separate Token-Endpoint-Requests[243][255]

**Refresh Token Flow:**
```http
POST /oauth/token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&
refresh_token=def456&
client_id=app123&
client_secret=secret456
```

#### Token-Hierarchie
```
OAuth 2.0 Token Ecosystem
├── Authorization Code (einmalig, kurzlebig)
├── Access Token (Ressourcenzugriff, 1-2h)
├── Refresh Token (Token-Erneuerung, Tage-Monate)
└── ID Token (OpenID Connect, Identitätsinformation)
```

### SAML Tokens & Assertions
**SAML 2.0 Token-Struktur:**[259][262][268]

#### SAML Assertion-Komponenten
- **Issuer:** Identity Provider (IdP) Identifikation[259][262]
- **Subject:** Authenticated User Information[262][268]
- **Conditions:** Gültigkeitsbedingungen (Zeit, Audience)[259][262]
- **Statements:** Authentication, Authorization, Attributes[262][268]

**SAML Assertion-Beispiel:**
```xml
<saml:Assertion ID="_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75"
                Version="2.0"
                IssueInstant="2025-09-22T14:00:00Z">
  <saml:Issuer>https://idp.example.org/SAML2</saml:Issuer>
  <ds:Signature>...</ds:Signature>
  
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">
      3f7b3dcf-1674-4ecd-92c8-1544f346baf8
    </saml:NameID>
  </saml:Subject>
  
  <saml:Conditions NotBefore="2025-09-22T13:55:00Z"
                   NotOnOrAfter="2025-09-22T14:10:00Z">
    <saml:AudienceRestriction>
      <saml:Audience>https://sp.example.com/SAML2</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  
  <saml:AuthnStatement AuthnInstant="2025-09-22T14:00:00Z">
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>
        urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
      </saml:AuthnContextClassRef>
    </saml:AuthnContext>
  </saml:AuthnStatement>
</saml:Assertion>
```

---

## 3. Token-Sicherheit & Kryptographie

### JWT-Signatur-Algorithmen
**Symmetric Algorithms:**[248][251]

#### HMAC (Hash-based Message Authentication Code)
- **HS256:** HMAC with SHA-256 (256-bit secret key)
- **HS384:** HMAC with SHA-384 (384-bit secret key)  
- **HS512:** HMAC with SHA-512 (512-bit secret key)
- **Verwendung:** Shared Secret zwischen Client und Server
- **Performance:** Sehr schnell, geringer Overhead

#### HMAC-Berechnung:
```
HMAC-SHA256(message, secret) = SHA256((secret XOR opad) || SHA256((secret XOR ipad) || message))

wobei:
- ipad = 0x36 repeated 64 times
- opad = 0x5c repeated 64 times
```

**Asymmetric Algorithms:**[248][251]

#### RSA-basierte Signaturen
- **RS256:** RSA-PSS with SHA-256 (2048-bit+ keys empfohlen)
- **RS384:** RSA-PSS with SHA-384
- **RS512:** RSA-PSS with SHA-512
- **Verwendung:** Public/Private Key Pairs
- **Vorteil:** Public Key kann weit verteilt werden

#### Elliptic Curve Signatures
- **ES256:** ECDSA mit P-256 Kurve und SHA-256
- **ES384:** ECDSA mit P-384 Kurve und SHA-384
- **ES512:** ECDSA mit P-521 Kurve und SHA-512
- **Performance:** Schneller als RSA bei gleicher Sicherheit
- **Key Size:** Deutlich kleinere Schlüssel als RSA

### Token-Speicherung & Transport-Sicherheit

#### Cookie-basierte Token-Speicherung
**Security Attributes:**[279][285][288]

```http
Set-Cookie: access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...; 
           HttpOnly; 
           Secure; 
           SameSite=Strict; 
           Max-Age=3600; 
           Path=/;
           Domain=example.com
```

**Attribute-Erklärung:**
- **HttpOnly:** Verhindert JavaScript-Zugriff, schützt vor XSS[279][285]
- **Secure:** Nur über HTTPS-Verbindungen übertragen[279][285]
- **SameSite=Strict:** Maximaler CSRF-Schutz, nur Same-Site-Requests[282][288]
- **SameSite=Lax:** CSRF-Schutz mit besserer Usability[282][291]
- **Max-Age/Expires:** Token-Lebensdauer-Kontrolle[285]

#### LocalStorage vs. SessionStorage vs. Cookies
| **Speicher-Typ** | **XSS-Schutz** | **CSRF-Schutz** | **Same-Site** | **Expiration** |
|-------------------|-----------------|------------------|---------------|----------------|
| **LocalStorage** | ❌ JavaScript-zugreifbar | ✅ Manueller Header | ❌ Cross-Origin | ⚠️ Manuell |
| **SessionStorage** | ❌ JavaScript-zugreifbar | ✅ Manueller Header | ❌ Cross-Origin | ✅ Session-Ende |
| **HttpOnly Cookies** | ✅ Kein JS-Zugriff | ⚠️ Benötigt CSRF-Schutz | ✅ SameSite-Attribute | ✅ Server-kontrolliert |

**Best Practice:** Dual-Token-Ansatz[288][297]
- **Access Token:** HttpOnly Cookie (automatischer Transport)
- **CSRF Token:** LocalStorage/Header (CSRF-Protection)

---

## 4. OAuth 2.0 Advanced Flows

### Proof Key for Code Exchange (PKCE)
**PKCE-Zweck (RFC 7636):**[280][286][289]

#### Security-Problem ohne PKCE
- **Authorization Code Interception:** Angreifer können Codes abfangen
- **Mobile/SPA Vulnerability:** Keine sicheren Client Secrets möglich[280][286]
- **Man-in-the-Middle:** Network-basierte Code-Diebstahl[289][292]

#### PKCE-Mechanismus
**1. Code Verifier & Challenge Generation:**[286][289][295]
```javascript
// 1. Code Verifier generieren (43-128 Zeichen)
const codeVerifier = base64URLEncode(crypto.getRandomValues(new Uint8Array(32)));

// 2. Code Challenge berechnen (SHA256)
const codeChallenge = base64URLEncode(sha256(codeVerifier));

// 3. Challenge Method
const codeChallengeMethod = "S256"; // oder "plain"
```

**2. Authorization Request mit PKCE:**
```http
GET /oauth/authorize?response_type=code
    &client_id=s6BhdRkqt3
    &redirect_uri=https://app.example.com/callback
    &scope=read
    &state=xyz
    &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
    &code_challenge_method=S256 HTTP/1.1
Host: auth.example.com
```

**3. Token Exchange mit Verification:**
```http
POST /oauth/token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&client_id=s6BhdRkqt3
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

**Server-side PKCE Validation:**
```python
def verify_pkce(code_challenge, code_verifier, method):
    if method == "S256":
        computed_challenge = base64_url_encode(sha256(code_verifier))
    elif method == "plain":
        computed_challenge = code_verifier
    else:
        raise ValueError("Unsupported challenge method")
    
    return computed_challenge == code_challenge
```

### Token Binding & Advanced Security
**Token Binding-Konzepte:**[283][292]

#### Channel Binding
- **TLS Token Binding:** Token an TLS-Channel gebunden
- **Certificate Binding:** Token an Client-Zertifikat gebunden
- **Device Binding:** Token an Device-spezifische Eigenschaften gebunden[289]

#### Implementation-Beispiel:
```http
Token-Binding: Ymhl7Q

Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.
eyJpc3MiOiJhdXRoLmV4YW1wbGUuY29tIiwic3ViIjoidXNlcjEyMyIsImV4cCI6MTY3MjUzMTIwMCwiaWF0IjoxNjcyNTI3NjAwLCJ0a2IiOiJZbWhsN1EifQ.
signature
```

---

## 5. API Keys & Secrets Management

### API Key-Architektur
**API Key-Eigenschaften:**[260][266][269]

#### Generation & Format
- **Entropy:** Mindestens 128-bit Zufälligkeit[260][263]
- **Format:** Alphanumerische Strings, oft mit Präfix
- **Example:** `sk_live_51HyG8SA9w6TRZ4XKLxWtd...` (Stripe-Style)
- **Length:** 32-64 Zeichen für ausreichende Sicherheit[266]

#### API Key-Hierarchie
```
API Key Types:
├── Public Keys (pk_*) - Client-seitige Integration
├── Secret Keys (sk_*) - Server-seitige Operationen  
├── Restricted Keys - Begrenzte Berechtigungen
└── Webhook Keys - Event-Verifikation
```

### API Key Management Best Practices
**Lifecycle Management:**[260][263][266]

#### 1. Sichere Generation
```python
import secrets
import string

def generate_api_key(prefix="sk_live_", length=32):
    alphabet = string.ascii_letters + string.digits
    random_part = ''.join(secrets.choice(alphabet) for _ in range(length))
    return f"{prefix}{random_part}"

# Beispiel
api_key = generate_api_key()  # sk_live_Kx8f3mN9pQ2rS7tU1vW4xY6zA8bC5dE0
```

#### 2. Verschlüsselung & Speicherung
```python
from cryptography.fernet import Fernet
import hashlib

class APIKeyManager:
    def __init__(self, encryption_key):
        self.cipher = Fernet(encryption_key)
    
    def store_key(self, api_key, user_id):
        # Hash für schnelle Lookups
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        # Verschlüsselung für sichere Speicherung
        encrypted_key = self.cipher.encrypt(api_key.encode())
        
        return {
            'key_hash': key_hash,
            'encrypted_key': encrypted_key,
            'user_id': user_id,
            'created_at': datetime.utcnow()
        }
    
    def verify_key(self, provided_key, stored_hash):
        provided_hash = hashlib.sha256(provided_key.encode()).hexdigest()
        return provided_hash == stored_hash
```

#### 3. Rotation & Expiration
**Rotation-Strategien:**[260][263][269]
- **Scheduled Rotation:** 30-90 Tage für kritische Systeme[263][266]
- **Event-based Rotation:** Nach Security-Incidents[260][269]
- **Dual-Key Period:** Overlap während Rotation[266]
- **Automated Tooling:** AWS Secrets Manager, HashiCorp Vault[260]

#### 4. Access Control & Monitoring
```python
class APIKeyPolicy:
    def __init__(self, key_id):
        self.key_id = key_id
        self.rate_limits = {}
        self.ip_whitelist = []
        self.scope_permissions = []
        self.quota_limits = {}
    
    def enforce_rate_limit(self, endpoint, requests_per_minute=100):
        self.rate_limits[endpoint] = {
            'requests': requests_per_minute,
            'window': 60  # seconds
        }
    
    def add_ip_restriction(self, cidr_blocks):
        self.ip_whitelist.extend(cidr_blocks)
    
    def set_scope_permissions(self, scopes):
        # Principle of least privilege
        self.scope_permissions = scopes
```

---

## 6. Token-Angriffe & Vulnerabilities

### JWT-spezifische Angriffe
**Common JWT Vulnerabilities:**[248][251]

#### 1. Algorithm Confusion (alg: "none")
```json
// Malicious Header
{
  "alg": "none",
  "typ": "JWT"
}
```
**Mitigation:** Explicitly validate algorithm in server code

#### 2. Key Confusion (RS256 → HS256)
- **Attack:** Public Key als HMAC Secret verwenden
- **Impact:** Signature-Forge möglich
- **Prevention:** Strikte Algorithm-Validierung[248][251]

#### 3. Weak Secrets
```python
# Vulnerable: Weak HMAC Secret
jwt_secret = "secret123"

# Secure: Strong Secret Generation
jwt_secret = secrets.token_urlsafe(32)  # 256-bit entropy
```

### Token Replay Attacks
**Replay Attack-Mechanismen:**[261][267][270]

#### Attack-Szenario
1. **Token Interception:** Network sniffing, Man-in-the-Middle[261][270]
2. **Token Storage:** Angreifer speichert gültiges Token[267]
3. **Token Reuse:** Mehrfache Verwendung für unauthorized access[261][276]

#### Defense-Strategien
**1. Nonce-basierte Protection:**[267][270]
```python
import uuid
import time

class NonceManager:
    def __init__(self):
        self.used_nonces = set()
        self.cleanup_interval = 3600  # 1 hour
    
    def generate_nonce(self):
        return str(uuid.uuid4())
    
    def validate_nonce(self, nonce, timestamp):
        # Check if nonce already used
        if nonce in self.used_nonces:
            raise ReplayAttackException("Nonce already used")
        
        # Check timestamp freshness (5-minute window)
        current_time = time.time()
        if abs(current_time - timestamp) > 300:
            raise ReplayAttackException("Request too old")
        
        self.used_nonces.add(nonce)
        return True
```

**2. Cryptographic Signatures:**[267][270]
```python
def create_signed_request(data, private_key, nonce, timestamp):
    message = f"{data}:{nonce}:{timestamp}"
    signature = rsa.sign(message.encode(), private_key, 'SHA-256')
    
    return {
        'data': data,
        'nonce': nonce,
        'timestamp': timestamp,
        'signature': base64.b64encode(signature).decode()
    }
```

### SAML-spezifische Vulnerabilities
**SAML Assertion Attacks:**[259][262]

#### 1. Assertion Replay
- **Problem:** SAML Assertions ohne Timestamp-Validation[259]
- **Attack:** Wiederverwendung alter, gültiger Assertions[262]
- **Mitigation:** NotBefore/NotOnOrAfter Validation[259][268]

#### 2. Signature Wrapping
```xml
<!-- Original Signed Assertion -->
<saml:Assertion>
  <ds:Signature>...</ds:Signature>
  <saml:Subject>legitimate@user.com</saml:Subject>
</saml:Assertion>

<!-- Wrapped Attack -->
<saml:Assertion>
  <saml:Subject>attacker@evil.com</saml:Subject>
  <saml:Assertion>
    <ds:Signature>...</ds:Signature>
    <saml:Subject>legitimate@user.com</saml:Subject>
  </saml:Assertion>
</saml:Assertion>
```

#### 3. Unsigned Assertions
- **Vulnerability:** Missing digital signature validation[259]
- **Attack:** Assertion manipulation, privilege escalation[259]
- **Prevention:** Mandatory signature validation for all assertions[268]

---

## 7. Rate Limiting & API Protection

### Rate Limiting Algorithms
**Algorithm-Vergleich:**[281][284][296]

#### 1. Fixed Window
```python
class FixedWindowLimiter:
    def __init__(self, requests_per_window, window_size):
        self.requests_per_window = requests_per_window
        self.window_size = window_size  # in seconds
        self.requests = {}
    
    def allow_request(self, client_id):
        current_window = int(time.time()) // self.window_size
        key = f"{client_id}:{current_window}"
        
        if key not in self.requests:
            self.requests[key] = 0
        
        if self.requests[key] < self.requests_per_window:
            self.requests[key] += 1
            return True
        
        return False
```

#### 2. Sliding Window
```python
class SlidingWindowLimiter:
    def __init__(self, requests_per_window, window_size):
        self.requests_per_window = requests_per_window
        self.window_size = window_size
        self.requests = defaultdict(list)
    
    def allow_request(self, client_id):
        now = time.time()
        
        # Remove old requests outside window
        self.requests[client_id] = [
            req_time for req_time in self.requests[client_id]
            if now - req_time < self.window_size
        ]
        
        if len(self.requests[client_id]) < self.requests_per_window:
            self.requests[client_id].append(now)
            return True
        
        return False
```

#### 3. Token Bucket
```python
class TokenBucketLimiter:
    def __init__(self, capacity, refill_rate):
        self.capacity = capacity
        self.refill_rate = refill_rate  # tokens per second
        self.buckets = {}
    
    def allow_request(self, client_id):
        now = time.time()
        
        if client_id not in self.buckets:
            self.buckets[client_id] = {
                'tokens': self.capacity,
                'last_refill': now
            }
        
        bucket = self.buckets[client_id]
        
        # Refill tokens
        time_passed = now - bucket['last_refill']
        new_tokens = time_passed * self.refill_rate
        bucket['tokens'] = min(self.capacity, bucket['tokens'] + new_tokens)
        bucket['last_refill'] = now
        
        if bucket['tokens'] >= 1:
            bucket['tokens'] -= 1
            return True
        
        return False
```

### API Gateway Integration
**Modern API Gateway Features:**[287][290][293]

#### Rate Limiting Configuration
```yaml
# API Gateway Rate Limiting Policy
apiVersion: v1
kind: RateLimitPolicy
metadata:
  name: api-rate-limits
spec:
  rateLimits:
    - key: api_key
      requests: 1000
      window: 3600  # 1 hour
      
    - key: ip_address
      requests: 100
      window: 60    # 1 minute
      
    - key: endpoint:/api/upload
      requests: 10
      window: 60
      
  quotas:
    - key: api_key
      requests: 10000
      window: 86400  # 24 hours
      
  burst:
    - key: api_key
      max_burst: 50
      refill_rate: 10  # per second
```

#### Advanced Protection
```python
class APIGatewaySecurityLayer:
    def __init__(self):
        self.rate_limiters = {
            'global': TokenBucketLimiter(1000, 10),
            'per_key': {},
            'per_ip': {}
        }
        self.threat_detector = ThreatDetector()
    
    def process_request(self, request):
        # 1. Global rate limiting
        if not self.rate_limiters['global'].allow_request('global'):
            return self.error_response(429, "Global rate limit exceeded")
        
        # 2. API key validation
        api_key = self.extract_api_key(request)
        if not self.validate_api_key(api_key):
            return self.error_response(401, "Invalid API key")
        
        # 3. Per-key rate limiting
        key_limiter = self.get_or_create_limiter(api_key)
        if not key_limiter.allow_request(api_key):
            return self.error_response(429, "API key rate limit exceeded")
        
        # 4. IP-based limiting
        client_ip = self.extract_client_ip(request)
        ip_limiter = self.get_or_create_ip_limiter(client_ip)
        if not ip_limiter.allow_request(client_ip):
            return self.error_response(429, "IP rate limit exceeded")
        
        # 5. Threat detection
        threat_score = self.threat_detector.analyze_request(request)
        if threat_score > 0.8:
            return self.error_response(403, "Suspicious activity detected")
        
        return self.forward_request(request)
```

---

## 8. Modern Token Standards & Trends (2025)

### Token-basierte Zero Trust Architecture
**Zero Trust Token Integration:**[273]

#### Continuous Verification
```python
class ZeroTrustTokenValidator:
    def __init__(self):
        self.risk_engine = RiskAssessmentEngine()
        self.context_analyzer = ContextAnalyzer()
    
    def validate_token_with_context(self, token, request_context):
        # 1. Standard token validation
        claims = self.validate_jwt_signature(token)
        
        # 2. Context analysis
        risk_factors = self.context_analyzer.analyze({
            'user_location': request_context.geolocation,
            'device_fingerprint': request_context.device_id,
            'network_reputation': request_context.ip_reputation,
            'time_patterns': request_context.access_time,
            'behavioral_anomalies': request_context.user_behavior
        })
        
        # 3. Risk-based token lifetime adjustment
        risk_score = self.risk_engine.calculate_risk(risk_factors)
        
        if risk_score > 0.7:  # High risk
            # Require step-up authentication
            return self.require_step_up_auth(token)
        elif risk_score > 0.4:  # Medium risk
            # Shorten token lifetime
            return self.adjust_token_lifetime(token, max_age=900)  # 15 minutes
        else:  # Low risk
            # Standard token handling
            return self.standard_token_validation(token)
```

### OAuth 2.1 & Security Best Practices (2025)
**OAuth 2.1 Enhancements:**[280][295]

#### Mandatory PKCE
- **Requirement:** PKCE für alle OAuth 2.1 clients (public + confidential)[280][295]
- **Security:** Eliminiert authorization code injection attacks[286][289]
- **Implementation:** Backward-compatible mit OAuth 2.0[295]

#### Enhanced Security Features
```python
class OAuth21Implementation:
    def __init__(self):
        self.required_features = {
            'pkce': True,                    # Mandatory for all flows
            'state_parameter': True,         # CSRF protection
            'redirect_uri_validation': True, # Exact match required
            'https_only': True,              # No HTTP allowed
            'short_lived_tokens': True       # Max 2 hours for access tokens
        }
    
    def create_authorization_request(self, client_id, redirect_uri, scope):
        # Generate PKCE parameters
        code_verifier = self.generate_code_verifier()
        code_challenge = self.generate_code_challenge(code_verifier)
        state = self.generate_state()
        
        # Store for later verification
        self.store_pkce_session(client_id, code_verifier, state)
        
        return {
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'scope': scope,
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
            'response_type': 'code'
        }
```

### Token-bound Sessions & Device Trust
**Device-bound Tokens:**[273][289]

#### Conditional Access Integration
```python
class ConditionalAccessEngine:
    def evaluate_token_request(self, token_request, device_info):
        conditions = {
            'device_compliance': self.check_device_compliance(device_info),
            'location_policy': self.validate_location(token_request.location),
            'risk_signals': self.analyze_risk_signals(token_request),
            'authentication_strength': self.evaluate_auth_method(token_request.auth_method)
        }
        
        # Policy evaluation
        if not conditions['device_compliance']:
            return self.deny_with_remediation("Device not compliant")
        
        if conditions['risk_signals'] > 0.8:
            return self.require_mfa("High risk detected")
        
        # Adjust token properties based on conditions
        token_properties = {
            'lifetime': self.calculate_lifetime(conditions),
            'scope': self.adjust_scope(conditions),
            'binding': self.determine_binding_requirements(conditions)
        }
        
        return self.issue_conditional_token(token_properties)
```

---

## 9. Implementierungs-Best Practices

### Secure Token Storage
**Storage-Strategy-Matrix:**[279][285][288]

| **Use Case** | **Recommended Storage** | **Security Attributes** | **Trade-offs** |
|--------------|------------------------|------------------------|----------------|
| **Web Application** | HttpOnly Cookies | `HttpOnly; Secure; SameSite=Strict` | Automatisch, CSRF-Schutz nötig |
| **Single Page App** | Dual Token (Cookie + LS) | HttpOnly Cookie + CSRF Token | Komplexer, aber sicherer |
| **Mobile App** | Secure Keystore | iOS Keychain, Android Keystore | Native APIs, OS-protected |
| **Desktop App** | Encrypted Local Storage | OS Credential Manager | User-context-bound |

### Token Lifecycle Management
**Comprehensive Token Management:**

#### 1. Token Generation
```python
class TokenFactory:
    def __init__(self, issuer, signing_key, encryption_key=None):
        self.issuer = issuer
        self.signing_key = signing_key
        self.encryption_key = encryption_key
    
    def create_access_token(self, user_id, scopes, audience, lifetime=3600):
        claims = {
            'iss': self.issuer,
            'sub': user_id,
            'aud': audience,
            'exp': int(time.time()) + lifetime,
            'iat': int(time.time()),
            'jti': str(uuid.uuid4()),  # Unique token ID
            'scope': ' '.join(scopes)
        }
        
        # Sign token
        token = jwt.encode(claims, self.signing_key, algorithm='RS256')
        
        # Optionally encrypt
        if self.encryption_key:
            token = self.encrypt_token(token)
        
        return token
    
    def create_refresh_token(self, user_id, client_id):
        # Opaque token with high entropy
        token_data = {
            'user_id': user_id,
            'client_id': client_id,
            'created_at': time.time(),
            'token_family': str(uuid.uuid4())  # For rotation detection
        }
        
        token_id = secrets.token_urlsafe(32)
        
        # Store in database for validation
        self.store_refresh_token(token_id, token_data)
        
        return token_id
```

#### 2. Token Validation Pipeline
```python
class TokenValidationPipeline:
    def __init__(self):
        self.validators = [
            self.validate_format,
            self.validate_signature,
            self.validate_expiration,
            self.validate_audience,
            self.validate_issuer,
            self.validate_revocation,
            self.validate_context
        ]
    
    def validate_token(self, token, context=None):
        for validator in self.validators:
            try:
                validator(token, context)
            except TokenValidationError as e:
                return ValidationResult(valid=False, error=str(e))
        
        return ValidationResult(valid=True, claims=self.extract_claims(token))
    
    def validate_signature(self, token, context):
        try:
            # Decode without verification to get header
            header = jwt.get_unverified_header(token)
            
            # Get appropriate public key
            public_key = self.get_public_key(header.get('kid'))
            
            # Verify signature
            claims = jwt.decode(token, public_key, algorithms=['RS256', 'ES256'])
            
        except jwt.InvalidSignatureError:
            raise TokenValidationError("Invalid signature")
        except jwt.DecodeError:
            raise TokenValidationError("Invalid token format")
    
    def validate_context(self, token, context):
        if not context:
            return
        
        claims = jwt.decode(token, verify=False)
        
        # IP binding validation
        if 'ip' in claims and context.client_ip != claims['ip']:
            raise TokenValidationError("IP binding validation failed")
        
        # Device binding validation
        if 'device_id' in claims and context.device_id != claims['device_id']:
            raise TokenValidationError("Device binding validation failed")
```

### Error Handling & Security Responses
**Security-aware Error Handling:**

```python
class SecureTokenErrorHandler:
    def __init__(self):
        self.security_logger = SecurityLogger()
        self.rate_limiter = RateLimiter()
    
    def handle_token_error(self, error_type, request_context):
        # Log security event
        self.security_logger.log_token_error(error_type, request_context)
        
        # Rate limit suspicious requests
        if error_type in ['invalid_signature', 'malformed_token']:
            self.rate_limiter.penalize_client(request_context.client_ip)
        
        # Generic error response (avoid information disclosure)
        if error_type == 'expired_token':
            return {
                'error': 'invalid_token',
                'error_description': 'Token has expired',
                'status_code': 401
            }
        elif error_type in ['invalid_signature', 'malformed_token']:
            return {
                'error': 'invalid_token',
                'error_description': 'Invalid token',
                'status_code': 401
            }
        elif error_type == 'insufficient_scope':
            return {
                'error': 'insufficient_scope',
                'error_description': 'Token lacks required scope',
                'status_code': 403
            }
        else:
            return {
                'error': 'invalid_request',
                'error_description': 'Request could not be processed',
                'status_code': 400
            }
```

---

## 10. Testing & Monitoring

### Token Security Testing
**Security Test Categories:**

#### 1. Cryptographic Tests
```python
class TokenSecurityTester:
    def test_signature_algorithms(self, token):
        """Test für Algorithm Confusion attacks"""
        tests = []
        
        # Test 1: None algorithm
        malicious_header = {'alg': 'none', 'typ': 'JWT'}
        malicious_token = self.create_unsigned_token(malicious_header, token.payload)
        tests.append(('none_algorithm', self.validate_token_rejection(malicious_token)))
        
        # Test 2: HS256 with RSA public key
        if token.algorithm == 'RS256':
            public_key_as_secret = self.get_public_key(token)
            hmac_token = self.create_hmac_token(token.payload, public_key_as_secret)
            tests.append(('key_confusion', self.validate_token_rejection(hmac_token)))
        
        # Test 3: Weak secrets (if HMAC)
        if token.algorithm.startswith('HS'):
            weak_secrets = ['secret', '123456', 'password', '']
            for weak_secret in weak_secrets:
                weak_token = self.create_hmac_token(token.payload, weak_secret)
                tests.append((f'weak_secret_{weak_secret}', self.validate_token_rejection(weak_token)))
        
        return tests
    
    def test_token_manipulation(self, token):
        """Test für Token-Manipulation"""
        tests = []
        
        # Test 1: Payload modification
        modified_payload = token.payload.copy()
        modified_payload['sub'] = 'admin'
        modified_token = self.create_token_with_payload(modified_payload)
        tests.append(('payload_manipulation', self.validate_token_rejection(modified_token)))
        
        # Test 2: Expiration extension
        extended_payload = token.payload.copy()
        extended_payload['exp'] = int(time.time()) + 86400  # +24 hours
        extended_token = self.create_token_with_payload(extended_payload)
        tests.append(('expiration_extension', self.validate_token_rejection(extended_token)))
        
        return tests
```

### Monitoring & Alerting
**Token-based Security Monitoring:**

```python
class TokenSecurityMonitor:
    def __init__(self):
        self.metrics_collector = MetricsCollector()
        self.alert_manager = AlertManager()
        self.threat_detector = ThreatDetector()
    
    def monitor_token_usage(self, token_event):
        # Collect metrics
        self.metrics_collector.record({
            'event_type': token_event.type,
            'token_algorithm': token_event.algorithm,
            'client_ip': token_event.client_ip,
            'user_agent': token_event.user_agent,
            'timestamp': token_event.timestamp,
            'success': token_event.success
        })
        
        # Anomaly detection
        anomalies = self.detect_anomalies(token_event)
        
        if anomalies:
            self.alert_manager.send_alert({
                'type': 'token_anomaly',
                'severity': self.calculate_severity(anomalies),
                'details': anomalies,
                'timestamp': token_event.timestamp
            })
    
    def detect_anomalies(self, token_event):
        anomalies = []
        
        # High frequency token requests
        if self.is_high_frequency_usage(token_event.client_ip):
            anomalies.append('high_frequency_requests')
        
        # Geographic impossibility
        if self.is_impossible_travel(token_event.user_id, token_event.location):
            anomalies.append('impossible_travel')
        
        # Unusual token algorithms
        if token_event.algorithm not in ['RS256', 'ES256']:
            anomalies.append('unusual_algorithm')
        
        # Multiple simultaneous sessions
        if self.count_active_sessions(token_event.user_id) > 5:
            anomalies.append('excessive_sessions')
        
        return anomalies
```

---

## 11. Klausur-relevante Formeln & Konzepte

### Wichtige Token-Algorithmen
**HMAC-SHA256-Berechnung:**
```
HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))

wobei:
- K = Secret Key (padded to block size)
- m = Message (Token Payload)
- H = Hash function (SHA-256)
- ipad = 0x36 repeated
- opad = 0x5c repeated
- || = Concatenation
- ⊕ = XOR operation
```

**JWT-Struktur:**
```
JWT = Base64URL(Header) + "." + Base64URL(Payload) + "." + Base64URL(Signature)

Header = {"alg": "HS256", "typ": "JWT"}
Payload = {"sub": "user123", "exp": 1672531200}
Signature = HMAC-SHA256(Base64URL(Header) + "." + Base64URL(Payload), Secret)
```

### Token-Lebensdauer-Kalkulationen
**Standard-Lifetimes:**
- **Access Token:** 1-2 Stunden (3600-7200 Sekunden)
- **Refresh Token:** 30-90 Tage (2,592,000-7,776,000 Sekunden)
- **ID Token:** Session-basiert (variable)
- **Authorization Code:** 10 Minuten (600 Sekunden)

**PKCE Code-Challenge-Berechnung:**
```
Code_Verifier = Base64URL(Random(256-bit))
Code_Challenge = Base64URL(SHA256(Code_Verifier))  // für method=S256
Code_Challenge = Code_Verifier                     // für method=plain
```

### Security-Metriken
**Token-Entropy-Berechnung:**
```
Entropy = log₂(|Character_Set|^Length)

Beispiele:
- API Key (64 chars, alphanumeric): log₂(62^64) ≈ 380 bits
- UUID v4: log₂(2^128) = 128 bits
- JWT Secret (256-bit): log₂(2^256) = 256 bits
```

---

## 12. Prüfungstipps & häufige Klausurfragen

### Typische Klausurfragen
1. **JWT-Struktur:** Header, Payload, Signature - Zweck und Inhalt jeder Komponente
2. **HMAC vs. RSA:** Symmetric vs. Asymmetric JWT-Signierung - Vor-/Nachteile
3. **OAuth 2.0 Flows:** Authorization Code, Client Credentials, Implicit - Wann welcher Flow?
4. **PKCE:** Warum benötigt, wie funktioniert Code Challenge/Verifier
5. **Token Storage:** LocalStorage vs. Cookies vs. SessionStorage - Sicherheitsimplikationen
6. **Rate Limiting:** Fixed Window vs. Sliding Window vs. Token Bucket - Algorithmus-Eigenschaften
7. **SAML vs. JWT:** XML vs. JSON Tokens - Einsatzgebiete und Unterschiede
8. **Token Attacks:** Replay Attacks, Algorithm Confusion, Key Confusion - Präventionsmaßnahmen

### Berechnungsaufgaben
- **JWT-Expiration:** Token-Lifetime-Berechnungen mit exp-Claims
- **HMAC-Verification:** Signature-Validierung Schritt-für-Schritt
- **Rate Limiting:** Request-Counts in verschiedenen Window-Algorithmen
- **Base64URL:** Encoding/Decoding von Token-Komponenten

### Vergleichstabellen lernen
- Token-Typen (Access, Refresh, ID, SAML Assertion)
- Storage-Strategien (Cookies, LocalStorage, SessionStorage)
- Rate-Limiting-Algorithmen (Fixed/Sliding Window, Token Bucket)
- JWT-Algorithmen (HS256, RS256, ES256)

### Aktuelle Trends 2025
- **OAuth 2.1:** Mandatory PKCE, Enhanced Security
- **Zero Trust:** Continuous token validation, Context-aware authentication
- **API Security:** Advanced rate limiting, Threat detection
- **Privacy:** Token minimization, Data protection compliance

---

**Quellen:** RFC 7519 (JWT), RFC 6749 (OAuth 2.0), RFC 7636 (PKCE), OWASP Authentication Cheat Sheet, NIST Cybersecurity Framework 2.0, OAuth 2.1 Draft Specification, Modern API Security Best Practices 2025