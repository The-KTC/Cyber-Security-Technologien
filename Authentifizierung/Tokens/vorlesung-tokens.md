# Vorlesung: Tokens - Die Zukunft der digitalen Identität
## Von Sessions zur Stateless Authentication Revolution

---

## Vorlesungsplan (90 Minuten)

### 1. Die Revolution der Authentifizierung (15 Min)
### 2. JWT & Bearer Tokens - Das neue Paradigma (25 Min)
### 3. OAuth 2.0 & Advanced Flows (20 Min)
### 4. Token Security & Attack Vectors (20 Min)
### 5. Modern Trends & Future Vision (10 Min)

---

## 1. Die Revolution der Authentifizierung

### Das Ende der Session-Ära

**Warum Sessions nicht mehr funktionieren:**[245][242]

In den frühen Tagen des Webs war alles einfach. Ein Benutzer meldete sich an, der Server erstellte eine Session, speicherte sie in einer Datenbank, und setzte ein Cookie mit einer Session-ID. Dieser Ansatz funktionierte perfekt - solange Sie nur einen Server hatten.

```
Traditional Session-based Authentication:
1. User Login → Server creates session in database
2. Set-Cookie: JSESSIONID=ABC123
3. Every request → Server queries database for session
4. Session timeout → Database cleanup required

Problems:
├── Database bottleneck for every request
├── Horizontal scaling requires shared session storage
├── Cross-domain authentication complex
└── Mobile/API integration challenging
```

**Die Microservices-Herausforderung:**

Stellen Sie sich vor, Sie haben 20 Microservices. Mit traditionellen Sessions muss jeder Service entweder:
- Die Session-Datenbank abfragen (Performance-Problem)
- Session-Daten replizieren (Consistency-Problem)
- Einem zentralen Auth-Service vertrauen (Single Point of Failure)

**Enter: Token-based Authentication:**[245][242]

Token lösen diese Probleme elegant durch ein einfaches Paradigma:
> "Don't ask the database, trust the token"

### Token-Philosophie: Trust through Cryptography

**Das Kryptographie-Vertrauen:**[248][251]

Anstatt eine Datenbank zu fragen "Ist dieser Benutzer authentifiziert?", fragt ein Token-basiertes System:
- "Ist diese Signatur gültig?"
- "Ist dieses Token noch nicht abgelaufen?"
- "Vertraue ich dem Herausgeber dieses Tokens?"

```python
# Traditional Session Validation
def validate_session(session_id):
    session = database.query("SELECT * FROM sessions WHERE id = ?", session_id)
    if session and session.expires_at > now():
        return session.user_id
    return None

# Token-based Validation
def validate_token(jwt_token):
    try:
        claims = jwt.decode(jwt_token, public_key, algorithms=['RS256'])
        if claims['exp'] > time.time():
            return claims['sub']  # User ID
    except jwt.InvalidTokenError:
        pass
    return None
```

**Die Performance-Revolution:**

```
Session-based (1000 requests/second):
├── 1000 database queries
├── Network latency: ~5ms per query
└── Total overhead: ~5 seconds

Token-based (1000 requests/second):
├── 1000 cryptographic verifications
├── CPU time: ~0.1ms per verification
└── Total overhead: ~0.1 seconds

Performance improvement: 50x faster!
```

---

## 2. JWT & Bearer Tokens - Das neue Paradigma

### JSON Web Tokens: Anatomy of Trust

**JWT ist mehr als nur ein Token - es ist ein Vertrag:**[239][248][251]

Wenn Sie ein JWT betrachten, sehen Sie zunächst nur einen langen String:
```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoLmV4YW1wbGUuY29tIiwic3ViIjoidXNlcjEyMyIsImV4cCI6MTY3MjUzMTIwMCwiaWF0IjoxNjcyNTI3NjAwLCJhdWQiOiJhcGkuZXhhbXBsZS5jb20iLCJzY29wZSI6InJlYWQgd3JpdGUifQ.signature_data_here
```

Aber dieser String enthält drei entscheidende Komponenten:

#### Die drei Säulen eines JWT

**1. Header - Die Metadaten:**
```json
{
  "alg": "RS256",     // "Ich bin mit RSA-256 signiert"
  "typ": "JWT",       // "Ich bin ein JSON Web Token"
  "kid": "key-2025"   // "Verwende Schlüssel #key-2025 zur Verifikation"
}
```

**2. Payload - Die Wahrheit:**
```json
{
  "iss": "auth.company.com",      // "Ich wurde von auth.company.com ausgestellt"
  "sub": "alice@company.com",     // "Ich repräsentiere Alice"
  "exp": 1672531200,              // "Ich bin bis 31.12.2022 23:59:59 gültig"
  "iat": 1672527600,              // "Ich wurde am 31.12.2022 23:00:00 erstellt"
  "aud": ["api.company.com"],     // "Ich bin nur für api.company.com bestimmt"
  "scope": ["read", "write"],     // "Ich erlaube Lese- und Schreibzugriff"
  "roles": ["user", "editor"],    // "Alice ist User und Editor"
  "department": "engineering"     // "Alice arbeitet in der Entwicklung"
}
```

**3. Signature - Der Beweis:**
```javascript
// Vereinfachte Darstellung der Signatur-Erstellung
const header = base64urlEncode(JSON.stringify({alg: "RS256", typ: "JWT"}));
const payload = base64urlEncode(JSON.stringify(claims));
const message = header + "." + payload;

// Mit Private Key signieren
const signature = rsaSign(message, privateKey, 'SHA256');
const jwt = message + "." + base64urlEncode(signature);
```

**Live-Demo: JWT-Dekodierung**

Lassen Sie uns gemeinsam ein echtes JWT dekodieren:

```python
import base64
import json

def decode_jwt_manual(jwt_token):
    """Manual JWT decoding for educational purposes"""
    parts = jwt_token.split('.')
    
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")
    
    # Decode header
    header_data = base64.urlsafe_b64decode(parts[0] + '==')  # Add padding
    header = json.loads(header_data)
    print("Header:", json.dumps(header, indent=2))
    
    # Decode payload
    payload_data = base64.urlsafe_b64decode(parts[1] + '==')
    payload = json.loads(payload_data)
    print("Payload:", json.dumps(payload, indent=2))
    
    # Signature (binary data)
    signature = base64.urlsafe_b64decode(parts[2] + '==')
    print(f"Signature: {len(signature)} bytes")
    
    return header, payload, signature

# Live-Beispiel
sample_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

header, payload, signature = decode_jwt_manual(sample_jwt)
```

### Bearer Tokens: "Trust the Bearer"

**Das Bearer-Konzept:**[241][244][247]

"Bearer Token" ist ein brillant einfaches Konzept: **Wer auch immer dieses Token besitzt, dem gewähre ich die darin definierten Rechte.**

Es ist wie ein Konzertticket - der Türsteher fragt nicht nach Ihrem Ausweis, solange Ihr Ticket echt ist.

```http
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

Translation: "Hallo API, ich bin der rechtmäßige Besitzer dieses Tokens. 
            Bitte gewähre mir die Rechte, die darin definiert sind."
```

**Bearer vs. andere Auth-Schemas:**

```http
# Basic Authentication (immer Benutzername + Passwort)
Authorization: Basic dXNlcjpwYXNzd29yZA==

# Digest Authentication (komplexer Challenge-Response)
Authorization: Digest username="user", realm="api"...

# API Key (oft custom headers)
X-API-Key: sk_live_abc123...

# Bearer Token (standardisiert, flexibel)
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Token-Lifecycle: Von der Geburt bis zum Tod

**Ein Token-Leben in 7 Akten:**

```python
class TokenLifecycle:
    """Ein Token durchlebt verschiedene Phasen"""
    
    def __init__(self, user_credentials):
        self.user_credentials = user_credentials
        self.token_history = []
    
    def act_1_authentication(self):
        """Akt 1: Der Benutzer weist seine Identität nach"""
        print("🎭 Akt 1: User präsentiert Credentials")
        
        if self.validate_credentials(self.user_credentials):
            print("✅ Credentials valid - Token creation authorized")
            return True
        else:
            print("❌ Invalid credentials - No token for you!")
            return False
    
    def act_2_token_birth(self):
        """Akt 2: Das Token wird geboren"""
        print("🎭 Akt 2: Token Creation")
        
        claims = {
            'sub': self.user_credentials.user_id,
            'iss': 'auth.company.com',
            'aud': 'api.company.com',
            'exp': int(time.time()) + 3600,  # 1 hour lifetime
            'iat': int(time.time()),
            'scope': ['read', 'write'],
            'birth_certificate': 'This token was born at ' + datetime.now().isoformat()
        }
        
        token = jwt.encode(claims, private_key, algorithm='RS256')
        print(f"🍼 Token born: {len(token)} characters of pure trust")
        return token
    
    def act_3_first_journey(self, token):
        """Akt 3: Die erste Reise über das Netzwerk"""
        print("🎭 Akt 3: First HTTP Journey")
        
        # Token travels from client to server
        http_request = f"""
        GET /api/user/profile HTTP/1.1
        Host: api.company.com
        Authorization: Bearer {token}
        User-Agent: MyApp/1.0
        """
        
        print("🚀 Token embarks on HTTP journey...")
        print("📡 Transmitted over TLS-encrypted channel")
        return http_request
    
    def act_4_validation(self, token):
        """Akt 4: Die große Prüfung"""
        print("🎭 Akt 4: The Great Validation")
        
        try:
            # Server validates the token
            claims = jwt.decode(token, public_key, algorithms=['RS256'])
            
            # Check expiration
            if claims['exp'] < time.time():
                raise jwt.ExpiredSignatureError("Token expired")
            
            # Check audience
            if 'api.company.com' not in claims['aud']:
                raise jwt.InvalidAudienceError("Wrong audience")
            
            print("✅ Token passed all validation tests!")
            return claims
            
        except jwt.InvalidTokenError as e:
            print(f"❌ Token validation failed: {e}")
            return None
    
    def act_5_productive_life(self, validated_claims):
        """Akt 5: Das produktive Leben"""
        print("🎭 Akt 5: Productive Working Life")
        
        # Token is now working, granting access to resources
        granted_permissions = validated_claims['scope']
        user_id = validated_claims['sub']
        
        print(f"🔧 Token now working for user {user_id}")
        print(f"🔑 Granting permissions: {granted_permissions}")
        
        # Simulate multiple API calls
        api_calls = [
            "GET /api/user/profile",
            "GET /api/documents",
            "POST /api/documents/123/edit",
            "GET /api/notifications"
        ]
        
        for call in api_calls:
            print(f"  ✅ {call} - Access granted")
        
        return len(api_calls)
    
    def act_6_aging(self, token):
        """Akt 6: Das Altern"""
        print("🎭 Akt 6: The Aging Process")
        
        claims = jwt.decode(token, public_key, algorithms=['RS256'])
        current_time = time.time()
        expiry_time = claims['exp']
        
        time_remaining = expiry_time - current_time
        age_percentage = (3600 - time_remaining) / 3600 * 100
        
        if age_percentage > 90:
            print("👴 Token is very old, refresh recommended")
        elif age_percentage > 70:
            print("🧓 Token is aging, but still valid")
        else:
            print("👶 Token is young and fresh")
        
        return age_percentage
    
    def act_7_death_or_renewal(self, token, refresh_token=None):
        """Akt 7: Tod oder Erneuerung"""
        print("🎭 Akt 7: Death or Renewal")
        
        claims = jwt.decode(token, public_key, algorithms=['RS256'])
        
        if time.time() > claims['exp']:
            print("💀 Token has expired - Natural death")
            
            if refresh_token:
                print("🔄 But wait! Refresh token available")
                new_token = self.renew_with_refresh_token(refresh_token)
                print("👶 Phoenix-like rebirth! New token created")
                return new_token
            else:
                print("⚰️ Final death - User must re-authenticate")
                return None
        else:
            print("✨ Token still alive and kicking!")
            return token

# Live-Demo des Token-Lifecycles
demo = TokenLifecycle(user_credentials={'user_id': 'alice', 'password': 'secret123'})

if demo.act_1_authentication():
    token = demo.act_2_token_birth()
    request = demo.act_3_first_journey(token)
    claims = demo.act_4_validation(token)
    
    if claims:
        api_calls = demo.act_5_productive_life(claims)
        age = demo.act_6_aging(token)
        final_token = demo.act_7_death_or_renewal(token)
```

---

## 3. OAuth 2.0 & Advanced Flows

### OAuth 2.0: The Authorization Universe

**OAuth 2.0 ist nicht nur ein Standard - es ist ein ganzes Ökosystem:**[240][243][246]

```
OAuth 2.0 Universe:
├── Authorization Server (The Trust Authority)
├── Resource Server (The API Guardian)
├── Client Application (The Permission Seeker)
├── Resource Owner (The Human User)
└── Tokens (The Digital Passports)
    ├── Access Token (Short-lived, 1-2 hours)
    ├── Refresh Token (Long-lived, days/months)
    └── Authorization Code (Very short-lived, ~10 minutes)
```

**Die 4 klassischen OAuth-Flows:**

### Authorization Code Flow - Der Goldstandard

**Warum Authorization Code Flow der sicherste ist:**[280][295]

```python
class AuthorizationCodeFlow:
    """The most secure OAuth 2.0 flow"""
    
    def __init__(self, client_id, client_secret, redirect_uri):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.state = secrets.token_urlsafe(32)  # CSRF protection
    
    def step_1_authorization_request(self):
        """User clicks 'Login with Google/Facebook/etc.'"""
        print("🚀 Step 1: Redirect user to authorization server")
        
        auth_url = (
            f"https://auth.provider.com/oauth/authorize?"
            f"response_type=code&"
            f"client_id={self.client_id}&"
            f"redirect_uri={self.redirect_uri}&"
            f"scope=read+write+profile&"
            f"state={self.state}"
        )
        
        print(f"🔗 Redirecting to: {auth_url}")
        return auth_url
    
    def step_2_user_consent(self):
        """User sees: 'MyApp wants to access your data. Allow?'"""
        print("👤 Step 2: User provides consent")
        print("   ✅ User clicks 'Allow'")
        print("   🔒 User authenticates with provider")
        
        # Simulation - in reality, this happens on the auth server
        user_consents = True
        return user_consents
    
    def step_3_authorization_code(self, user_consented):
        """Auth server redirects back with code"""
        if user_consented:
            auth_code = secrets.token_urlsafe(32)
            print(f"📞 Step 3: Redirect back with code: {auth_code}")
            
            callback_url = f"{self.redirect_uri}?code={auth_code}&state={self.state}"
            print(f"🔙 Callback URL: {callback_url}")
            return auth_code
        else:
            print("❌ User denied consent")
            return None
    
    def step_4_token_exchange(self, auth_code):
        """Exchange code for tokens - THE CRITICAL STEP"""
        print("🔄 Step 4: Exchange code for tokens")
        
        token_request = {
            'grant_type': 'authorization_code',
            'code': auth_code,
            'client_id': self.client_id,
            'client_secret': self.client_secret,  # This proves we're the real client!
            'redirect_uri': self.redirect_uri
        }
        
        # This request is server-to-server - much more secure!
        print("🔐 Making server-to-server request...")
        print("   Client Secret protects against code interception!")
        
        # Simulate token response
        tokens = {
            'access_token': jwt.encode({
                'sub': 'user123',
                'scope': 'read write profile',
                'exp': int(time.time()) + 3600
            }, 'secret', algorithm='HS256'),
            'refresh_token': secrets.token_urlsafe(32),
            'token_type': 'Bearer',
            'expires_in': 3600
        }
        
        print("✅ Tokens received!")
        return tokens

# Live-Demo des Authorization Code Flows
flow = AuthorizationCodeFlow(
    client_id="myapp123",
    client_secret="super_secret_client_secret",
    redirect_uri="https://myapp.com/callback"
)

auth_url = flow.step_1_authorization_request()
consent = flow.step_2_user_consent()
code = flow.step_3_authorization_code(consent)
if code:
    tokens = flow.step_4_token_exchange(code)
```

### PKCE: Der Code-Interception-Killer

**Das Problem, das PKCE löst:**[280][286][289]

Stellen Sie sich vor: Ein Angreifer sitzt im gleichen WLAN wie Sie. Ihre Mobile App startet einen OAuth-Flow. Der Authorization Code wird über HTTP übertragen (auch wenn HTTPS verwendet wird, kann es Schwachstellen geben).

**Ohne PKCE:**
```
1. App → Auth Server: "Gib mir einen Code"
2. Auth Server → App: "Hier ist Code ABC123"  
3. Angreifer fängt Code ab! 🕷️
4. Angreifer → Token Endpoint: "Code ABC123 gegen Tokens tauschen"
5. Token Endpoint: "Hier sind deine Tokens" ❌
```

**Mit PKCE:**
```python
class PKCEProtectedFlow:
    """PKCE macht Code-Interception nutzlos"""
    
    def __init__(self, client_id):
        self.client_id = client_id
        # Generate PKCE parameters
        self.code_verifier = base64.urlsafe_b64encode(
            secrets.token_bytes(32)
        ).decode('utf-8').rstrip('=')
        
        self.code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(self.code_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')
        
        print(f"🔐 Generated Code Verifier: {self.code_verifier[:10]}...")
        print(f"🔐 Generated Code Challenge: {self.code_challenge[:10]}...")
    
    def authorization_request_with_pkce(self):
        """Authorization request includes code challenge"""
        auth_url = (
            f"https://auth.provider.com/oauth/authorize?"
            f"response_type=code&"
            f"client_id={self.client_id}&"
            f"code_challenge={self.code_challenge}&"
            f"code_challenge_method=S256&"
            f"scope=read"
        )
        
        print("🚀 Authorization request with PKCE challenge")
        return auth_url
    
    def token_exchange_with_pkce(self, auth_code):
        """Token exchange requires code verifier"""
        print("🔄 Token exchange - must prove code ownership")
        
        token_request = {
            'grant_type': 'authorization_code',
            'code': auth_code,
            'client_id': self.client_id,
            'code_verifier': self.code_verifier  # THE PROOF!
        }
        
        # Server validation
        received_challenge = self.code_challenge
        received_verifier = token_request['code_verifier']
        
        # Server recomputes challenge from verifier
        computed_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(received_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')
        
        if computed_challenge == received_challenge:
            print("✅ PKCE verification successful!")
            print("🎯 Only the original client can complete this exchange")
            return {'access_token': 'secured_by_pkce_token'}
        else:
            print("❌ PKCE verification failed - Code interception detected!")
            return None

# Demonstration PKCE-Protection
pkce_flow = PKCEProtectedFlow("mobile_app_123")
auth_url = pkce_flow.authorization_request_with_pkce()

# Simulate authorization code (even if intercepted, it's useless without verifier!)
intercepted_code = "INTERCEPTED_CODE_123"
result = pkce_flow.token_exchange_with_pkce(intercepted_code)
```

### Refresh Tokens: The Immortality Mechanism

**Refresh Tokens lösen das Dilemma zwischen Sicherheit und Usability:**[240][249][252]

```python
class RefreshTokenManager:
    """Managing token refresh for seamless user experience"""
    
    def __init__(self):
        self.active_refresh_tokens = {}
        self.token_families = {}  # For rotation detection
    
    def create_token_pair(self, user_id, scopes):
        """Create access + refresh token pair"""
        print(f"👤 Creating token pair for user: {user_id}")
        
        # Short-lived access token
        access_token = jwt.encode({
            'sub': user_id,
            'scope': ' '.join(scopes),
            'exp': int(time.time()) + 3600,  # 1 hour
            'iat': int(time.time()),
            'token_type': 'access'
        }, 'access_secret', algorithm='HS256')
        
        # Long-lived refresh token (opaque)
        refresh_token_id = secrets.token_urlsafe(32)
        token_family_id = str(uuid.uuid4())
        
        refresh_token_data = {
            'user_id': user_id,
            'scopes': scopes,
            'created_at': time.time(),
            'family_id': token_family_id,
            'generation': 1
        }
        
        self.active_refresh_tokens[refresh_token_id] = refresh_token_data
        self.token_families[token_family_id] = [refresh_token_id]
        
        print(f"✅ Access token expires in: 1 hour")
        print(f"✅ Refresh token expires in: 30 days")
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token_id,
            'token_type': 'Bearer',
            'expires_in': 3600
        }
    
    def refresh_access_token(self, refresh_token_id):
        """The magic of seamless token refresh"""
        print("🔄 Attempting token refresh...")
        
        if refresh_token_id not in self.active_refresh_tokens:
            print("❌ Invalid refresh token")
            return None
        
        old_token_data = self.active_refresh_tokens[refresh_token_id]
        
        # Check if refresh token is expired (30 days)
        if time.time() - old_token_data['created_at'] > 30 * 24 * 3600:
            print("❌ Refresh token expired - user must re-authenticate")
            return None
        
        print("✅ Refresh token valid - issuing new tokens")
        
        # Create new access token
        new_access_token = jwt.encode({
            'sub': old_token_data['user_id'],
            'scope': ' '.join(old_token_data['scopes']),
            'exp': int(time.time()) + 3600,
            'iat': int(time.time()),
            'token_type': 'access'
        }, 'access_secret', algorithm='HS256')
        
        # SECURITY: Rotate refresh token (recommended best practice)
        new_refresh_token_id = secrets.token_urlsafe(32)
        new_token_data = old_token_data.copy()
        new_token_data['generation'] += 1
        new_token_data['created_at'] = time.time()
        
        # Update token family
        family_id = old_token_data['family_id']
        self.token_families[family_id].append(new_refresh_token_id)
        
        # Store new, invalidate old
        self.active_refresh_tokens[new_refresh_token_id] = new_token_data
        del self.active_refresh_tokens[refresh_token_id]
        
        print("🔄 Refresh token rotated for security")
        
        return {
            'access_token': new_access_token,
            'refresh_token': new_refresh_token_id,
            'token_type': 'Bearer',
            'expires_in': 3600
        }
    
    def detect_token_theft(self, old_refresh_token_id):
        """Detect if someone is using a rotated refresh token"""
        print("🕵️ Checking for token theft...")
        
        if old_refresh_token_id in self.active_refresh_tokens:
            return False  # Still valid, no theft
        
        # Check if this token was part of a family
        for family_id, token_list in self.token_families.items():
            if old_refresh_token_id in token_list:
                print("🚨 SECURITY ALERT: Old refresh token used!")
                print("🚨 Possible token theft detected!")
                
                # Revoke entire token family
                for token_id in token_list:
                    if token_id in self.active_refresh_tokens:
                        del self.active_refresh_tokens[token_id]
                
                print("🔒 All tokens in family revoked - user must re-authenticate")
                return True
        
        return False

# Demo der Refresh-Token-Mechanik
rtm = RefreshTokenManager()

# Initial token creation
tokens = rtm.create_token_pair('alice@company.com', ['read', 'write'])
print(f"🎫 Initial tokens created")

# Simulate app using access token for 1 hour...
time.sleep(1)  # In reality: 1 hour

# Access token expires, app automatically refreshes
new_tokens = rtm.refresh_access_token(tokens['refresh_token'])
if new_tokens:
    print("✅ Seamless token refresh - user never noticed!")

# Simulate token theft attempt
rtm.detect_token_theft(tokens['refresh_token'])  # Old token used = theft detected
```

---

## 4. Token Security & Attack Vectors

### JWT-Angriffe: When Trust Goes Wrong

**JWT-Sicherheit ist wie ein Schloss - nur so stark wie das schwächste Glied:**[248][251]

#### 1. The "None" Algorithm Attack

```python
class JWTSecurityDemo:
    """Demonstrating common JWT vulnerabilities"""
    
    def none_algorithm_attack(self):
        """The infamous 'alg: none' attack"""
        print("⚔️ Demonstrating 'none' algorithm attack")
        
        # Legitimate JWT
        legitimate_header = {'alg': 'HS256', 'typ': 'JWT'}
        legitimate_payload = {'sub': 'user', 'role': 'user', 'exp': int(time.time()) + 3600}
        legitimate_token = jwt.encode(legitimate_payload, 'secret', algorithm='HS256')
        
        print(f"✅ Legitimate token: {legitimate_token[:50]}...")
        
        # Attacker creates malicious token
        malicious_header = {'alg': 'none', 'typ': 'JWT'}  # No algorithm!
        malicious_payload = {'sub': 'admin', 'role': 'admin', 'exp': int(time.time()) + 3600}
        
        # Manual token creation (no signature!)
        header_b64 = base64.urlsafe_b64encode(json.dumps(malicious_header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(malicious_payload).encode()).decode().rstrip('=')
        malicious_token = f"{header_b64}.{payload_b64}."  # Note: empty signature!
        
        print(f"⚔️ Malicious token: {malicious_token}")
        
        # Vulnerable server code
        def vulnerable_verify(token):
            parts = token.split('.')
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            
            if header['alg'] == 'none':
                # VULNERABLE: Accepts unsigned tokens!
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
                return payload
            else:
                return jwt.decode(token, 'secret', algorithms=['HS256'])
        
        # Secure server code
        def secure_verify(token):
            # SECURE: Explicitly specify allowed algorithms
            return jwt.decode(token, 'secret', algorithms=['HS256'])  # 'none' not allowed!
        
        print("\n🔍 Testing vulnerable server:")
        try:
            result = vulnerable_verify(malicious_token)
            print(f"❌ BREACH: Server accepted malicious token! User role: {result['role']}")
        except:
            print("✅ Malicious token rejected")
        
        print("\n🔒 Testing secure server:")
        try:
            result = secure_verify(malicious_token)
            print(f"❌ This should not print")
        except:
            print("✅ Secure server rejected malicious token")
    
    def key_confusion_attack(self):
        """RSA public key used as HMAC secret"""
        print("\n⚔️ Demonstrating Key Confusion Attack")
        
        # Server uses RSA keys
        private_key = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB
wxPkOv/iwQoTwq8gP+mBvYqeq7uUnKB5rLrrbS2QGKyfF8hEQnZB...
-----END PRIVATE KEY-----"""
        
        public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1L7VLPHCgcMT5Dr/
4sEKE8KvID/pgb2Knqu7lJygeay6620tkBisnxfIREJ2QQA7...
-----END PUBLIC KEY-----"""
        
        # Legitimate RS256 token
        payload = {'sub': 'user', 'role': 'user', 'exp': int(time.time()) + 3600}
        rs256_token = jwt.encode(payload, private_key, algorithm='RS256')
        
        print(f"✅ Legitimate RS256 token created")
        
        # Attacker creates HS256 token using public key as secret
        malicious_payload = {'sub': 'admin', 'role': 'admin', 'exp': int(time.time()) + 3600}
        
        # This is the attack: use public key as HMAC secret
        hs256_malicious_token = jwt.encode(malicious_payload, public_key, algorithm='HS256')
        
        print(f"⚔️ Malicious HS256 token created using public key")
        
        # Vulnerable server (accepts both algorithms)
        def vulnerable_server(token):
            try:
                # Vulnerable: Allows both RS256 and HS256
                return jwt.decode(token, public_key, algorithms=['RS256', 'HS256'])
            except:
                return None
        
        # Secure server (algorithm-specific verification)
        def secure_server(token):
            header = jwt.get_unverified_header(token)
            if header['alg'] == 'RS256':
                return jwt.decode(token, public_key, algorithms=['RS256'])
            else:
                raise ValueError("Unsupported algorithm")
        
        print("\n🔍 Testing vulnerable server:")
        result = vulnerable_server(hs256_malicious_token)
        if result:
            print(f"❌ BREACH: Key confusion successful! Role: {result['role']}")
        
        print("\n🔒 Testing secure server:")
        try:
            result = secure_server(hs256_malicious_token)
        except:
            print("✅ Secure server prevented key confusion attack")

# Live-Demo der JWT-Angriffe
security_demo = JWTSecurityDemo()
security_demo.none_algorithm_attack()
security_demo.key_confusion_attack()
```

### Token Replay Attacks: The Time Dimension

**Replay Attacks nutzen die Zeit-Dimension aus:**[261][267][270]

```python
class ReplayAttackDemo:
    """Token Replay Attack scenarios and defenses"""
    
    def __init__(self):
        self.used_nonces = set()
        self.request_timestamps = {}
    
    def simulate_replay_attack(self):
        """Showing how replay attacks work"""
        print("🔄 Simulating Token Replay Attack")
        
        # Step 1: Legitimate user makes a request
        legitimate_token = self.create_legitimate_token()
        print("✅ Legitimate user creates token")
        
        # Step 2: Attacker intercepts token (network sniffing, etc.)
        intercepted_token = legitimate_token  # Same token!
        print("🕷️ Attacker intercepts token")
        
        # Step 3: Attacker reuses token multiple times
        print("\n⚔️ Attacker attempting multiple reuses:")
        
        for i in range(3):
            print(f"  Attempt {i+1}:")
            result = self.process_api_request(intercepted_token, f"attacker_request_{i}")
            if result['success']:
                print(f"    ❌ BREACH: Attack successful - {result['data']}")
            else:
                print(f"    ✅ Attack blocked: {result['error']}")
    
    def create_legitimate_token(self):
        """Create a token with anti-replay measures"""
        nonce = secrets.token_hex(16)
        timestamp = int(time.time())
        
        payload = {
            'sub': 'user123',
            'exp': int(time.time()) + 3600,
            'iat': timestamp,
            'nonce': nonce,  # Unique identifier
            'jti': str(uuid.uuid4()),  # JWT ID for tracking
        }
        
        return jwt.encode(payload, 'secret', algorithm='HS256')
    
    def process_api_request(self, token, request_id):
        """Process API request with replay protection"""
        try:
            claims = jwt.decode(token, 'secret', algorithms=['HS256'])
            
            # Anti-replay checks
            nonce = claims.get('nonce')
            timestamp = claims.get('iat')
            jwt_id = claims.get('jti')
            
            # Check 1: Nonce-based protection
            if nonce in self.used_nonces:
                return {'success': False, 'error': 'Nonce already used (replay detected)'}
            
            # Check 2: Timestamp freshness (5-minute window)
            current_time = int(time.time())
            if current_time - timestamp > 300:  # 5 minutes
                return {'success': False, 'error': 'Request too old (possible replay)'}
            
            # Check 3: JWT ID tracking
            if jwt_id in self.request_timestamps:
                return {'success': False, 'error': 'JWT ID already used (replay detected)'}
            
            # All checks passed - mark as used
            self.used_nonces.add(nonce)
            self.request_timestamps[jwt_id] = current_time
            
            return {
                'success': True, 
                'data': f'Sensitive data for {claims["sub"]}'
            }
            
        except jwt.ExpiredSignatureError:
            return {'success': False, 'error': 'Token expired'}
        except jwt.InvalidTokenError:
            return {'success': False, 'error': 'Invalid token'}
    
    def demonstrate_cryptographic_binding(self):
        """Advanced: Cryptographically bound requests"""
        print("\n🔐 Advanced: Cryptographic Request Binding")
        
        # Generate request-specific signature
        def create_bound_request(token, request_data, private_key):
            """Create request with cryptographic binding"""
            
            # Create signature of token + request data + timestamp
            timestamp = int(time.time())
            message = f"{token}:{request_data}:{timestamp}"
            
            signature = jwt.encode({
                'message_hash': hashlib.sha256(message.encode()).hexdigest(),
                'timestamp': timestamp
            }, private_key, algorithm='HS256')
            
            return {
                'token': token,
                'request_data': request_data,
                'timestamp': timestamp,
                'signature': signature
            }
        
        # User private key (in real app: securely stored)
        user_private_key = "user_secret_key_123"
        
        # Create bound request
        token = self.create_legitimate_token()
        bound_request = create_bound_request(
            token, 
            "GET /api/sensitive-data", 
            user_private_key
        )
        
        print("✅ Created cryptographically bound request")
        print(f"   Request cannot be replayed without private key")

# Demo der Replay-Attack-Szenarien
replay_demo = ReplayAttackDemo()
replay_demo.simulate_replay_attack()
replay_demo.demonstrate_cryptographic_binding()
```

---

## 5. Modern Trends & Future Vision

### Zero Trust Tokens: Never Trust, Always Verify

**Die Evolution zu kontinuierlicher Verifikation:**[273]

```python
class ZeroTrustTokenArchitecture:
    """Future of token-based authentication"""
    
    def __init__(self):
        self.risk_engine = RiskAssessmentEngine()
        self.context_analyzer = ContextAnalyzer()
        self.policy_engine = PolicyEngine()
    
    def evaluate_token_request(self, token, context):
        """Zero Trust evaluation for every token use"""
        print("🔍 Zero Trust Token Evaluation")
        
        # Traditional validation
        basic_validation = self.validate_token_cryptography(token)
        if not basic_validation['valid']:
            return {'granted': False, 'reason': 'Invalid token'}
        
        # Context analysis
        context_score = self.analyze_request_context(context)
        print(f"📊 Context risk score: {context_score:.2f}")
        
        # Continuous risk assessment
        risk_factors = {
            'geolocation_anomaly': self.check_location_anomaly(context),
            'device_trust_score': self.assess_device_trust(context),
            'behavioral_pattern': self.analyze_user_behavior(context),
            'network_reputation': self.check_network_reputation(context),
            'time_pattern': self.analyze_access_time(context)
        }
        
        total_risk = sum(risk_factors.values()) / len(risk_factors)
        print(f"⚠️ Total risk score: {total_risk:.2f}")
        
        # Dynamic token lifetime based on risk
        if total_risk > 0.8:
            return {
                'granted': False,
                'reason': 'High risk detected',
                'required_action': 'step_up_authentication'
            }
        elif total_risk > 0.5:
            return {
                'granted': True,
                'token_lifetime': 900,  # 15 minutes instead of 1 hour
                'required_controls': ['mfa_verification_required']
            }
        else:
            return {
                'granted': True,
                'token_lifetime': 3600,  # Full lifetime
                'trust_level': 'high'
            }
    
    def analyze_request_context(self, context):
        """Comprehensive context analysis"""
        print("🔍 Analyzing request context...")
        
        # Device fingerprinting
        device_trust = 0.8 if context.device_known else 0.3
        
        # Location analysis
        location_trust = 1.0 if context.location_known else 0.5
        
        # Time-based analysis
        current_hour = datetime.now().hour
        time_trust = 0.9 if 6 <= current_hour <= 22 else 0.6  # Work hours
        
        # Network reputation
        network_trust = 0.9 if context.corporate_network else 0.7
        
        overall_trust = (device_trust + location_trust + time_trust + network_trust) / 4
        return 1.0 - overall_trust  # Convert to risk score

# Beispiel der Zero Trust Evaluation
class MockContext:
    def __init__(self, device_known=True, location_known=True, corporate_network=True):
        self.device_known = device_known
        self.location_known = location_known
        self.corporate_network = corporate_network

zt_architecture = ZeroTrustTokenArchitecture()

# Scenario 1: Trusted context
trusted_context = MockContext(device_known=True, location_known=True, corporate_network=True)
result1 = zt_architecture.evaluate_token_request("dummy_token", trusted_context)
print(f"✅ Trusted context result: {result1}")

# Scenario 2: Suspicious context
suspicious_context = MockContext(device_known=False, location_known=False, corporate_network=False)
result2 = zt_architecture.evaluate_token_request("dummy_token", suspicious_context)
print(f"⚠️ Suspicious context result: {result2}")
```

### Token-bound Sessions: The Hardware Revolution

**Hardware-gebundene Tokens für ultimative Sicherheit:**[273][289]

```python
class HardwareBoundTokens:
    """Tokens bound to hardware characteristics"""
    
    def __init__(self):
        self.device_registry = {}
        self.hardware_attestation = HardwareAttestationService()
    
    def create_hardware_bound_token(self, user_id, device_info):
        """Create token bound to specific hardware"""
        print("🔧 Creating hardware-bound token")
        
        # Generate device fingerprint
        device_fingerprint = self.generate_device_fingerprint(device_info)
        
        # Hardware attestation (TPM, Secure Enclave, etc.)
        attestation_data = self.hardware_attestation.attest_device(device_info)
        
        # Create bound token
        bound_token_claims = {
            'sub': user_id,
            'exp': int(time.time()) + 3600,
            'device_binding': {
                'fingerprint': device_fingerprint,
                'attestation': attestation_data,
                'hardware_keys': device_info.get('hw_keys', [])
            },
            'binding_type': 'hardware_bound'
        }
        
        # Sign with device-specific key material
        device_key = self.derive_device_key(device_fingerprint)
        bound_token = jwt.encode(bound_token_claims, device_key, algorithm='HS256')
        
        print(f"✅ Token bound to device: {device_fingerprint[:8]}...")
        return bound_token
    
    def validate_hardware_bound_token(self, token, current_device_info):
        """Validate hardware binding"""
        print("🔍 Validating hardware binding...")
        
        current_fingerprint = self.generate_device_fingerprint(current_device_info)
        device_key = self.derive_device_key(current_fingerprint)
        
        try:
            claims = jwt.decode(token, device_key, algorithms=['HS256'])
            token_fingerprint = claims['device_binding']['fingerprint']
            
            if current_fingerprint == token_fingerprint:
                print("✅ Hardware binding validation successful")
                return claims
            else:
                print("❌ Hardware binding mismatch - token stolen/moved?")
                return None
                
        except jwt.InvalidTokenError:
            print("❌ Token validation failed - hardware binding broken")
            return None
    
    def generate_device_fingerprint(self, device_info):
        """Create unique device fingerprint"""
        fingerprint_data = {
            'cpu_info': device_info.get('cpu_serial'),
            'motherboard_id': device_info.get('board_id'),
            'mac_addresses': sorted(device_info.get('mac_addrs', [])),
            'installed_software_hash': device_info.get('sw_hash'),
            'tpm_endorsement_key': device_info.get('tpm_ek')
        }
        
        fingerprint_string = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(fingerprint_string.encode()).hexdigest()
    
    def derive_device_key(self, device_fingerprint):
        """Derive cryptographic key from device characteristics"""
        # PBKDF2 key derivation from device fingerprint
        master_salt = b"device_binding_salt_2025"
        device_key = hashlib.pbkdf2_hmac(
            'sha256',
            device_fingerprint.encode(),
            master_salt,
            100000  # iterations
        )
        return base64.b64encode(device_key).decode()

# Demo hardware-bound tokens
hw_token_system = HardwareBoundTokens()

# Simulate device info
device_info = {
    'cpu_serial': 'CPU123456789',
    'board_id': 'MB987654321',
    'mac_addrs': ['00:1B:44:11:3A:B7', '00:1B:44:11:3A:B8'],
    'sw_hash': 'abc123def456',
    'tmp_ek': 'tpm_key_data'
}

# Create bound token
hw_token = hw_token_system.create_hardware_bound_token('alice', device_info)

# Validate on same device (should succeed)
validation_result = hw_token_system.validate_hardware_bound_token(hw_token, device_info)

# Validate on different device (should fail)
different_device = device_info.copy()
different_device['cpu_serial'] = 'DIFFERENT_CPU'
validation_result_2 = hw_token_system.validate_hardware_bound_token(hw_token, different_device)
```

### The Future: Quantum-Resistant Tokens

**Vorbereitung auf die Post-Quantum-Ära:**

```python
class QuantumResistantTokens:
    """Preparing for the quantum computing threat"""
    
    def __init__(self):
        # Hybrid classical/quantum-resistant approach
        self.classical_key = self.load_rsa_key()
        self.pq_key = self.load_crystal_kyber_key()  # Post-quantum algorithm
    
    def create_hybrid_token(self, payload):
        """Token signed with both classical and post-quantum algorithms"""
        print("🔮 Creating quantum-resistant token")
        
        # Classical signature (for current compatibility)
        classical_signature = self.sign_classical(payload)
        
        # Post-quantum signature (for future security)
        pq_signature = self.sign_post_quantum(payload)
        
        # Hybrid token structure
        hybrid_token = {
            'header': {
                'alg': 'HYBRID_RSA_CRYSTALS',
                'typ': 'JWT'
            },
            'payload': payload,
            'signatures': {
                'classical': classical_signature,
                'post_quantum': pq_signature
            }
        }
        
        print("✅ Hybrid token created - quantum-ready!")
        return json.dumps(hybrid_token)
    
    def verify_hybrid_token(self, hybrid_token_json):
        """Verify using both signature types"""
        token = json.loads(hybrid_token_json)
        
        # Verify classical signature (current)
        classical_valid = self.verify_classical(
            token['payload'], 
            token['signatures']['classical']
        )
        
        # Verify post-quantum signature (future-proof)
        pq_valid = self.verify_post_quantum(
            token['payload'], 
            token['signatures']['post_quantum']
        )
        
        # Both must be valid for security
        if classical_valid and pq_valid:
            print("✅ Hybrid verification successful - quantum-resistant!")
            return token['payload']
        else:
            print("❌ Hybrid verification failed")
            return None
```

---

## Zusammenfassung & Vision

### Die Token-Revolution ist erst der Anfang

**Was wir heute gelernt haben:**

1. **Paradigmenwechsel:** Von Sessions zu stateless Tokens
2. **JWT-Anatomie:** Header, Payload, Signature - die drei Säulen des Vertrauens
3. **OAuth-Ökosystem:** Authorization Codes, Access & Refresh Tokens
4. **PKCE-Revolution:** Code-Interception-Schutz für mobile Apps
5. **Sicherheits-Realität:** Angriffe und Verteidigung
6. **Zukunfts-Vision:** Zero Trust, Hardware-Binding, Quantum-Resistance

### Die nächste Dekade der Token-Evolution

**Trends 2025-2035:**

```
Token Evolution Timeline:
├── 2025: Universal PKCE adoption, Hardware token binding
├── 2027: AI-powered risk assessment, Dynamic token lifetimes
├── 2030: Quantum-resistant algorithms mainstream
├── 2033: Biometric token binding, Neural authentication
└── 2035: Fully autonomous security, Self-healing tokens
```

**Call to Action für Entwickler:**

1. **Adoptieren Sie OAuth 2.1** mit mandatory PKCE
2. **Implementieren Sie Zero Trust** token validation
3. **Vorbereitung auf Post-Quantum** cryptography
4. **Hardware-Security** wo immer möglich
5. **Continuous Learning** - Security ist ein Marathon, kein Sprint

### Abschlusszitat

> "In der Welt der digitalen Identität sind Tokens nicht nur Technologie - sie sind die DNA der Zukunft. Jeder Token trägt die Verantwortung für das Vertrauen, das unsere vernetzte Welt zusammenhält."

---

**Vielen Dank für Ihre Aufmerksamkeit!**

### Weiterführende Ressourcen
- **JWT.io:** Interactive token decoder und validator
- **OAuth 2.1 Specification:** Latest security enhancements
- **OWASP Authentication Cheat Sheet:** Security best practices
- **RFC 7636 (PKCE):** Proof Key for Code Exchange specification
- **NIST Post-Quantum Cryptography:** Future-proofing guidelines

### Nächste Vorlesung
**Thema:** "Zero Trust Architectures - Never Trust, Always Verify"

---

*Diese Vorlesung basiert auf RFC 7519 (JWT), RFC 6749 (OAuth 2.0), RFC 7636 (PKCE), aktuellen OWASP Guidelines und modernen Token-Security-Standards 2025.*