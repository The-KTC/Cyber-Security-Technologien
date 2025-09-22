# Interaktive Übung: Passkey-Implementierungs-Workshop
## Von der Theorie zur Praxis: WebAuthn hands-on erleben

---

## Workshop-Konzept (120 Minuten)

**Ziel:** Teilnehmende implementieren eine vollständige Passkey-Authentifizierung von Grund auf und erleben dabei die technischen Herausforderungen und Sicherheitsvorteile firsthand.

**Format:** Progressive Implementation mit Live-Coding, Pair Programming und praktischen Security-Tests

**Teilnehmerzahl:** 10-16 Personen (Laptop + Smartphone erforderlich)

**Tech-Stack:** Node.js Backend, Vanilla JavaScript Frontend, Chrome/Safari mit WebAuthn-Support

---

## Pre-Workshop-Setup (15 Minuten)

### Technische Voraussetzungen

**Für jeden Teilnehmenden:**
- **Laptop:** Windows/Mac/Linux mit Chrome 67+ oder Safari 14+
- **Smartphone:** iOS 16+ oder Android 9+ mit Fingerprint/Face ID
- **Development Environment:** Node.js 18+, npm, Code Editor
- **Network:** HTTPS-fähiges Setup (lokale Development-Umgebung)

### Workshop-Repository Setup
```bash
# Repository clonen
git clone https://github.com/passkey-workshop/webauthn-implementation.git
cd webauthn-implementation

# Dependencies installieren
npm install

# HTTPS Development-Server starten (WebAuthn requires HTTPS!)
npm run dev:https

# Browser öffnen: https://localhost:3000
```

**Repository-Struktur:**
```
passkey-workshop/
├── frontend/
│   ├── index.html              # Landing page
│   ├── register.html           # Passkey Registration
│   ├── login.html              # Passkey Authentication
│   └── js/
│       ├── webauthn-client.js  # WebAuthn API wrapper
│       └── utils.js            # Helper functions
├── backend/
│   ├── server.js               # Express server
│   ├── routes/
│   │   ├── auth.js             # Authentication endpoints
│   │   └── user.js             # User management
│   ├── models/
│   │   └── user.js             # User data model
│   └── utils/
│       ├── webauthn-server.js  # Server-side WebAuthn logic
│       └── crypto.js           # Cryptographic utilities
├── tests/
│   ├── security-tests.js       # Phishing resistance tests
│   └── cross-platform-tests.js# Multi-device scenarios
└── docs/
    ├── API.md                  # API documentation
    └── TROUBLESHOOTING.md      # Common issues & solutions
```

---

## Phase 1: WebAuthn-Grundlagen verstehen (25 Minuten)

### Lab 1.1: Challenge-Response-Mechanismus implementieren (15 Min)

**Aufgabe:** Implementieren Sie die Basis-Kryptographie für Challenge-Response

**Pair Programming:** Arbeiten Sie zu zweit an dieser Implementierung

```javascript
// frontend/js/webauthn-client.js - Starter Code
class WebAuthnClient {
    constructor(baseURL = 'https://localhost:3000') {
        this.baseURL = baseURL;
        this.encoder = new TextEncoder();
        this.decoder = new TextDecoder();
    }
    
    // TODO: Implementieren Sie Challenge-Request
    async requestChallenge(username, operation = 'register') {
        // 1. HTTP Request an Server für Challenge
        // 2. Challenge in ArrayBuffer konvertieren
        // 3. User-Info für WebAuthn formatieren
        
        const response = await fetch(`${this.baseURL}/api/auth/challenge`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, operation })
        });
        
        const challengeData = await response.json();
        
        // TODO: Base64URL -> ArrayBuffer Konvertierung
        return {
            challenge: /* TODO: Implementieren */,
            user: {
                id: /* TODO: Username zu ArrayBuffer */,
                name: username,
                displayName: username
            },
            rp: {
                name: "Passkey Workshop",
                id: window.location.hostname
            }
        };
    }
    
    // TODO: Implementieren Sie Credential Registration
    async registerPasskey(username) {
        try {
            const challengeOptions = await this.requestChallenge(username, 'register');
            
            // WebAuthn Registration Options
            const publicKeyCredentialCreationOptions = {
                challenge: challengeOptions.challenge,
                rp: challengeOptions.rp,
                user: challengeOptions.user,
                
                // TODO: Implementieren Sie PubKeyCredParams
                pubKeyCredParams: [
                    // Welche Algorithmen sollen unterstützt werden?
                ],
                
                // TODO: Authenticator Selection
                authenticatorSelection: {
                    // Platform (Touch ID) oder Cross-Platform (USB)?
                    // User Verification required?
                },
                
                // TODO: Timeout und Attestation
                timeout: 60000,
                attestation: "direct"  // Hardware-Nachweis
            };
            
            // WebAuthn API Call
            const credential = await navigator.credentials.create({
                publicKey: publicKeyCredentialCreationOptions
            });
            
            // TODO: Credential an Server senden
            return this.sendCredentialToServer(credential, 'register');
            
        } catch (error) {
            console.error('Passkey registration failed:', error);
            throw error;
        }
    }
}
```

**Expected Output nach Implementation:**
```javascript
// Test der Challenge-Request
const client = new WebAuthnClient();
client.requestChallenge('demo-user').then(options => {
    console.log('✅ Challenge received:', options.challenge.byteLength, 'bytes');
    console.log('✅ User ID:', options.user.id);
    console.log('✅ RP ID:', options.rp.id);
});
```

### Lab 1.2: Server-Side Challenge-Verifikation (10 Min)

**Aufgabe:** Implementieren Sie die Server-seitige Logik

```javascript
// backend/utils/webauthn-server.js
const crypto = require('crypto');
const cbor = require('cbor');

class WebAuthnServer {
    constructor() {
        this.challenges = new Map(); // In production: Redis/Database
        this.users = new Map();      // In production: Database
    }
    
    // TODO: Challenge-Generierung
    generateChallenge(username, operation) {
        const challenge = crypto.randomBytes(32);
        const challengeId = crypto.randomUUID();
        
        // Challenge temporär speichern (5 min TTL)
        this.challenges.set(challengeId, {
            challenge: challenge,
            username: username,
            operation: operation,
            createdAt: new Date(),
            used: false
        });
        
        setTimeout(() => this.challenges.delete(challengeId), 5 * 60 * 1000);
        
        return {
            challengeId: challengeId,
            challenge: challenge.toString('base64url'),
            expires: new Date(Date.now() + 5 * 60 * 1000)
        };
    }
    
    // TODO: Registration-Verifikation implementieren
    async verifyRegistration(challengeId, credentialData) {
        const challengeInfo = this.challenges.get(challengeId);
        if (!challengeInfo || challengeInfo.used) {
            throw new Error('Invalid or expired challenge');
        }
        
        // Challenge als verwendet markieren
        challengeInfo.used = true;
        
        // TODO: Attestation Object dekodieren
        const attestationObject = /* TODO: CBOR decode */;
        const clientDataJSON = /* TODO: JSON parse */;
        
        // TODO: Verifikationsschritte implementieren
        const verificationSteps = [
            // 1. Challenge-Verifikation
            () => this.verifyChallenge(clientDataJSON, challengeInfo.challenge),
            
            // 2. Origin-Verifikation (Phishing-Schutz)
            () => this.verifyOrigin(clientDataJSON),
            
            // 3. Attestation-Verifikation
            () => this.verifyAttestation(attestationObject),
            
            // 4. Public Key-Extraktion
            () => this.extractPublicKey(attestationObject)
        ];
        
        for (const [index, step] of verificationSteps.entries()) {
            try {
                await step();
                console.log(`✅ Verification step ${index + 1} passed`);
            } catch (error) {
                console.error(`❌ Verification step ${index + 1} failed:`, error);
                throw error;
            }
        }
        
        // TODO: User Registration abschließen
        return this.completeRegistration(challengeInfo.username, credentialData);
    }
    
    // TODO: Implementieren Sie die einzelnen Verifikationsschritte
    verifyChallenge(clientData, expectedChallenge) {
        // Implementierung hier
    }
    
    verifyOrigin(clientData) {
        // Implementierung hier - kritisch für Phishing-Schutz!
    }
    
    verifyAttestation(attestationObject) {
        // Implementierung hier
    }
    
    extractPublicKey(attestationObject) {
        // Implementierung hier
    }
}

module.exports = WebAuthnServer;
```

---

## Phase 2: Live Passkey-Registration (30 Minuten)

### Lab 2.1: Frontend-Integration mit echter Hardware (15 Min)

**Aufgabe:** Vervollständigen Sie die Frontend-Implementation und testen Sie mit echten Geräten

```html
<!-- frontend/register.html -->
<!DOCTYPE html>
<html>
<head>
    <title>Passkey Registration - Workshop</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        .demo-container { 
            max-width: 600px; margin: 50px auto; 
            padding: 20px; font-family: Arial, sans-serif; 
        }
        .status { 
            padding: 10px; margin: 10px 0; border-radius: 5px; 
        }
        .success { background: #d4edda; color: #155724; }
        .error { background: #f8d7da; color: #721c24; }
        .info { background: #d1ecf1; color: #0c5460; }
        button { 
            background: #007bff; color: white; 
            border: none; padding: 12px 24px; 
            border-radius: 5px; cursor: pointer; 
            font-size: 16px; margin: 5px;
        }
        button:hover { background: #0056b3; }
        button:disabled { background: #6c757d; cursor: not-allowed; }
    </style>
</head>
<body>
    <div class="demo-container">
        <h1>🔐 Passkey Registration Workshop</h1>
        
        <div id="device-check" class="status info">
            🔍 Checking device capabilities...
        </div>
        
        <div id="registration-form">
            <label for="username">Username:</label>
            <input type="text" id="username" placeholder="your-username" 
                   value="workshop-user-${Date.now()}" />
            
            <div style="margin: 20px 0;">
                <button id="register-platform" disabled>
                    📱 Register with Platform Authenticator (Touch/Face ID)
                </button>
                
                <button id="register-cross-platform" disabled>
                    🔑 Register with Security Key (USB/NFC)
                </button>
            </div>
        </div>
        
        <div id="status-log"></div>
    </div>

    <script src="js/utils.js"></script>
    <script src="js/webauthn-client.js"></script>
    <script>
        // TODO: Device Capability Detection
        async function checkDeviceCapabilities() {
            const statusDiv = document.getElementById('device-check');
            const platformBtn = document.getElementById('register-platform');
            const crossPlatformBtn = document.getElementById('register-cross-platform');
            
            try {
                // WebAuthn-Unterstützung prüfen
                if (!window.PublicKeyCredential) {
                    throw new Error('WebAuthn not supported');
                }
                
                // Platform Authenticator-Verfügbarkeit
                const platformAvailable = await PublicKeyCredential
                    .isUserVerifyingPlatformAuthenticatorAvailable();
                
                statusDiv.innerHTML = `
                    ✅ WebAuthn supported<br>
                    ${platformAvailable ? '✅' : '❌'} Platform Authenticator 
                    (${platformAvailable ? 'Touch/Face ID available' : 'Not available'})<br>
                    ✅ Cross-platform Authenticators supported
                `;
                statusDiv.className = 'status success';
                
                platformBtn.disabled = !platformAvailable;
                crossPlatformBtn.disabled = false;
                
            } catch (error) {
                statusDiv.innerHTML = `❌ WebAuthn not supported: ${error.message}`;
                statusDiv.className = 'status error';
            }
        }
        
        // TODO: Registrierungslogik implementieren
        async function registerPasskey(authenticatorType) {
            const username = document.getElementById('username').value;
            const statusLog = document.getElementById('status-log');
            
            if (!username) {
                statusLog.innerHTML = '<div class="status error">Please enter a username</div>';
                return;
            }
            
            try {
                statusLog.innerHTML = '<div class="status info">🔄 Starting registration...</div>';
                
                const client = new WebAuthnClient();
                
                // TODO: Authenticator-spezifische Optionen
                const options = {
                    authenticatorSelection: {
                        authenticatorAttachment: authenticatorType, // "platform" oder "cross-platform"
                        userVerification: "required",
                        residentKey: "preferred"
                    }
                };
                
                const result = await client.registerPasskey(username, options);
                
                statusLog.innerHTML = `
                    <div class="status success">
                        ✅ Passkey registration successful!<br>
                        <strong>Credential ID:</strong> ${result.credentialId}<br>
                        <strong>Authenticator:</strong> ${authenticatorType}<br>
                        <strong>User Verification:</strong> ${result.userVerification}
                    </div>
                `;
                
                // TODO: Login-Button aktivieren oder zur Login-Seite weiterleiten
                
            } catch (error) {
                console.error('Registration error:', error);
                statusLog.innerHTML = `
                    <div class="status error">
                        ❌ Registration failed: ${error.message}<br>
                        <small>See console for details</small>
                    </div>
                `;
            }
        }
        
        // Event Listeners
        document.addEventListener('DOMContentLoaded', async () => {
            await checkDeviceCapabilities();
            
            document.getElementById('register-platform')
                .addEventListener('click', () => registerPasskey('platform'));
                
            document.getElementById('register-cross-platform')
                .addEventListener('click', () => registerPasskey('cross-platform'));
        });
    </script>
</body>
</html>
```

### Lab 2.2: Multi-Device-Testing (15 Min)

**Aufgabe:** Testen Sie Passkey-Registration auf verschiedenen Geräten

**Test-Szenarien:**
1. **iPhone mit Touch ID/Face ID**
2. **Android mit Fingerprint**
3. **Laptop mit Windows Hello**
4. **Hardware Security Key (falls verfügbar)**

**Testing-Protokoll:**
```javascript
// frontend/js/testing-suite.js
class PasskeyTestSuite {
    constructor() {
        this.testResults = [];
    }
    
    async runDeviceTests() {
        const tests = [
            {
                name: 'Platform Authenticator Detection',
                test: () => PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
            },
            {
                name: 'WebAuthn API Availability',
                test: () => !!window.PublicKeyCredential
            },
            {
                name: 'Conditional UI Support',
                test: async () => {
                    if (!PublicKeyCredential.isConditionalMediationAvailable) return false;
                    return await PublicKeyCredential.isConditionalMediationAvailable();
                }
            },
            {
                name: 'Large Blob Support (CTAP 2.1)',
                test: async () => {
                    // Test für erweiterte Features
                    return this.testLargeBlobSupport();
                }
            }
        ];
        
        console.log('🧪 Running Device Capability Tests...');
        
        for (const testCase of tests) {
            try {
                const result = await testCase.test();
                this.testResults.push({
                    test: testCase.name,
                    passed: !!result,
                    result: result
                });
                console.log(`${result ? '✅' : '❌'} ${testCase.name}: ${result}`);
            } catch (error) {
                this.testResults.push({
                    test: testCase.name,
                    passed: false,
                    error: error.message
                });
                console.log(`❌ ${testCase.name}: ERROR - ${error.message}`);
            }
        }
        
        return this.generateTestReport();
    }
    
    generateTestReport() {
        const passed = this.testResults.filter(r => r.passed).length;
        const total = this.testResults.length;
        
        return {
            summary: `${passed}/${total} tests passed`,
            details: this.testResults,
            recommendations: this.generateRecommendations()
        };
    }
    
    generateRecommendations() {
        const recommendations = [];
        
        if (!this.testResults.find(r => r.test.includes('Platform')).passed) {
            recommendations.push('Consider using hardware security keys for better compatibility');
        }
        
        if (!this.testResults.find(r => r.test.includes('Conditional')).passed) {
            recommendations.push('Conditional UI not supported - use explicit authentication flows');
        }
        
        return recommendations;
    }
}

// Test automatisch beim Laden ausführen
document.addEventListener('DOMContentLoaded', async () => {
    const testSuite = new PasskeyTestSuite();
    const report = await testSuite.runDeviceTests();
    
    // Test-Ergebnisse in UI anzeigen
    const testResultsDiv = document.createElement('div');
    testResultsDiv.innerHTML = `
        <h3>Device Test Results</h3>
        <p><strong>${report.summary}</strong></p>
        <details>
            <summary>Detailed Results</summary>
            <pre>${JSON.stringify(report.details, null, 2)}</pre>
        </details>
    `;
    document.body.appendChild(testResultsDiv);
});
```

---

## Phase 3: Passkey-Authentication implementieren (25 Minuten)

### Lab 3.1: Login-Flow mit Passkey (15 Min)

**Aufgabe:** Implementieren Sie die Authentifizierung mit bereits registrierten Passkeys

```javascript
// frontend/js/webauthn-client.js - Authentication erweitern
class WebAuthnClient {
    // ... vorherige Methoden ...
    
    // TODO: Passkey-Authentication implementieren
    async authenticateWithPasskey(username) {
        try {
            // 1. Challenge für Authentication anfordern
            const challengeData = await this.requestChallenge(username, 'authenticate');
            
            // 2. Credential IDs für User abrufen
            const userCredentials = await this.getUserCredentials(username);
            
            // 3. WebAuthn Authentication Options
            const publicKeyCredentialRequestOptions = {
                challenge: challengeData.challenge,
                allowCredentials: userCredentials.map(cred => ({
                    id: this.base64urlToArrayBuffer(cred.credentialId),
                    type: 'public-key',
                    transports: cred.transports || ['internal', 'usb', 'nfc', 'ble']
                })),
                userVerification: 'required',
                timeout: 60000
            };
            
            console.log('🔍 Starting authentication with options:', publicKeyCredentialRequestOptions);
            
            // 4. WebAuthn Authentication
            const assertion = await navigator.credentials.get({
                publicKey: publicKeyCredentialRequestOptions
            });
            
            console.log('✅ Assertion received:', assertion);
            
            // 5. Assertion an Server zur Verifikation senden
            return await this.verifyAssertion(assertion, challengeData.challengeId);
            
        } catch (error) {
            console.error('❌ Authentication failed:', error);
            throw error;
        }
    }
    
    // TODO: Conditional UI für passwordlose Anmeldung
    async enableConditionalUI() {
        if (!PublicKeyCredential.isConditionalMediationAvailable) {
            console.log('ℹ️ Conditional UI not supported');
            return false;
        }
        
        const supported = await PublicKeyCredential.isConditionalMediationAvailable();
        if (!supported) {
            console.log('ℹ️ Conditional UI not available on this device');
            return false;
        }
        
        try {
            // Conditional UI für automatische Passkey-Vorschläge
            const assertion = await navigator.credentials.get({
                publicKey: {
                    challenge: new Uint8Array(32), // Dummy challenge
                    userVerification: 'required'
                },
                mediation: 'conditional' // Magic für Conditional UI!
            });
            
            console.log('🎯 Conditional UI authentication successful');
            return assertion;
            
        } catch (error) {
            console.log('ℹ️ Conditional UI authentication cancelled or failed');
            return false;
        }
    }
    
    // Hilfsmethoden
    async getUserCredentials(username) {
        const response = await fetch(`${this.baseURL}/api/user/${username}/credentials`);
        return await response.json();
    }
    
    async verifyAssertion(assertion, challengeId) {
        const response = await fetch(`${this.baseURL}/api/auth/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                challengeId: challengeId,
                credentialId: assertion.id,
                authenticatorData: this.arrayBufferToBase64url(assertion.response.authenticatorData),
                clientDataJSON: this.arrayBufferToBase64url(assertion.response.clientDataJSON),
                signature: this.arrayBufferToBase64url(assertion.response.signature),
                userHandle: assertion.response.userHandle ? 
                    this.arrayBufferToBase64url(assertion.response.userHandle) : null
            })
        });
        
        return await response.json();
    }
}
```

### Lab 3.2: Server-Side Authentication-Verifikation (10 Min)

**Aufgabe:** Komplette Server-seitige Assertion-Verifikation

```javascript
// backend/utils/webauthn-server.js - Authentication erweitern
class WebAuthnServer {
    // ... vorherige Methoden ...
    
    // TODO: Authentication-Verifikation
    async verifyAuthentication(challengeId, assertionData) {
        const challengeInfo = this.challenges.get(challengeId);
        if (!challengeInfo || challengeInfo.used) {
            throw new Error('Invalid or expired challenge');
        }
        
        challengeInfo.used = true;
        
        // User und Credential laden
        const user = this.users.get(challengeInfo.username);
        if (!user) {
            throw new Error('User not found');
        }
        
        const credential = user.credentials.find(
            c => c.credentialId === assertionData.credentialId
        );
        if (!credential) {
            throw new Error('Credential not found');
        }
        
        // TODO: Assertion-Verifikation durchführen
        const verificationSteps = [
            // 1. Client Data Verifikation
            () => this.verifyClientDataJSON(
                assertionData.clientDataJSON, 
                challengeInfo.challenge,
                'webauthn.get'
            ),
            
            // 2. Authenticator Data Parsing
            () => this.parseAuthenticatorData(assertionData.authenticatorData),
            
            // 3. Signature-Verifikation
            (authData) => this.verifySignature(
                credential.publicKey,
                authData,
                assertionData.clientDataJSON,
                assertionData.signature
            ),
            
            // 4. Counter-Verifikation (Clone Detection)
            (authData) => this.verifyCounter(credential, authData.counter),
            
            // 5. User Verification Check
            (authData) => this.verifyUserPresence(authData)
        ];
        
        let authData;
        for (const [index, step] of verificationSteps.entries()) {
            try {
                const result = await step(authData);
                if (index === 1) authData = result; // AuthenticatorData speichern
                console.log(`✅ Auth verification step ${index + 1} passed`);
            } catch (error) {
                console.error(`❌ Auth verification step ${index + 1} failed:`, error);
                throw new Error(`Authentication verification failed at step ${index + 1}: ${error.message}`);
            }
        }
        
        // Counter aktualisieren (Clone Detection)
        credential.counter = authData.counter;
        credential.lastUsed = new Date();
        
        // Erfolgreiche Authentifizierung
        return {
            authenticated: true,
            username: challengeInfo.username,
            credentialId: assertionData.credentialId,
            counter: authData.counter,
            userVerified: authData.userVerified,
            timestamp: new Date()
        };
    }
    
    // TODO: Signature-Verifikation implementieren
    verifySignature(publicKey, authenticatorData, clientDataJSON, signature) {
        const crypto = require('crypto');
        
        // Signed data = authenticatorData + hash(clientDataJSON)
        const clientDataHash = crypto
            .createHash('sha256')
            .update(Buffer.from(clientDataJSON, 'base64url'))
            .digest();
            
        const signedData = Buffer.concat([
            Buffer.from(authenticatorData, 'base64url'),
            clientDataHash
        ]);
        
        // Public Key für Verifikation verwenden
        const verify = crypto.createVerify('SHA256');
        verify.update(signedData);
        
        const isValid = verify.verify(publicKey, Buffer.from(signature, 'base64url'));
        
        if (!isValid) {
            throw new Error('Invalid signature');
        }
        
        return true;
    }
    
    // TODO: Counter-basierte Clone Detection
    verifyCounter(credential, newCounter) {
        if (newCounter <= credential.counter) {
            // Mögliche Token-Klonierung!
            console.warn(`⚠️  Potential cloning detected: counter ${newCounter} <= ${credential.counter}`);
            throw new Error('Potential authenticator cloning detected');
        }
        return true;
    }
}
```

---

## Phase 4: Security-Tests & Phishing-Resistenz (25 Minuten)

### Lab 4.1: Phishing-Resistenz-Demo (15 Min)

**Aufgabe:** Praktische Demonstration der Phishing-Resistenz von Passkeys

**Setup:** Zwei Domains für Phishing-Simulation
- **Legitimate:** `https://localhost:3000` (echte App)
- **Phishing:** `https://localhost:3001` (Phishing-Simulation)

```javascript
// tests/security-tests.js
class PhishingResistanceTest {
    constructor() {
        this.legitimateDomain = 'localhost:3000';
        this.phishingDomain = 'localhost:3001';
    }
    
    async runPhishingTest() {
        console.log('🎣 Starting Phishing Resistance Test');
        
        // Test 1: Legitimate Domain
        await this.testLegitimateAuthentication();
        
        // Test 2: Phishing Domain
        await this.testPhishingAttempt();
        
        // Test 3: Origin Spoofing
        await this.testOriginSpoofing();
        
        console.log('✅ Phishing resistance test completed');
    }
    
    async testLegitimateAuthentication() {
        console.log('📋 Test 1: Legitimate Authentication');
        
        try {
            // Normale Passkey-Authentifizierung auf echter Domain
            const client = new WebAuthnClient();
            const result = await client.authenticateWithPasskey('test-user');
            
            console.log('✅ Legitimate authentication succeeded (expected)');
            return true;
            
        } catch (error) {
            console.error('❌ Legitimate authentication failed (unexpected):', error);
            return false;
        }
    }
    
    async testPhishingAttempt() {
        console.log('🎣 Test 2: Phishing Domain Attempt');
        
        // Simuliere Phishing-Angriff durch Domain-Wechsel
        const originalOrigin = window.location.origin;
        
        try {
            // In echter Umgebung: Benutzer besucht examp1e.com statt example.com
            const phishingClient = new WebAuthnClient(`https://${this.phishingDomain}`);
            
            // Dieser Aufruf sollte scheitern wegen Origin-Mismatch
            await phishingClient.authenticateWithPasskey('test-user');
            
            console.error('❌ Phishing attempt succeeded (SECURITY BUG!)');
            return false;
            
        } catch (error) {
            if (error.message.includes('origin') || error.name === 'NotAllowedError') {
                console.log('✅ Phishing attempt blocked (expected):', error.message);
                return true;
            } else {
                console.error('❌ Unexpected error in phishing test:', error);
                return false;
            }
        }
    }
    
    async testOriginSpoofing() {
        console.log('🎭 Test 3: Origin Spoofing Attempt');
        
        try {
            // Versuche Client Data JSON zu manipulieren
            const challengeData = await this.requestPhishingChallenge();
            
            // Manipulierte Client Data (in der Realität nicht möglich!)
            const fakeClientData = {
                type: "webauthn.get",
                challenge: challengeData.challenge,
                origin: this.legitimateDomain, // Gefälscht!
                crossOrigin: false
            };
            
            // Browser verhindert automatisch diese Manipulation
            const assertion = await navigator.credentials.get({
                publicKey: {
                    challenge: challengeData.challenge,
                    allowCredentials: [{
                        id: new Uint8Array(32), // Dummy
                        type: 'public-key'
                    }],
                    userVerification: 'required'
                }
            });
            
            // Wenn wir bis hier kommen, ist etwas schiefgelaufen
            console.error('❌ Origin spoofing succeeded (CRITICAL SECURITY BUG!)');
            return false;
            
        } catch (error) {
            console.log('✅ Origin spoofing blocked by browser (expected):', error.message);
            return true;
        }
    }
    
    // Live-Demo für Teilnehmende
    async liveDemoPhishingResistance() {
        const demoDiv = document.createElement('div');
        demoDiv.innerHTML = `
            <h3>🛡️ Live Phishing Resistance Demo</h3>
            <p>This demo shows why passkeys cannot be phished:</p>
            
            <div>
                <h4>Step 1: Normal Authentication (should work)</h4>
                <button id="normal-auth">Authenticate on ${this.legitimateDomain}</button>
                <div id="normal-result"></div>
            </div>
            
            <div>
                <h4>Step 2: Phishing Attempt (should fail)</h4>
                <button id="phishing-auth">Try to use passkey on fake domain</button>
                <div id="phishing-result"></div>
            </div>
            
            <div id="demo-results"></div>
        `;
        
        document.body.appendChild(demoDiv);
        
        // Event Handlers für Live-Demo
        document.getElementById('normal-auth').onclick = async () => {
            const resultDiv = document.getElementById('normal-result');
            try {
                const client = new WebAuthnClient();
                await client.authenticateWithPasskey('demo-user');
                resultDiv.innerHTML = '<div class="status success">✅ Authentication succeeded (expected)</div>';
            } catch (error) {
                resultDiv.innerHTML = `<div class="status error">❌ Authentication failed: ${error.message}</div>`;
            }
        };
        
        document.getElementById('phishing-auth').onclick = async () => {
            const resultDiv = document.getElementById('phishing-result');
            resultDiv.innerHTML = '<div class="status info">🔄 Attempting phishing attack...</div>';
            
            setTimeout(() => {
                // Simuliere automatisches Scheitern
                resultDiv.innerHTML = `
                    <div class="status success">
                        ✅ Phishing attack automatically blocked!<br>
                        <small>Passkey refused to work because domain doesn't match registration.</small>
                    </div>
                `;
            }, 2000);
        };
    }
}
```

### Lab 4.2: Cross-Device-Authentication testen (10 Min)

**Aufgabe:** Teste Cross-Device-Authentifizierung mit QR-Codes und Bluetooth

```javascript
// tests/cross-platform-tests.js
class CrossDeviceAuthenticationTest {
    
    async testCrossDeviceFlow() {
        console.log('📱 Testing Cross-Device Authentication');
        
        // Test 1: QR Code Generation
        const qrAuth = await this.generateQRCodeAuth();
        console.log('✅ QR Code authentication flow generated');
        
        // Test 2: Bluetooth Low Energy Detection
        if (navigator.bluetooth) {
            const bleTest = await this.testBluetoothDiscovery();
            console.log(`${bleTest ? '✅' : '❌'} Bluetooth LE support: ${bleTest}`);
        }
        
        // Test 3: Cross-Platform Authenticator
        const crossPlatformTest = await this.testCrossPlatformAuthenticator();
        console.log(`${crossPlatformTest ? '✅' : '❌'} Cross-platform authenticator: ${crossPlatformTest}`);
    }
    
    async generateQRCodeAuth() {
        const sessionId = crypto.randomUUID();
        const challenge = crypto.getRandomValues(new Uint8Array(32));
        
        // QR Code für Mobile Authentication
        const qrData = {
            type: 'webauthn-cross-device',
            url: `${window.location.origin}/auth/cross-device/${sessionId}`,
            challenge: Array.from(challenge),
            rpId: window.location.hostname
        };
        
        // QR Code generieren (in echter App: QR-Code-Bibliothek verwenden)
        const qrCodeDiv = document.createElement('div');
        qrCodeDiv.innerHTML = `
            <h4>📱 Cross-Device Authentication</h4>
            <div style="border: 2px solid #ccc; padding: 20px; text-align: center; margin: 10px 0;">
                <p>QR CODE PLACEHOLDER</p>
                <small>In production: Use QR code library to display actual QR code</small>
                <br><br>
                <code style="word-break: break-all;">${JSON.stringify(qrData, null, 2)}</code>
            </div>
            <p><strong>Instructions:</strong></p>
            <ol>
                <li>Open your phone's camera or passkey app</li>
                <li>Scan this QR code</li>
                <li>Use your phone's biometric authentication</li>
                <li>Authentication will complete on this device</li>
            </ol>
        `;
        
        document.body.appendChild(qrCodeDiv);
        
        return qrData;
    }
    
    async testBluetoothDiscovery() {
        if (!navigator.bluetooth) {
            console.log('ℹ️ Bluetooth not supported in this browser');
            return false;
        }
        
        try {
            // Test Bluetooth LE für FIDO Authenticators
            const device = await navigator.bluetooth.requestDevice({
                filters: [{ services: ['f1d0'] }], // FIDO service UUID
                optionalServices: ['battery_service']
            });
            
            console.log('✅ Bluetooth FIDO device found:', device.name);
            return true;
            
        } catch (error) {
            console.log('ℹ️ Bluetooth discovery cancelled or failed:', error.message);
            return false;
        }
    }
    
    async testCrossPlatformAuthenticator() {
        try {
            const credential = await navigator.credentials.create({
                publicKey: {
                    challenge: crypto.getRandomValues(new Uint8Array(32)),
                    rp: { name: "Cross-Platform Test", id: window.location.hostname },
                    user: { 
                        id: new Uint8Array(16), 
                        name: "cross-platform-test", 
                        displayName: "Cross Platform Test" 
                    },
                    pubKeyCredParams: [{ alg: -7, type: "public-key" }],
                    authenticatorSelection: {
                        authenticatorAttachment: "cross-platform", // Wichtig!
                        userVerification: "preferred"
                    },
                    timeout: 10000 // Kurzes Timeout für Test
                }
            });
            
            return true;
            
        } catch (error) {
            if (error.name === 'AbortError' || error.name === 'NotAllowedError') {
                console.log('ℹ️ Cross-platform test cancelled or not available');
                return false;
            }
            throw error;
        }
    }
}
```

---

## Phase 5: Enterprise-Szenarien & Account Recovery (20 Minuten)

### Lab 5.1: Multi-Passkey-Management (10 Min)

**Aufgabe:** Implementieren Sie Enterprise-Grade Passkey-Management

```javascript
// frontend/js/enterprise-passkey-manager.js
class EnterprisePasskeyManager extends WebAuthnClient {
    constructor(baseURL, policies = {}) {
        super(baseURL);
        this.policies = {
            maxPasskeysPerUser: 5,
            requireDeviceBound: false,
            attestationRequired: false,
            backupRequired: true,
            ...policies
        };
    }
    
    // TODO: Passkey-Inventar für Benutzer
    async getPasskeyInventory(username) {
        const response = await fetch(`${this.baseURL}/api/user/${username}/passkeys`);
        const passkeys = await response.json();
        
        return passkeys.map(pk => ({
            credentialId: pk.credentialId,
            friendlyName: pk.friendlyName || 'Unnamed Device',
            createdAt: new Date(pk.createdAt),
            lastUsed: pk.lastUsed ? new Date(pk.lastUsed) : null,
            authenticatorType: pk.authenticatorAttachment || 'unknown',
            counter: pk.counter,
            isBackup: pk.backup || false,
            attestation: pk.attestation
        }));
    }
    
    // TODO: Passkey-Registrierung mit Enterprise-Policies
    async registerEnterprisePasskey(username, options = {}) {
        const inventory = await this.getPasskeyInventory(username);
        
        // Policy-Checks
        if (inventory.length >= this.policies.maxPasskeysPerUser) {
            throw new Error(`Maximum ${this.policies.maxPasskeysPerUser} passkeys per user exceeded`);
        }
        
        if (this.policies.requireDeviceBound && options.authenticatorAttachment !== 'platform') {
            throw new Error('Device-bound passkeys required by policy');
        }
        
        // Enterprise-spezifische Optionen
        const enterpriseOptions = {
            ...options,
            attestation: this.policies.attestationRequired ? 'direct' : 'none',
            authenticatorSelection: {
                ...options.authenticatorSelection,
                residentKey: 'required', // Für Enterprise immer required
                userVerification: 'required'
            }
        };
        
        const result = await this.registerPasskey(username, enterpriseOptions);
        
        // Friendly Name setzen
        if (options.friendlyName) {
            await this.setPasskeyFriendlyName(result.credentialId, options.friendlyName);
        }
        
        return result;
    }
    
    // TODO: Backup-Passkey-System
    async createBackupPasskey(username) {
        console.log('🔄 Creating backup passkey...');
        
        const backupOptions = {
            friendlyName: `Backup Key ${new Date().toISOString().split('T')[0]}`,
            authenticatorSelection: {
                authenticatorAttachment: 'cross-platform', // Hardware-Token für Backup
                userVerification: 'required'
            },
            isBackup: true
        };
        
        return await this.registerEnterprisePasskey(username, backupOptions);
    }
    
    // TODO: Passkey-Recovery-Flow
    async initiatePasskeyRecovery(username, adminApproval = false) {
        const recoveryMethods = [];
        
        // Method 1: Backup Passkey
        const inventory = await this.getPasskeyInventory(username);
        const backupPasskeys = inventory.filter(pk => pk.isBackup);
        
        if (backupPasskeys.length > 0) {
            recoveryMethods.push({
                type: 'backup_passkey',
                available: true,
                description: `Use one of ${backupPasskeys.length} backup passkeys`
            });
        }
        
        // Method 2: Admin Override (Enterprise)
        if (adminApproval) {
            recoveryMethods.push({
                type: 'admin_override',
                available: true,
                description: 'Administrator can reset passkeys',
                requiredApprovals: 2 // Dual control
            });
        }
        
        // Method 3: Recovery Codes
        const recoveryCodes = await this.getRecoveryCodes(username);
        if (recoveryCodes && recoveryCodes.length > 0) {
            recoveryMethods.push({
                type: 'recovery_codes',
                available: true,
                description: `${recoveryCodes.length} recovery codes available`
            });
        }
        
        return {
            username: username,
            recoveryMethods: recoveryMethods,
            timestamp: new Date(),
            sessionId: crypto.randomUUID()
        };
    }
}

// Demo für Enterprise-Funktionen
async function demoEnterpriseFeatures() {
    const enterpriseManager = new EnterprisePasskeyManager('https://localhost:3000', {
        maxPasskeysPerUser: 3,
        requireDeviceBound: false,
        attestationRequired: true,
        backupRequired: true
    });
    
    const username = 'enterprise-demo-user';
    
    try {
        // 1. Passkey-Inventar anzeigen
        console.log('📋 Current passkey inventory:');
        const inventory = await enterpriseManager.getPasskeyInventory(username);
        console.table(inventory);
        
        // 2. Neuen Passkey mit Policy-Checks erstellen
        console.log('🔐 Creating new enterprise passkey...');
        const newPasskey = await enterpriseManager.registerEnterprisePasskey(username, {
            friendlyName: 'Workshop Laptop',
            authenticatorAttachment: 'platform'
        });
        console.log('✅ Enterprise passkey created:', newPasskey);
        
        // 3. Backup-Passkey erstellen
        console.log('💾 Creating backup passkey...');
        const backupPasskey = await enterpriseManager.createBackupPasskey(username);
        console.log('✅ Backup passkey created:', backupPasskey);
        
        // 4. Recovery-Optionen anzeigen
        console.log('🔧 Available recovery methods:');
        const recovery = await enterpriseManager.initiatePasskeyRecovery(username, true);
        console.log(recovery);
        
    } catch (error) {
        console.error('❌ Enterprise demo failed:', error);
    }
}
```

### Lab 5.2: Account Recovery Workshop (10 Min)

**Aufgabe:** Implementieren Sie robuste Account-Recovery-Mechanismen

```javascript
// frontend/js/recovery-manager.js
class PasskeyRecoveryManager {
    constructor(baseURL) {
        this.baseURL = baseURL;
    }
    
    // TODO: Recovery-Strategien implementieren
    async createRecoveryStrategy(username) {
        const strategies = [
            {
                id: 'multiple_passkeys',
                name: 'Multiple Passkeys',
                description: 'Register passkeys on multiple devices',
                implementation: () => this.setupMultiplePasskeys(username),
                priority: 1,
                userFriendly: true
            },
            {
                id: 'recovery_codes',
                name: 'Recovery Codes',
                description: 'One-time backup codes',
                implementation: () => this.generateRecoveryCodes(username),
                priority: 2,
                userFriendly: true
            },
            {
                id: 'trusted_contacts',
                name: 'Trusted Contacts',
                description: 'Social recovery via trusted friends/colleagues',
                implementation: () => this.setupTrustedContacts(username),
                priority: 3,
                userFriendly: true
            },
            {
                id: 'enterprise_escrow',
                name: 'Enterprise Key Escrow',
                description: 'IT department backup for enterprise users',
                implementation: () => this.setupEnterpriseEscrow(username),
                priority: 4,
                userFriendly: false
            }
        ];
        
        return strategies;
    }
    
    async setupMultiplePasskeys(username) {
        const setupUI = document.createElement('div');
        setupUI.innerHTML = `
            <div class="recovery-setup">
                <h3>📱 Multiple Device Setup</h3>
                <p>Register your passkey on multiple devices for redundancy:</p>
                
                <div class="device-checklist">
                    <label><input type="checkbox" id="primary-phone"> Primary Smartphone</label><br>
                    <label><input type="checkbox" id="backup-phone"> Backup Smartphone</label><br>
                    <label><input type="checkbox" id="laptop"> Work/Personal Laptop</label><br>
                    <label><input type="checkbox" id="tablet"> Tablet</label><br>
                    <label><input type="checkbox" id="hardware-key"> Hardware Security Key</label><br>
                </div>
                
                <button id="register-device">Register Current Device</button>
                <button id="generate-qr">Generate QR for Mobile</button>
                
                <div id="device-status"></div>
            </div>
        `;
        
        document.body.appendChild(setupUI);
        
        // Event Handlers
        setupUI.querySelector('#register-device').onclick = async () => {
            try {
                const client = new WebAuthnClient();
                await client.registerPasskey(username, {
                    friendlyName: this.detectDeviceType()
                });
                this.updateDeviceStatus('✅ Device registered successfully');
            } catch (error) {
                this.updateDeviceStatus(`❌ Registration failed: ${error.message}`);
            }
        };
        
        setupUI.querySelector('#generate-qr').onclick = () => {
            this.generateCrossDeviceQR(username);
        };
    }
    
    async generateRecoveryCodes(username) {
        // Generiere kryptographisch sichere Recovery-Codes
        const codes = [];
        for (let i = 0; i < 10; i++) {
            const code = crypto.getRandomValues(new Uint32Array(2))
                .reduce((acc, val) => acc + val.toString(36), '').substring(0, 8);
            codes.push(code.toUpperCase());
        }
        
        // Codes an Server senden (gehasht speichern!)
        await fetch(`${this.baseURL}/api/user/${username}/recovery-codes`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ codes: codes })
        });
        
        // UI für Code-Anzeige
        const codesUI = document.createElement('div');
        codesUI.innerHTML = `
            <div class="recovery-codes">
                <h3>🔑 Recovery Codes</h3>
                <p><strong>⚠️ Important:</strong> Save these codes securely. Each can only be used once.</p>
                
                <div class="codes-grid" style="font-family: monospace; display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                    ${codes.map((code, i) => `<div>${i + 1}. ${code}</div>`).join('')}
                </div>
                
                <div style="margin: 20px 0;">
                    <button id="download-codes">📥 Download as File</button>
                    <button id="print-codes">🖨️ Print Codes</button>
                    <button id="confirm-saved">✅ I have saved these codes</button>
                </div>
                
                <div class="warning" style="background: #fff3cd; padding: 10px; border-radius: 5px;">
                    <strong>Security Tips:</strong>
                    <ul>
                        <li>Store in password manager</li>
                        <li>Keep physical copy in safe location</li>
                        <li>Never share or store unencrypted online</li>
                    </ul>
                </div>
            </div>
        `;
        
        document.body.appendChild(codesUI);
        
        // Download-Funktionalität
        codesUI.querySelector('#download-codes').onclick = () => {
            const blob = new Blob([
                `Passkey Recovery Codes for ${username}\n`,
                `Generated: ${new Date().toISOString()}\n\n`,
                ...codes.map((code, i) => `${i + 1}. ${code}\n`)
            ], { type: 'text/plain' });
            
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `passkey-recovery-codes-${username}.txt`;
            a.click();
            URL.revokeObjectURL(url);
        };
        
        return codes;
    }
    
    // TODO: Social Recovery Implementation
    async setupTrustedContacts(username) {
        const trustedContactsUI = document.createElement('div');
        trustedContactsUI.innerHTML = `
            <div class="trusted-contacts">
                <h3>👥 Trusted Contacts</h3>
                <p>Select trusted colleagues who can help verify your identity:</p>
                
                <form id="trusted-contacts-form">
                    <div class="contact-input">
                        <label>Contact 1 Email:</label>
                        <input type="email" name="contact1" required>
                    </div>
                    <div class="contact-input">
                        <label>Contact 2 Email:</label>
                        <input type="email" name="contact2" required>
                    </div>
                    <div class="contact-input">
                        <label>Contact 3 Email:</label>
                        <input type="email" name="contact3" required>
                    </div>
                    
                    <button type="submit">Send Verification Requests</button>
                </form>
                
                <div class="social-recovery-info">
                    <h4>How Social Recovery Works:</h4>
                    <ol>
                        <li>If you lose access, request social recovery</li>
                        <li>System emails your trusted contacts</li>
                        <li>2 of 3 contacts must verify your identity</li>
                        <li>Time-delayed recovery (24h) for security</li>
                    </ol>
                </div>
            </div>
        `;
        
        document.body.appendChild(trustedContactsUI);
        
        trustedContactsUI.querySelector('#trusted-contacts-form').onsubmit = async (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            const contacts = [
                formData.get('contact1'),
                formData.get('contact2'),
                formData.get('contact3')
            ].filter(email => email);
            
            try {
                await fetch(`${this.baseURL}/api/user/${username}/trusted-contacts`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ contacts })
                });
                
                alert('✅ Trusted contacts configured successfully!');
            } catch (error) {
                alert(`❌ Failed to setup trusted contacts: ${error.message}`);
            }
        };
    }
    
    // Hilfsmethoden
    detectDeviceType() {
        const ua = navigator.userAgent;
        if (/iPhone|iPad/.test(ua)) return 'iOS Device';
        if (/Android/.test(ua)) return 'Android Device';
        if (/Windows/.test(ua)) return 'Windows PC';
        if (/Mac/.test(ua)) return 'Mac Computer';
        return 'Unknown Device';
    }
    
    updateDeviceStatus(message) {
        const statusDiv = document.getElementById('device-status');
        if (statusDiv) statusDiv.innerHTML = `<div class="status">${message}</div>`;
    }
}
```

---

## Wrap-Up & Reflexion (15 Minuten)

### Demo-Präsentationen (10 Min)

**Jede Gruppe präsentiert (2-3 Minuten):**
1. **Was haben Sie implementiert?** Demo der funktionierenden Passkey-Authentifizierung
2. **Welche Herausforderungen sind aufgetreten?** Technische Probleme und Lösungen
3. **Security-Erkenntnisse:** Was haben Sie über Passkey-Sicherheit gelernt?
4. **Enterprise-Readiness:** Wie würden Sie Passkeys in einem Unternehmen einführen?

### Lessons Learned Sammlung (5 Min)

**Gemeinsame Erkenntnisse:**
- **Hardware-Abhängigkeit:** Passkeys funktionieren nur mit moderner Hardware
- **UX-Komplexität:** Account Recovery ist schwieriger als gedacht
- **Phishing-Resistenz:** Automatischer Schutz funktioniert tatsächlich
- **Cross-Platform-Herausforderungen:** Ökosystem-Lock-in ist real

**Technische Insights:**
- **WebAuthn API:** Komplex, aber mächtig
- **Browser-Unterstützung:** Sehr gut, aber kleine Unterschiede
- **HTTPS-Requirement:** Absolute Notwendigkeit für alle Passkey-Features
- **Error Handling:** Sehr wichtig für gute User Experience

### Praktische Take-Aways

**Für Entwickler:**
1. **Starten Sie mit einfachen Implementierungen** - WebAuthn ist komplex
2. **Testen Sie auf echten Geräten** - Simulator reichen nicht
3. **Planen Sie Account Recovery von Anfang an** - nicht als Nachgedanke
4. **Implementieren Sie graceful degradation** - nicht alle Nutzer haben moderne Geräte

**Für Unternehmen:**
1. **Pilot-Programme mit Tech-Savvy-Nutzern** starten
2. **Mehrere Backup-Strategien** parallel implementieren
3. **Change Management** ist genauso wichtig wie die Technik
4. **Vendor Lock-in** bei der Technologie-Auswahl berücksichtigen

### Advanced Challenges (Bonus)

**Für schnelle Gruppen - Take-Home-Projekte:**

1. **Post-Quantum-Passkeys:** Implementieren Sie hybrid classical/PQ-Kryptographie
2. **Biometric Template Protection:** Erforschen Sie biometrische Datenschutz-Techniken
3. **Decentralized Identity:** Kombinieren Sie Passkeys mit Self-Sovereign Identity
4. **IoT-Integration:** Passkeys für IoT-Device-Authentifizierung

### Code-Repository & Resources

**Workshop-Code verfügbar unter:**
```
https://github.com/passkey-workshop/complete-implementation
├── completed-solutions/     # Vollständige Lösungen aller Labs
├── security-tests/         # Erweiterte Security-Tests
├── enterprise-extensions/  # Enterprise-Features
└── troubleshooting/       # Häufige Probleme & Lösungen
```

**Weiterführende Ressourcen:**
- **FIDO Alliance Developer Resources:** https://developers.yubico.com/WebAuthn/
- **WebAuthn Guide:** https://webauthn.guide/
- **Apple Passkeys Documentation:** https://developer.apple.com/passkeys/
- **Google Identity Documentation:** https://developers.google.com/identity/passkeys
- **Microsoft WebAuthn Documentation:** https://docs.microsoft.com/en-us/microsoft-edge/web-platform/passkeys

### Evaluation & Feedback

**Post-Workshop-Umfrage:**
1. **Technisches Verständnis:** Wie gut verstehen Sie jetzt Passkeys? (1-10)
2. **Implementation Confidence:** Trauen Sie sich zu, Passkeys zu implementieren? (1-10)
3. **Security Awareness:** Wie hat sich Ihr Verständnis für Phishing-Resistenz geändert?
4. **Enterprise Readiness:** Würden Sie Passkeys in Ihrem Unternehmen empfehlen?

**Follow-Up:**
- **Code-Review-Session** nach 1 Woche für weitere Fragen
- **Enterprise-Implementation-Workshop** als Fortsetzung
- **Community-Channel** für kontinuierlichen Austausch

---

**Dieser Workshop macht Passkeys von abstrakten Standards zu greifbarer, implementierbarer Technologie und vermittelt ein tiefes Verständnis für sowohl die technischen Möglichkeiten als auch die praktischen Herausforderungen der passwordlosen Zukunft!**