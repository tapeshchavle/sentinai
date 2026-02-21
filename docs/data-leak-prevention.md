# 🔒 Data Leak Prevention

**Scans API responses for sensitive data before it ever reaches the client.**

---

## 🛑 The Problem: What Existed Before
It happens to the best of us: a developer is rushing, and instead of taking the time to map a Database Entity to a clean Data Transfer Object (DTO), they just return the entire Entity object directly from the Controller.

Suddenly, a simple `GET /api/users/{id}` endpoint that was only supposed to return a name and email is returning this:

```json
{
  "id": 5,
  "name": "John Doe",
  "email": "john@company.com",
  "password_hash": "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
  "ssn": "123-45-6789",
  "internal_api_key": "sk-1234567890abcdef"
}
```

**Here's the problem:**
Standard Web Application Firewalls (WAFs) are almost entirely focused on *inbound* traffic. They rarely scan outbound JSON payloads. Even if they do, adding a heavy regex engine at the CDN/gateway level often adds unacceptable latency to every single API response. Therefore, these leaks often go completely undetected until a security researcher (or a malicious actor) points them out.

## 💡 The Solution: Data Leak Prevention (DLP)
The Data Leak Prevention module sits right at the exit door of your Spring Boot application. 

Because it's running inside the application, it has direct access to the raw response object before it gets serialized over the network. It quickly scans the outgoing payload against a battery of highly optimized regular expressions, and if it finds a match, it can either silently redact the data or outright block the response from leaving the server.

---

## 🏗️ How It Works (Architecture)

The DLP module acts as a final checkpoint. When your Controller finishes its work and returns a JSON payload, the SentinAI Security Filter intercepts it.

```mermaid
sequenceDiagram
    participant Client
    participant Filter as SentinAI Filter
    participant Controller as Spring Controller
    participant DB as Database
    participant DLP as DLP Module

    Client->>Filter: GET /api/users/5
    Filter->>Controller: Forward Request
    Controller->>DB: Fetch User Entity
    DB-->>Controller: Returns Full User Object
    
    %% The Developer Mistake
    note over Controller,DLP: Developer forgets DTO, returns full entity.
    Controller-->>Filter: Response Payload (Includes SSN & Hash)
    
    %% The SentinAI Checkpoint
    Filter->>DLP: Analyze Outbound Payload
    
    alt Mode: REDACT
        DLP-->>Filter: Modify Payload (Replace SSN with [REDACTED])
        Filter-->>Client: 200 OK (Cleaned JSON)
    else Mode: BLOCK
        DLP-->>Filter: Drop Payload
        Filter-->>Client: 500 Internal Error (Data Leak Blocked)
    else Mode: LOG (Default)
        DLP-->>Filter: Log Warning Only, keep payload
        Filter-->>Client: 200 OK (Original Leaky JSON)
    end
```

---

## 🔎 Built-in Detectors

The module comes loaded with 11 native detectors that are optimized for speed.

| Detector | What It Looks For | Validation Layer |
|:---|:---|:---|
| **Credit Card** | `4XXX-XXXX...` (Visa, MC, Amex) | ✅ Double-checked against the Luhn algorithm to prevent false positives on random 16-digit IDs. |
| **SSN (US)** | `XXX-XX-XXXX` | Strict format matching |
| **Aadhaar (IN)** | `XXXX XXXX XXXX` | Strict format matching |
| **Bcrypt Hash** | `$2a$10$...` | Prefix matching |
| **Argon2 Hash** | `$argon2id$...`| Prefix matching |
| **OpenAI API Key** | `sk-XXXX...` | Prefix + length boundaries |
| **AWS Access Key** | `AKIAXXXXXXXX` | Prefix + length boundaries |
| **GitHub Token** | `ghp_XXXX...` | Prefix + length boundaries |
| **JWT Token** | `eyJhbG...` | Three-segment base64 encoding |
| **Private Key** | `-----BEGIN PRIVATE KEY-----` | Header signature matching |

---

## 📦 Independent Installation

If you prefer a lightweight footprint and don't want the full starter, you can pull in just the DLP module:

```xml
<dependency>
    <groupId>io.github.tapeshchavle</groupId>
    <artifactId>sentinai-module-data-leak-prevention</artifactId>
    <version>1.1.0</version>
</dependency>
```

---

## ⚙️ Configuration

### Minimal (Default)
When you install SentinAI, the DLP module is active out-of-the-box in `LOG` mode. It won't modify your responses, but it will aggressively yell at you in the application console if it sees sensitive data leaving.
```yaml
sentinai:
  ai:
    api-key: ${AI_API_KEY}
```

### Custom Settings
When you are ready to enforce data protection, change the mode.
```yaml
sentinai:
  modules:
    data-leak-prevention:
      enabled: true
      config:
        mode: REDACT        # Available modes: LOG, REDACT, or BLOCK
        max-payload-size: 1048576 # Skip responses larger than 1MB to save CPU
```

### What a REDACTED Output Looks Like

If the module is set to `REDACT`, it will intercept the leaky JSON from earlier and rewrite it on the fly:

```json
{
  "id": 5,
  "name": "John Doe",
  "email": "john@company.com",
  "password_hash": "[REDACTED BY SENTINAI]",
  "ssn": "[REDACTED BY SENTINAI]",
  "internal_api_key": "[REDACTED BY SENTINAI]"
}
```

---

## 🛡️ Edge Cases Handled

| Scenario | How SentinAI Handles It |
|:---|:---|
| **A generated ID happens to look exactly like a credit card number** | The module runs potential credit card numbers through the Luhn algorithm. If it's a random ID, the algorithm fails, and SentinAI ignores it. No false positives. |
| **Massive JSON Responses (e.g., millions of rows)** | Running heavy regex over massive strings hangs the CPU. SentinAI automatically skips scanning any payload larger than `1MB` (configurable) to preserve latency. |
| **Authentication Endpoints** | If your controller intentionally returns a JWT upon successful login, the detector explicitly ignores JWTs on paths named `/login` or `/auth`. |
| **File Downloads / Images** | The module checks the `Content-Type`. It only runs its regex engine on `application/json` or `text/*` payloads. Binary data is skipped instantly. |
