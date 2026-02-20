# 🔒 Data Leak Prevention

**Scans API responses for sensitive data before it reaches the client.**

## The Problem

A developer forgets to exclude the `password_hash` field from a user serialization. For **2 weeks**, every `/api/users/{id}` response leaks bcrypt hashes. No WAF catches this because the response is a "valid 200 OK".

```json
{
  "id": 5,
  "name": "John Doe",
  "email": "john@company.com",
  "password_hash": "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
  "ssn": "123-45-6789"
}
```

## How It Works

![Data Leak Prevention](images/data-leak-prevention.png)

### 11 Built-in Detectors

| Detector | Pattern | Validation |
|:---|:---|:---|
| Credit Card (Visa/MC/Amex) | `4XXX-XXXX-XXXX-XXXX` | ✅ Luhn algorithm |
| SSN (US) | `XXX-XX-XXXX` | Format match |
| Aadhaar (India) | `XXXX XXXX XXXX` | Format match |
| Bcrypt Hash | `$2a$10$...` | Prefix match |
| Argon2 Hash | `$argon2id$...` | Prefix match |
| OpenAI API Key | `sk-XXXX...` | Prefix + length |
| AWS Access Key | `AKIAXXXXXXXX` | Prefix + length |
| GitHub Token | `ghp_XXXX...` | Prefix + length |
| JWT Token | `eyJhbG...` | Three-segment base64 |
| Private Key (PEM) | `-----BEGIN PRIVATE KEY-----` | Header match |
| Hex Secrets | 64-char hex in JSON values | Context-aware |

## Independent Installation

If you don't want the full `sentinai-spring-boot-starter`, you can include just this module:

```xml
<dependency>
    <groupId>io.github.tapeshchavle</groupId>
    <artifactId>sentinai-module-data-leak-prevention</artifactId>
    <version>1.0.0</version>
</dependency>
```

## Integration

### Minimal
```yaml
sentinai:
  ai:
    api-key: ${AI_API_KEY}
# Scans all API responses by default in LOG mode
```

### Custom Config
```yaml
sentinai:
  modules:
    data-leak-prevention:
      enabled: true
      config:
        mode: REDACT        # LOG (default), REDACT, or BLOCK
```

### What Redacted Output Looks Like

```json
{
  "id": 5,
  "name": "John Doe",
  "email": "john@company.com",
  "password_hash": "[REDACTED BY SENTINAI]",
  "ssn": "[REDACTED BY SENTINAI]"
}
```

## Edge Cases Handled

| Scenario | How It's Handled |
|:---|:---|
| Number looks like a credit card | Luhn algorithm validates — rejects false positives |
| Large responses (>1MB) | Skipped for performance (configurable) |
| Non-JSON responses | Skipped — only scans `application/json` |
| Empty responses | Skipped — no scanning needed |
