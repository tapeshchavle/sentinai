# SentinAI — Complete Interview Guide
### "Why I Built This, What Problem It Solves, and Why Cloudflare/WAF Is Not Enough"

---

## Table of Contents

1. [The Big Picture — What Is API Security?](#the-big-picture)
2. [What Existed Before — Traditional WAF and Its Fatal Flaws](#traditional-waf)
3. [Vulnerability #1 — Distributed Credential Stuffing](#vulnerability-1)
4. [Vulnerability #2 — BOLA / IDOR (The Most Misunderstood One)](#vulnerability-2)
5. [Vulnerability #3 — Application-Layer DDoS via Expensive Queries](#vulnerability-3)
6. [Vulnerability #4 — Accidental Outbound Data Leakage](#vulnerability-4)
7. [Vulnerability #5 — AI Denial of Wallet / Token Exhaustion](#vulnerability-5)
8. [Why Not Just Use Cloudflare / AWS WAF?](#why-not-cloudflare)
9. [How SentinAI Solves Each Problem](#how-sentinai-solves)
10. [Expected Interview Questions and Answers](#interview-qa)

---

## 1. The Big Picture — What Is API Security?

### Think of It Like a Bank

Imagine you own a bank. You have two types of protection:

**Outside Protection (Traditional WAF / Cloudflare):**
- Security guard at the main door
- He checks: "Do you look suspicious? Are you on a known criminal list?"
- He does NOT know whether you have an account
- He does NOT know your account balance
- He does NOT know if you are allowed to enter vault #3 or vault #5

**Inside Protection (SentinAI):**
- A security system *inside* the bank
- It knows: "This is Alice. She has savings account #501. She just tried to access vault #502 which belongs to Bob. That is suspicious."

**The problem with only having outside protection:**
- A sophisticated thief can dress nicely, walk through the front door confidently, and the outside guard waves him in
- Once inside, nobody is watching what vault he opens

**This is exactly what happens with modern APIs.**

---

## 2. What Existed Before — Traditional WAF and Its Fatal Flaws

### What Is a WAF?

WAF = Web Application Firewall. Examples: Cloudflare, AWS WAF, Azure Front Door, Akamai, Nginx ModSecurity.

**How a WAF works:**
1. All internet traffic hits the WAF first (before reaching your application)
2. WAF looks at the HTTP request and makes a decision: ALLOW or BLOCK
3. If ALLOW, the request passes to your application server

### What Information Does a WAF Have?

```
WAF can see:
  Source IP Address        ->  198.51.100.22
  HTTP Method              ->  GET
  URL Path                 ->  /api/orders/502
  Request Headers          ->  Authorization: Bearer eyJhbGci...
  Raw Request Body         ->  {"username":"alice", "password":"test123"}

WAF CANNOT see:
  WHO is the authenticated user   ->  (JWT is just a token, WAF does not decode it for business logic)
  What data belongs to this user  ->  WAF has no access to your database
  Your business rules             ->  WAF does not know "order 502 belongs to Bob"
  Outbound JSON responses         ->  WAF only inspects incoming requests
  Token costs / budget            ->  WAF does not know what your LLM API costs
```

### The Core Flaw In One Sentence

> A WAF only sees the ENVELOPE of a letter. SentinAI reads and understands the actual CONTENT and CONTEXT of the letter.

---

## 3. Vulnerability #1 — Distributed Credential Stuffing

### What Is Credential Stuffing? (Simple Explanation)

Every few months, a major website gets hacked and millions of username/password combinations get leaked on the dark web. These lists are called "combo lists."

Attackers download these lists and write a script that tries every username/password combination against your login API — hoping that people reused the same password on your app too.

### A Real-World Example

```
Leaked combo list on dark web:
  alice@gmail.com : Summer2019!
  bob@gmail.com : Football123
  carol@gmail.com : Qwerty@456
  ... (5 million more rows)

Attacker's script tries these against YOUR app:
  POST /api/login  {"username": "alice@gmail.com", "password": "Summer2019!"}
  POST /api/login  {"username": "bob@gmail.com", "password": "Football123"}
  ...
```

### Why Traditional IP-Based Rate Limiting Fails

The obvious solution: "Block any IP that fails login more than 5 times."

But attackers use a **Residential Proxy Network (Botnet)** — a service giving them access to millions of real home internet connections (compromised devices) around the world.

```
Request 1:  IP 101.53.22.1   ->  alice@gmail.com : Summer2019!    ->  FAIL
Request 2:  IP 72.31.98.44   ->  bob@gmail.com : Football123      ->  FAIL
Request 3:  IP 188.12.5.231  ->  carol@gmail.com : Qwerty@456     ->  SUCCESS (found one!)
Request 4:  IP 45.76.11.88   ->  dave@gmail.com : Password1!      ->  FAIL
```

From the WAF's perspective: 4 different IPs, each made exactly 1 request. Totally normal.
IP-based rate limiter: Never triggers. 0 requests blocked.
But from a human perspective: ALL of these are the same attacker.

### Why SentinAI Solves This

SentinAI tracks the **username being targeted**, not the IP address.

```java
// SentinAI reads the JSON body: {"username": "alice@gmail.com", "password": "Summer2019!"}
// It extracts the username: "alice@gmail.com"
// It increments a Redis counter keyed by USERNAME, not IP:
//   "credential-guard:alice@gmail.com:failures" -> 1, 2, 3 ... BLOCKED
```

Even if 5,000 different IPs attack Alice's account — after 5-10 failures for "alice@gmail.com", SentinAI blocks that username target.

**The attacker has 5 million proxy IPs, but Alice still only has 1 username. SentinAI wins.**

---

## 4. Vulnerability #2 — BOLA / IDOR (The Most Misunderstood One)

### FIRST: Clear The JWT Confusion

**Question:** "If my endpoint has a JWT filter, why would someone be able to access `/api/orders/502`?"

**Answer:** JWT verifies WHO you are. It does NOT automatically verify WHAT you are allowed to access.

### A Simple Code Example

```java
// YOUR SPRING BOOT CODE (very common in real-world apps)

@GetMapping("/api/orders/{orderId}")
public Order getOrder(@PathVariable Long orderId) {
    // JWT filter confirms user is LOGGED IN as Alice -- OK
    // But this fetches ANY order by ID without checking ownership!
    return orderRepository.findById(orderId).orElseThrow();
    // NOBODY CHECKED: Does Alice OWN order #502?
}

// CORRECT way:
@GetMapping("/api/orders/{orderId}")
public Order getOrder(@PathVariable Long orderId, Principal user) {
    Order order = orderRepository.findById(orderId).orElseThrow();
    if (!order.getOwnerUserId().equals(user.getName())) {
        throw new AccessDeniedException("Not your order!");  // This check is OFTEN MISSING
    }
    return order;
}
```

When Alice calls `/api/orders/502`:
- JWT filter: "Alice is logged in. Allow request." -- PASS
- Controller fetches order #502 from database (which belongs to Bob)
- Nobody checked ownership -- DATA BREACH

### This Is NOT a Theoretical Problem

**OWASP** lists BOLA as the **#1 most critical API vulnerability** for multiple years in a row.

Real-world breaches:
- **Peloton (2021):** Any user could access private profile data of any account by changing the user ID in the URL
- **Venmo:** Years of transactions were publicly accessible by iterating user IDs
- **Uber (2016):** BOLA in internal API exposed driver data

### How Does The Attack Work Step By Step?

```
Step 1: Alice logs in legitimately and gets a JWT token.

Step 2: Alice sees a request in Chrome DevTools:
        GET /api/orders/2058

Step 3: Alice opens Burp Suite or Postman and sends:
        GET /api/orders/2059   (with her valid JWT attached)
        GET /api/orders/2060
        GET /api/orders/2061
        ... and so on

Step 4: If developer forgot ownership check:
        Every request passes JWT validation (she IS logged in)
        Every request returns data (DB fetches by ID without owner check)
        Alice just downloaded ALL orders from your database -- DATA BREACH
```

### Why WAF Cannot Catch This

```
GET /api/orders/2058  ->  Valid HTTP, valid JWT. ALLOWED.
GET /api/orders/2059  ->  Valid HTTP, valid JWT. ALLOWED.
GET /api/orders/2060  ->  Valid HTTP, valid JWT. ALLOWED.
```

The WAF has no idea that orders 2059 and 2060 belong to different users.

### How SentinAI Catches This

SentinAI tracks behavioral patterns per authenticated user:

```
Alice (userId: 1001) accessed: /api/orders/2058  ->  ID: 2058
Alice (userId: 1001) accessed: /api/orders/2059  ->  ID: 2059  (sequential!)
Alice (userId: 1001) accessed: /api/orders/2060  ->  ID: 2060  (sequential!)
Alice (userId: 1001) accessed: /api/orders/2061  ->  ID: 2061  (sequential!)
Alice (userId: 1001) accessed: /api/orders/2062  ->  ID: 2062  (sequential!)
                                                 5 consecutive sequential IDs -> BLOCK
```

Also: "Alice accessed 25 unique order IDs in 10 minutes" -- a normal user never does this.

**The key insight: Even if each individual request looks valid, the PATTERN of behavior reveals the attack.**

---

## 5. Vulnerability #3 — Application-Layer DDoS via Expensive Queries

### Two Types of DDoS

**Type 1: Volumetric DDoS (What WAFs stop)**
- Attacker sends 10 million packets per second
- Server overwhelmed by VOLUME
- Cloudflare easily stops this

**Type 2: Application-Layer DDoS (What WAFs CANNOT stop)**
- Attacker sends just 5-10 requests per second
- But each request triggers an extremely expensive database operation
- Server crashes from COMPUTATION, not volume

### A Real Example

Your search API: `GET /api/products?search=laptop`
Database runs: `SELECT * FROM products WHERE name LIKE '%laptop%';`
Normal: 10ms, 5MB memory. Fine.

**Malicious request:** `GET /api/products?search=a%25b%25c%25d%25e%25f%25g`

When URL-decoded, `%25` becomes `%`, so the database runs:
```sql
SELECT * FROM products WHERE name LIKE '%a%b%c%d%e%f%g%';
```

This "wildcard explosion" forces a full table scan. Can take 30 seconds and 2GB of RAM.

**Attacker sends 10 such requests per second.** DB connection pool fills up. Server crashes. This is DDoS with just 10 requests/second.

### Why WAF Cannot Stop This

The WAF sees a valid HTTP GET request with normal volume. It has NO idea this will cause a 30-second database query. The WAF cannot run your database query to evaluate its cost.

### How SentinAI Handles This (Query Shield)

1. **URL Decoding First:** Automatically decodes `%25` to `%` before regex analysis, preventing obfuscation bypass.
2. **Concurrency Circuit Breaker:** If more than N concurrent heavy operations are running (tracked in Redis), Query Shield rejects new heavy requests before they hit the database.

---

## 6. Vulnerability #4 — Accidental Outbound Data Leakage

### A Developer Mistake, Not An Attack

The attacker makes a normal API request. Your OWN CODE accidentally leaks sensitive data in the response.

### How It Happens

```java
// BAD: Returns the full database entity
@GetMapping("/api/user/profile")
public User getProfile(Principal principal) {
    return userRepository.findByUsername(principal.getName());
    // The User entity contains EVERYTHING from the database:
    // {
    //   "id": 101,
    //   "email": "alice@gmail.com",
    //   "passwordHash": "$2a$12$xyz...",  <-- BCRYPT HASH LEAKED!
    //   "ssn": "123-45-6789",             <-- SSN LEAKED!
    //   "stripeSecretKey": "sk_live_...", <-- API KEY LEAKED!
    // }
}

// CORRECT: Use a DTO
@GetMapping("/api/user/profile")
public UserProfileDTO getProfile(Principal principal) {
    User user = userRepository.findByUsername(principal.getName());
    return new UserProfileDTO(user.getId(), user.getName(), user.getEmail());
}
```

The developer forgets to use a DTO. Hibernate/JPA returns ALL database fields.

### Why WAF Cannot Help

The WAF only inspects **incoming** requests. It never sees the JSON data being returned by your server.

### How SentinAI Solves This (DLP Module)

SentinAI intercepts the **outbound response** before it reaches the client:

```
SentinAI scans outbound JSON:
  {"id": 101, "email": "alice@gmail.com", "passwordHash": "$2a$12$xyz..."}

Detects Bcrypt hash pattern. In REDACT mode:
  {"id": 101, "email": "alice@gmail.com", "passwordHash": "[REDACTED]"}

Client gets safe version. Developer mistake is silently caught.
```

Detects: Bcrypt/Argon2 hashes, AWS Secret Keys, SSNs, private keys, credit card numbers.

---

## 7. Vulnerability #5 — AI Denial of Wallet / Token Exhaustion

### A Brand New Problem (2024-2025)

This only affects applications that use LLMs (OpenAI, Claude, Gemini) as part of their API.

### How LLM APIs Are Charged

You pay per "token" (roughly 1 token = 1 word).
- Normal user conversation: ~$0.002

### The Attack

```
POST /api/chat
{"message": "Explain quantum physics in complete detail covering every known subfield..."}
```

Attacker scripts 1,000 requests per hour. Each forces a 10,000-word LLM response.

```
Cost per request:             ~$0.30
1,000 requests/hour x $0.30 = $300/hour
Over a weekend (48 hours)   = $14,400
```

They do not take your service down. They drain your bank account.

### Why WAF Cannot Help

A WAF does not know that this endpoint calls an LLM, how many tokens it uses, or what your daily budget is.

### How SentinAI Solves This (Cost Protection Module)

```yaml
sentinai:
  modules:
    cost-protection:
      enabled: true
      config:
        daily-limit: 50       # $50/day total app limit
        per-user-limit: 2     # $2/day per user limit
```

SentinAI counts tokens from LLM response metadata, calculates dollar cost, increments Redis counters per user, and blocks requests once the user hits their daily limit.

```
Attacker's 51st request -> Redis shows $2.10 spent -> BLOCKED (429)
```

---

## 8. Why Not Just Use Cloudflare / AWS WAF?

### Honest Answer: They Are Complementary, Not Competing

SentinAI is NOT a replacement for Cloudflare. Cloudflare does things SentinAI cannot:
- Absorb 10 Tbps volumetric DDoS attacks
- SSL termination at edge
- Global CDN and caching

But Cloudflare cannot do what SentinAI does:

| Threat Type | Cloudflare / AWS WAF | SentinAI |
|:---|:---|:---|
| Volumetric DDoS | Excellent | Not designed for this |
| Known CVEs and exploit signatures | Good | Limited |
| Distributed Credential Stuffing | Cannot track by username | Tracks by username in Redis |
| BOLA/IDOR | Cannot see ownership | Behavioral pattern detection |
| Application-Layer DDoS | Cannot evaluate query cost | Concurrency circuit breaker |
| Outbound data leakage | Only inspects inbound | Scans outbound JSON responses |
| AI token cost protection | No concept of tokens | Per-user budget enforcement |
| Business logic abuse | Zero context | Full user and app context |

### The Core Argument

The OWASP API Security Top 10's #1, #2, and #3 most critical API vulnerabilities are ALL application-layer vulnerabilities that external WAFs fundamentally cannot detect.

- Cloudflare = Airport security (checks entrance, blocks known threats)
- SentinAI = Security inside the bank vault (knows who can access what, watches behavior)

**You need BOTH.**

---

## 9. How SentinAI Solves Each Problem — Architecture Summary

### Phase 1: Synchronous (3-7ms, every request)

```
Request arrives
  -> Check Redis blocklist: "Is this user/IP already flagged?"
  -> Credential Guard: "Is this a login targeting a locked username?"
  -> Query Shield: "Does this contain expensive query patterns?"
  -> BOLA Detection: "Is this user accessing too many different IDs?"
  -> Any BLOCK -> return 403/429 immediately
  -> All SAFE -> forward to your controller
```

### Phase 2: Asynchronous (0ms impact on API response)

```
Background thread:
  -> Buffer batches of 10 request events
  -> Send telemetry (path, userId, patterns -- NOT sensitive payloads) to LLM
  -> LLM analyzes for slow reconnaissance patterns
  -> If BLOCK -> write verdict to Redis
  -> All Gateway instances pick up the block instantly via Redis
```

### Two Operating Modes

**MONITOR (default):** Logs all threats without blocking. Safe to deploy first and observe for a week.

**ACTIVE:** Fully enforces all blocks. Switch after tuning thresholds to your usage patterns.

### Plugin Architecture

```java
// Add any custom module:
@Component
public class CouponFraudDetector implements SecurityModule {
    public ThreatVerdict analyzeRequest(RequestEvent event, ModuleContext ctx) {
        // Your custom detection logic here
        return ThreatVerdict.safe(getId());
    }
}
// SentinAI auto-discovers it via @Component scanning. Zero configuration needed.
```

---

## 10. Expected Interview Questions and Answers

---

### Q1: "What problem does SentinAI solve?"

"Modern applications face application-layer security threats that traditional external WAFs like Cloudflare fundamentally cannot detect because they lack user identity and business context. SentinAI operates INSIDE the Spring Boot application, within the Spring Security filter chain, post-authentication. It gives full knowledge of who the user is, what resource they are accessing, and what your business rules are. It detects distributed credential stuffing by tracking failed logins per USERNAME rather than IP, catches BOLA/IDOR by monitoring per-user behavioral patterns, prevents outbound data leaks by scanning JSON responses, and enforces LLM cost budgets. None of these are possible with an external WAF."

---

### Q2: "Why not use Cloudflare? It's way bigger and more trusted."

"Cloudflare is excellent at what it does — absorbing volumetric DDoS, enforcing rate limits by IP, filtering known malicious signatures. I actually recommend using both together. The problem is Cloudflare cannot see inside your application. When an authenticated user changes `/api/orders/501` to `/api/orders/502` — both requests have valid JWT, valid HTTP, and normal volume. Cloudflare lets both through. SentinAI knows the user is Alice and she just accessed her 20th unique order ID in 5 minutes — a behavioral anomaly it can block. These are fundamentally different layers of defense. Cloudflare secures the perimeter. SentinAI secures the application logic."

---

### Q3: "BOLA sounds like a simple authorization bug. Why don't developers just fix their code?"

"Developers SHOULD write proper ownership checks. But large codebases have hundreds of endpoints maintained by multiple developers under deadline pressure. OWASP lists BOLA as the #1 API vulnerability for years precisely because it is so common and hard to systematically prevent. SentinAI is a safety net. Even if one developer forgets an ownership check in one endpoint out of two hundred, SentinAI's behavioral detection catches the attack pattern before mass data extraction occurs. It is defense in depth — correct code AND a runtime behavioral guard."

---

### Q4: "What is your tech stack and why Spring Boot?"

"Java 17 and Spring Boot 3.4 plus. Spring Security is the industry standard for enterprise auth in Java. By integrating into the Spring Security filter chain, SentinAI operates at exactly the right moment — after authentication so it knows the user, but before the controller executes so it can block threats before business code runs. The Spring Boot Starter auto-configuration model means zero manual configuration — just add the Maven dependency. I also used Spring AI's abstraction layer for LLM integration, making it provider-agnostic. You can swap OpenAI for DeepSeek or Nvidia NIM with just a config change."

---

### Q5: "How does SentinAI scale across multiple instances?"

"If you run 5 Spring Cloud Gateway instances and an attack is detected on instance #1, instances #2 through #5 would be unaware if we used in-memory storage. SentinAI uses a shared Redis Decision Store. Blocking verdicts are written to Redis with a TTL. Every instance checks Redis on every request for existing blocks on that IP or userId. A block on instance #1 propagates to all others within milliseconds — purely through Redis reads. Credential Guard counters and Cost Protection daily budgets are also Redis-backed and distributed from day one."

---

### Q6: "What is the performance impact?"

"Synchronous checks add 3-7ms total. Redis blocklist check is 1ms (single key lookup). Regex matching is 0.1ms. Outbound DLP scan is 2-5ms. The heavy AI behavioral analysis is completely asynchronous — zero milliseconds added to API response time. Requests buffer in batches of 10 and are analyzed offline. For production APIs with 50-200ms response times, 3-7ms overhead is negligible and a very reasonable trade-off for enterprise-grade security."

---

### Q7: "Why use an LLM for threat detection? Isn't regex enough?"

"Regex is excellent for known static patterns and SentinAI uses regex for those cases — DLP patterns and simple injection strings. But LLMs excel at recognizing complex behavioral patterns across multiple requests over time. A regex cannot look at 10 requests and determine 'this user is probing resource IDs in a randomized pattern that looks like reconnaissance.' LLMs can reason about context and anomaly in ways rule-based systems cannot. The key design choice is that LLMs are only used for expensive async batch analysis — never on the hot request path — so there is zero latency cost."

---

### Q8: "What happens if the LLM API goes down?"

"The system fails gracefully. All synchronous heuristics — Redis blocklist, Credential Guard, Query Shield, BOLA sequential and unique ID detection — run completely independently of the LLM. If OpenAI goes down, async batch analysis pauses but all synchronous protections remain fully operational. The API keeps running and core modules keep blocking threats. You temporarily lose the deep behavioral analysis layer until the LLM recovers. The system is designed for graceful degradation — a third-party AI outage never makes your application insecure."

---

### Q9: "How do you handle false positives?"

"MONITOR mode is the default for exactly this reason. When you first deploy SentinAI, it logs every threat it would have blocked without actually blocking anyone. Observe this for a week and tune thresholds. If the BOLA module triggers at 15 unique IDs in 10 minutes but your admin users regularly access 20 records, raise the threshold to 30. Once you are confident thresholds match real usage patterns, switch to ACTIVE mode. All thresholds are configurable in YAML. You can also add specific paths to the exclude-paths list. The philosophy: give operators full visibility and control before enforcing anything."

---

### Q10: "Why would enterprises use an open-source security library?"

"Open-source is a feature for security tools, not a risk. Closed-source security products rely on 'security through obscurity.' With open-source code, security researchers and auditors can inspect exactly what SentinAI does — no hidden backdoors, no data silently sent to third parties. The source code is exactly what it claims to be. The world's most trusted security tools are open-source: Spring Security, OpenSSL, Bouncy Castle. For enterprises, the code can be forked, audited, and deployed in fully air-gapped on-premise environments. A business model can be built around enterprise support contracts and hosted threat intelligence — the same model used by HashiCorp, Elastic, and Red Hat."

---

*Document created for SentinAI project interview preparation.*
*Author: Tapesh Chavle*
*Published on Maven Central: io.github.tapeshchavle:sentinai-spring-boot-starter*
