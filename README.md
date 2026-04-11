# spring_boot_security_project

spring_boot_security_project is a security middleware suite for Spring Boot that demonstrates common defensive programming practices in Java. It intercepts every incoming HTTP request and applies layered protections: threat detection (SQL injection & XSS), IP-based rate limiting, and a full audit log of all security events — all persisted to a database and queryable via a REST API.

Built as a portfolio project to showcase practical Java and Spring Security skills.

---

## Features

| Feature | Description |
|---|---|
| **Request Interception** | A custom `OncePerRequestFilter` inspects every request before it reaches any controller |
| **SQL Injection Detection** | Regex patterns catch `' OR 1=1`, `UNION SELECT`, `; DROP TABLE`, `--` comments, and more |
| **XSS Detection** | Detects `<script>` tags, `javascript:` URIs, and inline event handlers like `onerror=` |
| **IP Rate Limiting** | Limits each IP to 5 requests per 60-second window using `ConcurrentHashMap` and `AtomicInteger` |
| **Security Event Audit Log** | Every request is persisted to a database with its IP, method, URI, action (`ALLOWED` / `BLOCKED_THREAT` / `BLOCKED_RATE_LIMIT`), and threat type |
| **REST API for Events** | Paginated endpoint to browse logged events and an aggregated stats endpoint |
| **Spring Security (HTTP Basic)** | Protects the events API behind HTTP Basic Auth with BCrypt-encoded passwords |

---

## Security Practices Demonstrated

- **Custom servlet filter** — extends `OncePerRequestFilter` to guarantee exactly one execution per request, even across forwards/includes
- **Regex-based threat detection** — patterns are compiled once at class load time (`Pattern.compile`) for performance, then reused on every request
- **Concurrent rate limiter** — uses `ConcurrentHashMap.compute()` for atomic IP tracking without explicit locking
- **Spring Security configuration** — `SecurityFilterChain` bean with role-based rules, HTTP Basic Auth, and CSRF disabled for a stateless API
- **BCrypt password encoding** — passwords are never stored in plain text
- **Constructor injection** — all dependencies are injected via constructors (preferred over field injection)
- **DTO projection** — entity fields are filtered through a DTO before being returned from the API to avoid leaking internal model details
- **Structured logging** — SLF4J is used with `{}` placeholders throughout (never string concatenation), preventing log injection and improving performance
- **URL decoding before inspection** — query strings are URL-decoded before threat scanning to catch encoded payloads like `%27%20OR%201%3D1`

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Java 25 |
| Framework | Spring Boot 4.0.5 |
| Security | Spring Security |
| Persistence | Spring Data JPA + H2 (in-memory) |
| Build | Maven (Maven Wrapper included) |
| Boilerplate reduction | Lombok |

---

## Project Structure

```
src/main/java/com/github/ecrent/spring_guard/
├── config/
│   ├── SecurityConfig.java            # Spring Security filter chain, BCrypt, HTTP Basic
│   └── H2ConsoleConfig.java           # H2 console setup
├── filter/
│   └── RequestInterceptorFilter.java  # Core middleware — intercepts all requests
├── service/
│   ├── ThreatDetector.java            # SQLi & XSS regex detection
│   ├── RateLimiter.java               # Per-IP sliding-window rate limiter
│   └── SecurityEventService.java      # Persists events, computes stats
├── controller/
│   ├── HealthController.java          # Public health-check endpoint
│   └── SecurityEventController.java   # Paginated events & stats API
├── model/
│   └── SecurityEvent.java             # JPA entity for audit log entries
├── repository/
│   └── SecurityEventRepository.java   # Spring Data JPA repository
└── dto/
    ├── SecurityEventDTO.java          # Safe public view of a SecurityEvent
    └── StatsDTO.java                  # Aggregated stats response
```

---

## API Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/health` | Public | Returns `"SpringGuard is running"` |
| `GET` | `/api/events` | Basic Auth | Paginated list of all security events |
| `GET` | `/api/events/stats` | Basic Auth | Total events, blocked count, top attacking IPs |
| `GET` | `/h2-console` | Public | H2 database browser (dev only) |

Default credentials: **username** `user` / **password** `password`

### Pagination

```
GET /api/events?page=0&size=20&sort=timestamp,desc
```

### Example Stats Response

```json
{
  "totalEvents": 42,
  "blockedEvents": 7,
  "topAttackingIPs": {
    "192.168.1.100": 5,
    "10.0.0.1": 2
  }
}
```

---

## How to Run

**Prerequisites:** Java 17+ and Maven (or use the included `./mvnw` wrapper)

```bash
# Clone and run
git clone https://github.com/ecrent/spring_boot_security_project.git
cd spring_boot_security_project
./mvnw spring-boot:run
```

The app starts on **http://localhost:8080**.

---

## Testing the Security Features

```bash
# Normal request — should be ALLOWED
curl http://localhost:8080/api/health

# SQL injection attempt — should return 403
curl "http://localhost:8080/api/health?q=%27+OR+1%3D1+--"

# XSS attempt — should return 403
curl "http://localhost:8080/api/health?name=<script>alert(1)</script>"

# Trigger rate limiting — 6th request within 60s from the same IP is blocked
for i in {1..6}; do curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/api/health; done

# View audit log (requires authentication)
curl -u user:password http://localhost:8080/api/events

# View stats
curl -u user:password http://localhost:8080/api/events/stats
```

---

## Running Tests

```bash
./mvnw test
```
