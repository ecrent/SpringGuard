Plan: Phase 1 — "The Interceptor"
Build a OncePerRequestFilter that intercepts every incoming HTTP request and logs the client IP, URI, HTTP method, and User-Agent. This is the foundation for all later phases (threat detection, rate limiting, etc.).

Before You Start
Run ./mvnw test and ./mvnw spring-boot:run to confirm your scaffold works. You should see "Tomcat started on port 8080" and the context-loads test should pass.

Phase 1A — Understand the Concepts (Research)
Learn the Servlet Filter lifecycle. A jakarta.servlet.Filter has three stages: init() → doFilter() → destroy(). Google "Jakarta Servlet Filter lifecycle". Your filter logic lives in doFilter().

Learn what OncePerRequestFilter is. It's a Spring abstract class at org.springframework.web.filter.OncePerRequestFilter that guarantees your filter runs exactly once per request (even during forwards/includes). The method you override is doFilterInternal(HttpServletRequest, HttpServletResponse, FilterChain).

Understand filterChain.doFilter(request, response). This is the "pass it along" call. Call it → request continues to the controller. Skip it → request is blocked (this is how Phase 2 will block attacks). For now, always call it.

Understand @Component registration. Annotating your filter with @Component makes Spring auto-detect and register it in the filter chain. Simple and sufficient for Phase 1.

Phase 1B — Create a Dummy REST Endpoint
Create a test controller. You need a target to send requests to. Create a package com.github.ecrent.spring_guard.controller and a class annotated with @RestController. Add one method mapped to GET /api/health that returns a string like "SpringGuard is running". Use @GetMapping("/api/health").

Test it manually. Start the app and run curl http://localhost:8080/api/health from the Codespaces terminal. You should get your string back.

Phase 1C — Build the Filter (the main event)
Create a package com.github.ecrent.spring_guard.filter.

Create RequestInterceptorFilter in that package. It should:

Be annotated @Component
Extend OncePerRequestFilter
Override doFilterInternal(HttpServletRequest, HttpServletResponse, FilterChain)
Add a logger. Use SLF4J: create a private static final Logger via LoggerFactory.getLogger(YourClass.class). (Or use Lombok's @Slf4j annotation — your choice. Manual approach teaches you what Lombok hides.)

Extract request metadata inside doFilterInternal using the HttpServletRequest API:

request.getRemoteAddr() → client IP
request.getMethod() → GET, POST, etc.
request.getRequestURI() → path like /api/health
request.getHeader("User-Agent") → client identifier
Log it with logger.info("Incoming: method={}, uri={}, ip={}, agent={}", ...). Use SLF4J {} placeholders — never string concatenation. This is a best practice for performance and safety.

Call filterChain.doFilter(request, response) at the end. If you forget this, every request dies in your filter and returns nothing.

Phase 1D — Verify
Restart the app (./mvnw spring-boot:run).

curl -v http://localhost:8080/api/health — check the app console for your log line showing IP, URI, method, and User-Agent.

curl -H "User-Agent: EvilBot/1.0" http://localhost:8080/api/health — verify the log shows EvilBot/1.0.

curl http://localhost:8080/does-not-exist — verify the filter still logs even for 404 paths. This proves it intercepts ALL traffic.

(Optional) Write a test using @WebMvcTest + MockMvc that calls GET /api/health and asserts status 200.


-------------------------



Plan: Phase 2 — "Threat Detection"
Add SQL Injection and XSS detection to your filter. When a malicious pattern is found in the URL or query parameters, block the request with 403 Forbidden instead of calling filterChain.doFilter(). Detection logic lives in a separate service class for clean separation and testability.

Phase 2A — Understand the Concepts
How blocking works. In Phase 1 you always called filterChain.doFilter(). To block a request, you skip that call. Instead:

response.setStatus(HttpServletResponse.SC_FORBIDDEN) → sets HTTP 403
response.getWriter().write("Blocked by SpringGuard: ...") → sends a message body
return; → exits without calling filterChain.doFilter()
Where attackers inject payloads. Three places:

URI path: GET /api/users/<script>alert(1)</script>
Query parameters: GET /api/search?q=' OR 1=1 --
Request body: POST /api/login with {"username": "' OR 1=1 --"}
We'll cover URI + query params first. Body inspection is more complex (stream can only be read once) — we'll tackle it as an optional enhancement.

Java regex. Pattern.compile("regex") compiles once (expensive), pattern.matcher(input).find() runs fast on every request. (?i) makes a pattern case-insensitive.

Why a separate service class. Putting all detection logic in the filter makes it bloated and hard to test. A @Service class can be unit-tested with plain JUnit — no web server needed. The filter calls the service via constructor injection.

Phase 2B — Create the ThreatDetector Service
Create package com.github.ecrent.spring_guard.service.

Create ThreatDetector.java with @Service annotation.

Define SQL Injection patterns as a List<Pattern> field, compiled once in the field initializer:

(?i)('\\s*(OR|AND)\\s+.*=) — catches ' OR 1=1, ' AND 'x'='x
(?i)(;\\s*(DROP|ALTER|DELETE|UPDATE|INSERT)) — catches ; DROP TABLE users
(?i)(UNION\\s+SELECT) — catches UNION-based injection
(--) — SQL comment injection
Define XSS patterns as another List<Pattern> field:

(?i)(<\\s*script[\\s>]) — catches <script> tags
(?i)(javascript\\s*:) — catches javascript: URIs
(?i)(\\bon\\w+\\s*=) — catches onerror=, onload= inline handlers
Create two public methods:

boolean isThreat(String input) — returns true if any pattern matches
String detectThreatType(String input) — returns "SQL_INJECTION", "XSS", or null — useful for logging
Phase 2C — Wire the Detector into the Filter
Add constructor injection to RequestInterceptorFilter. Declare private final ThreatDetector threatDetector and accept it as a constructor parameter. Spring auto-passes the @Service bean. This teaches the preferred injection style (constructor > @Autowired on fields).

Extract the query string with request.getQueryString() — returns the ?key=value part, or null.

Check for threats — pass both URI and query string through threatDetector.detectThreatType(...). If a threat is found:

Log it at WARN level: logger.warn("BLOCKED: ..., threat={}", threatType)
Set response.setStatus(HttpServletResponse.SC_FORBIDDEN)
Write a response body via response.getWriter().write(...)
return; — do NOT call filterChain.doFilter()
If clean, proceed as Phase 1: log at INFO level, call filterChain.doFilter().

Phase 2D — Verify with Attack Payloads
SQL Injection test:

→ Expected: HTTP 403

XSS test:

→ Expected: HTTP 403

Clean requests still pass:

→ Expected: HTTP 200

SQL injection in URI path:


→ Expected: HTTP 403

Check console logs — blocked requests show as WARN with threat type, clean requests show as INFO (same as Phase 1).

(Optional) Write unit tests for ThreatDetector — pure JUnit, no Spring context. Test patterns with known attack strings and known clean strings.

Relevant Files
File	Action
src/.../filter/RequestInterceptorFilter.java	Modify — add ThreatDetector injection + blocking logic
src/.../service/ThreatDetector.java	New — pattern-matching service
src/.../service/ThreatDetectorTest.java (test dir)	Optional new — unit tests
Verification Checklist
./mvnw test passes
SQLi query param → 403
XSS query param → 403
Clean request → 200
Console shows WARN for blocked, INFO for clean
Existing Phase 1 logging still works on clean requests
Scope Boundary
Included: URI path + query parameter inspection, SQL Injection patterns, XSS patterns
Excluded for now: Request body inspection (requires wrapping the input stream — can add as Phase 2 enhancement after the basics work)
Excluded: Session-based tracking, persistent blocking (that's Phase 3 rate limiting + Phase 4 logging)
Want me to expand any step into detailed instructions (like I did for Phase 1B and 1C), or are you ready to start with Phase 2B?


Plan: Phase 3 — "Rate Limiting"
Build an in-memory rate limiter using ConcurrentHashMap that tracks request counts per IP. IPs exceeding the threshold get blocked with HTTP 429 Too Many Requests. The rate limiter runs before threat detection — no point wasting CPU on regex if the IP is already spamming.

Phase 3A — Understand the Concepts
Rate limiting — limit how many requests a single IP can make within a time window. Prevents brute-force attacks, credential stuffing, and denial-of-service.

ConcurrentHashMap — a thread-safe HashMap. Multiple Tomcat threads handle requests simultaneously (you saw nio-8080-exec-2 and exec-5 in Phase 1 logs). A regular HashMap would corrupt data under concurrent access. ConcurrentHashMap handles locking internally.

HTTP 429 — the standard status code for rate limiting. Different from 403 (forbidden/blocked for security) — 429 means "you're sending too many requests, slow down."

Fixed time window — count requests per IP in a fixed window (e.g., 60 seconds). When the window expires, the count resets. Simpler than a sliding window and sufficient for learning.

Filter order matters. The check order inside doFilterInternal will become: rate limit check → threat detection → pass through. If an IP is spamming 1000 requests, you don't want to run 7 regex patterns on each one.

Phase 3B — Create the RateLimiter Service
Create RateLimiter.java in the service package with @Service.

Data structure — ConcurrentHashMap<String, RequestInfo> where the key is the IP address and RequestInfo holds two things: the request count and the window start timestamp.

Create a small inner class RequestInfo inside RateLimiter with fields: an AtomicInteger count (thread-safe counter) and a long windowStart (epoch milliseconds from System.currentTimeMillis()). An AtomicInteger is like an int that can be safely incremented from multiple threads without locking.

Define two constants as fields on the class:

MAX_REQUESTS = 50 (requests per window)
WINDOW_SIZE_MS = 60_000 (window = 60 seconds in milliseconds)
Implement boolean isRateLimited(String ip) — the core method:

Use ConcurrentHashMap.compute(ip, ...) for atomic read-modify-write
If no entry exists or window has expired → create a new RequestInfo with count=1 and windowStart=now → return false
Otherwise increment count → if count exceeds MAX_REQUESTS → return true, else false
Phase 3C — Wire into the Filter
Add RateLimiter as a second constructor parameter in RequestInterceptorFilter — same pattern as ThreatDetector.

Add the rate limit check as the first check inside doFilterInternal, before threat detection:

Call rateLimiter.isRateLimited(ip)
If true → logger.warn(...), set response status 429, write body, return
If false → continue to existing threat detection code
Phase 3D — Verify
Spam test — run this loop from the terminal:

First 50 responses should say 200, remaining 5 should say 429.

Reset test — wait 60 seconds after being rate-limited, then try again → should get 200.

Threat payloads within rate limit should still return 403 (not 429):


Clean requests still return 200 as before.

Relevant Files
File	Action
src/.../service/RateLimiter.java	New — in-memory rate limiting with ConcurrentHashMap
src/.../filter/RequestInterceptorFilter.java	Modify — add RateLimiter injection + 429 check before threat detection
New Concepts You'll Learn
ConcurrentHashMap and why thread safety matters in web apps
AtomicInteger for lock-free concurrent counting
ConcurrentHashMap.compute() for atomic read-modify-write operations
System.currentTimeMillis() for time-based logic
Constructor injection with multiple dependencies
