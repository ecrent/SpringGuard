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


Phase 4 Roadmap — Database + Auth
Where you are now: Your RequestInterceptorFilter has three code paths — rate-limited (429), threat-blocked (403), and allowed (pass-through). Phase 4 makes these events persistent and queryable, then locks down the query API with authentication.

Phase 4A — Persist Security Events to H2 Database
Concepts to research first (Google these, understand them before touching code):

JPA (Jakarta Persistence API) — a specification that defines how Java objects map to database tables. It's like an interface — it says "these annotations exist" but doesn't implement anything itself.
Hibernate — the implementation of JPA. Spring Boot auto-configures it. You never call Hibernate directly — you use JPA annotations and Spring does the wiring.
Spring Data JPA — sits on top of JPA/Hibernate. You write a Java interface, Spring generates the SQL implementation at runtime. You get save(), findAll(), findById() for free with zero code.
H2 — an in-memory database written in Java. Runs inside your app process (no external install). Data disappears on restart. Perfect for learning.
@Entity — marks a class as a database table. Each field = a column. @Id = primary key. @GeneratedValue(strategy = GenerationType.IDENTITY) = auto-increment.
Steps (in order):

Add dependencies to pom.xml — two new ones:

spring-boot-starter-data-jpa (brings in Hibernate + Spring Data)
com.h2database:h2 with <scope>runtime</scope> (H2 only needed at runtime, not compile time)
Configure H2 in application.properties:

Set the datasource URL to jdbc:h2:mem:springguard (in-memory, named "springguard")
Enable the H2 web console at /h2-console (a built-in database browser)
Set spring.jpa.hibernate.ddl-auto=create-drop (Hibernate creates tables on startup, drops on shutdown)
Optionally spring.jpa.show-sql=true to see generated SQL in your console logs — very educational
Create the entity — new package model, new class SecurityEvent. Fields:

id (Long, primary key, auto-generated)
timestamp (LocalDateTime)
ip, method, uri, userAgent (all String)
action (String — one of: "ALLOWED", "BLOCKED_THREAT", "BLOCKED_RATE_LIMIT")
threatType (String, nullable — only populated when there's a threat)
You'll need @Entity, @Id, @GeneratedValue, and a no-arg constructor (JPA requires it)
Create the repository — new package repository, new interface SecurityEventRepository extends JpaRepository<SecurityEvent, Long>. That's it. Empty body. Spring generates the implementation. This is the "magic" of Spring Data.

Create the service — SecurityEventService in service package, annotated @Service. Inject SecurityEventRepository via constructor. Write one method: logEvent(String ip, String method, String uri, String userAgent, String action, String threatType) that builds a SecurityEvent object and calls repository.save(entity).

Wire into your filter — add SecurityEventService as a third constructor parameter in RequestInterceptorFilter.java. Call logEvent(...) in all three code paths:

Rate-limited path → action = "BLOCKED_RATE_LIMIT"
Threat-blocked path → action = "BLOCKED_THREAT" + include the threatType
Clean pass-through → action = "ALLOWED"
Gotcha to watch for: If you don't exclude /h2-console requests from logging, you'll get noise. Consider overriding shouldNotFilter(HttpServletRequest request) in your filter to skip paths starting with /h2-console.

Verify:

./mvnw spring-boot:run
curl http://localhost:8080/api/health (clean request)
curl "http://localhost:8080/api/health?q=' OR 1=1" (blocked request)
Open http://localhost:8080/h2-console in browser, connect with JDBC URL jdbc:h2:mem:springguard, user sa, empty password
Run SELECT * FROM SECURITY_EVENT; — you should see both requests logged with their action types
Phase 4B — REST API for Security Events
Concepts to research:

DTO (Data Transfer Object) — a plain class that shapes what your API returns. Never expose your @Entity directly in API responses. Why? Your entity has userAgent (internal), and if you add fields to the entity later, they'd automatically leak into your API. DTOs decouple your database schema from your API contract.
Spring Data derived queries — name a method findByAction(String action) in your repository interface, and Spring parses the method name into SELECT * FROM security_event WHERE action = ?. No SQL needed. Google "Spring Data JPA query derivation" — the naming rules are well-documented.
Pagination — add a Pageable parameter to a controller method and return Page<T>. Spring reads ?page=0&size=10 from query params automatically. Clients can page through large result sets.
Steps:

Create DTOs — new package dto:

SecurityEventDTO — same fields as entity minus userAgent (that's internal). You'll manually map entity → DTO (or write a simple static factory method on the DTO).
StatsDTO — holds summary data: totalEvents (long), totalBlocked (long), and topAttackingIps (a list of strings or a map of IP → count)
Add query methods to your SecurityEventRepository interface — just declare them, Spring implements them:

List<SecurityEvent> findByAction(String action);
List<SecurityEvent> findByIp(String ip);
List<SecurityEvent> findTop10ByOrderByTimestampDesc();
Build stats logic in SecurityEventService:

countAll() → repository.count()
countBlocked() → query events where action is not "ALLOWED" and count them
Top attacking IPs → fetch blocked events, group by IP using Java streams, sort by count descending
Create the controller — SecurityEventController with @RestController and @RequestMapping("/api/events"):

Where You Are
You've already built more than you might realize:

Entity, Repository, DTOs — all done. Your SecurityEventDTO even has the fromEntity() factory method, and StatsDTO has the right shape.
Repository query methods — findByAction(), findByIp(), findTop10ByOrderByTimestampDesc() — all declared.
SecurityEventService — has logEvent() and getEvents(Pageable).
Two things are missing to finish Phase 4B:

Step 1: Add stats logic to SecurityEventService
Your service needs a method that builds and returns a StatsDTO. Think about what data it needs:

Total events: Your repository inherits a method from JpaRepository that counts all rows. Look at what JpaRepository gives you for free (hint: it's a one-word method).
Blocked events: You already have findByAction(String action). But "blocked" means both "BLOCKED_THREAT" and "BLOCKED_RATE_LIMIT". You have two options:
Fetch all events and filter in Java
Or use repository.count() minus the count of "ALLOWED" events — think about which is simpler
Top attacking IPs: Fetch the blocked events, then use Java Streams to group them by IP and count occurrences. The key methods to research:
stream().collect(Collectors.groupingBy(..., Collectors.counting())) — this gives you a Map<String, Long>
Then sort that map by value descending and take the top entries
Try writing this method yourself. If you get stuck on the Streams part, that's normal — it's the trickiest part. Try getting totalEvents and blockedEvents working first, then tackle the map.

Step 2: Create SecurityEventController
Create a new class in the controller package. Here's what you need to figure out:

Annotate it with @RestController and @RequestMapping("/api/events") — just like HealthController but with a base path
Inject SecurityEventService via constructor (same pattern you've used everywhere)
GET /api/events — the method takes a Pageable parameter (Spring auto-populates it from ?page=0&size=5 query params). Call your service's getEvents(), then map the Page<SecurityEvent> to Page<SecurityEventDTO>. Research Page.map() — it works like stream().map() but preserves pagination metadata.
GET /api/events/stats — maps to a sub-path. Call your stats method, return the DTO.
Key question to think about: For the /stats endpoint, what @GetMapping value do you use given that the class already has @RequestMapping("/api/events")?

Step 3: Verify
Once both pieces are in place:


Then generate some mixed traffic:


The events endpoint should return paginated JSON. The stats endpoint should show counts and the IP map.

Start with Step 1 — add the stats method to SecurityEventService.java. Get totalEvents returning correctly first, then layer on blockedEvents, then tackle the Streams grouping for top IPs. Show me what you come up with and I'll help you through any rough spots.

GET /api/events — accepts Pageable parameter, returns Page<SecurityEventDTO>. Use repository.findAll(pageable) then map entities to DTOs.
GET /api/events/stats — returns StatsDTO built by the service
Verify:

Make a mix of requests (clean + attacks + rapid-fire for rate limiting)
curl http://localhost:8080/api/events → paginated JSON list
curl http://localhost:8080/api/events?page=0&size=5 → first 5 events
curl http://localhost:8080/api/events/stats → summary JSON with counts and top IPs
Phase 4C — Spring Security Authentication
Concepts to research (this is the biggest conceptual leap):

Spring Security's filter chain — when you add spring-boot-starter-security, Spring inserts a whole chain of security filters that run before your controllers. By default, it locks down EVERYTHING — every endpoint returns 401 until you configure exceptions. This is "secure by default."
SecurityFilterChain bean — the modern way (Spring Security 6+) to configure security. You write a @Bean method in a @Configuration class. No more extending WebSecurityConfigurerAdapter (that's been deprecated for years — ignore old tutorials that use it).
HTTP Basic Auth — the simplest auth mechanism. Client sends Authorization: Basic base64(user:pass) header. The server decodes and validates. Good for APIs and learning. Not for browser UIs.
BCryptPasswordEncoder — hashes passwords with a salt. You never store plain-text passwords. When you define your in-memory user, the password must be encoded with BCrypt.
InMemoryUserDetailsManager — stores users in memory (hardcoded). Fine for learning. In a real app, you'd implement UserDetailsService backed by a database.
Filter ordering — your RequestInterceptorFilter (@Component + OncePerRequestFilter) runs BEFORE Spring Security by default. This is exactly what you want — rate limiting and threat detection should protect ALL traffic, even unauthenticated requests. The request flow becomes:

Steps:

Add dependency to pom.xml: spring-boot-starter-security

Create config class — new package config, new class SecurityConfig annotated with @Configuration and @EnableWebSecurity

Define SecurityFilterChain bean — a method that takes HttpSecurity http as parameter and returns http.build(). Inside, configure:

.authorizeHttpRequests(...) → permit /api/health and /h2-console/** without auth, require auth for /api/events/**
.httpBasic(Customizer.withDefaults()) → enable HTTP Basic
.csrf(csrf -> csrf.disable()) → disable CSRF (you're building an API, not serving HTML forms)
.headers(headers -> headers.frameOptions(f -> f.disable())) → needed for H2 console (it uses iframes)
Define UserDetailsService bean — returns new InMemoryUserDetailsManager(...) with one user. Use User.withUsername("admin").password(encodedPassword).roles("ADMIN").build()

Define PasswordEncoder bean — returns new BCryptPasswordEncoder(). Use it to encode the admin password.

Two gotchas that WILL bite you:

After adding Spring Security, if you start the app without your SecurityConfig, every endpoint returns 401 including /api/health. Spring Security locks everything by default. Don't panic — it means it's working. Your config opens the paths you choose.
Your existing test in SpringGuardApplicationTests.java may fail because the Spring context now loads Security and your test doesn't provide auth. Fix it with @WithMockUser annotation on the test class, or add test-specific security config.
Verify:

curl http://localhost:8080/api/health → 200 (public, no auth)
curl http://localhost:8080/api/events → 401 Unauthorized (protected)
curl -u admin:yourpassword http://localhost:8080/api/events → 200 with event data
curl "http://localhost:8080/api/health?q=<script>alert(1)</script>" → 403 (threat detection still works, runs before auth)
Rapid-fire curl loop → 429 (rate limiting still works)
H2 console still accessible at http://localhost:8080/h2-console
The Big Picture — How It All Connects

Recommended Order of Work
Do 4A first (database) → verify with H2 console → then 4B (API) → verify with curl → then 4C (auth) → verify with curl + credentials. Each sub-phase is independently testable. If something breaks, you know which layer caused it.

What You'll Learn
JPA entity mapping (@Entity, @Id, @GeneratedValue)
Spring Data repositories (zero-boilerplate CRUD)
H2 in-memory database + web console
DTO pattern for clean API design
Pagination with Pageable/Page<T>
SecurityFilterChain (modern Spring Security config)
HTTP Basic auth + BCryptPasswordEncoder
How your servlet filter and Spring Security's filter chain coexist
Ready to start with Phase 4A? Once you get into it, let me know if you want me to explain any concept deeper — like how JPA annotations map to SQL, or how SecurityFilterChain builder methods work.