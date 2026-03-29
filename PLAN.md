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