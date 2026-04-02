package com.github.ecrent.spring_guard.filter;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.github.ecrent.spring_guard.service.ThreatDetector;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import com.github.ecrent.spring_guard.service.RateLimiter;
import com.github.ecrent.spring_guard.service.SecurityEventService;

@Component
public class RequestInterceptorFilter extends OncePerRequestFilter {
    private static final Logger logger = LoggerFactory.getLogger(RequestInterceptorFilter.class);

    private final RateLimiter rateLimiter;
    private final ThreatDetector threatDetector;
    private final SecurityEventService securityEventService;

    public RequestInterceptorFilter(ThreatDetector threatDetector, RateLimiter rateLimiter, SecurityEventService securityEventService) {
        this.threatDetector = threatDetector;
        this.rateLimiter = rateLimiter;
        this.securityEventService = securityEventService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return request.getRequestURI().startsWith("/h2-console");
    }
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String ip = request.getRemoteAddr();
        String method = request.getMethod();
        String uri = request.getRequestURI();
        String userAgent = request.getHeader("User-Agent");
        String queryString = request.getQueryString();
        String decodedQuery = queryString != null ? URLDecoder.decode(queryString, StandardCharsets.UTF_8) : null;
        String threatType = threatDetector.detectThreatType(uri);

        if (rateLimiter.isRateLimited(ip)) {
            logger.warn("Rate limit exceeded: ip={}, method={}, uri={}, agent={}", ip, method, uri, userAgent);
            securityEventService.logEvent(ip, method, uri, userAgent, "BLOCKED_RATE_LIMIT", null);
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Rate limit exceeded");
            return;
        }
        if (threatType == null) {
            threatType = threatDetector.detectThreatType(decodedQuery);
        }

        if (threatType != null) {
            logger.warn("Potential threat detected: type={}, method={}, uri={}, ip={}, agent={}", threatType, method, uri, ip, userAgent);
            securityEventService.logEvent(ip, method, uri, userAgent, "BLOCKED_THREAT", threatType);
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Potential threat detected: " + threatType);
            return;
        }

        logger.info("Incoming: method={}, uri={}, ip={}, agent={}", method, uri, ip, userAgent);
        securityEventService.logEvent(ip, method, uri, userAgent, "ALLOWED", null);
        filterChain.doFilter(request, response);
    }
}