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

@Component
public class RequestInterceptorFilter extends OncePerRequestFilter {
    private static final Logger logger = LoggerFactory.getLogger(RequestInterceptorFilter.class);

    private final ThreatDetector threatDetector;

    public RequestInterceptorFilter(ThreatDetector threatDetector) {
        this.threatDetector = threatDetector;
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

        if (threatType == null) {
            threatType = threatDetector.detectThreatType(decodedQuery);
        }

        if (threatType != null) {
            logger.warn("Potential threat detected: type={}, method={}, uri={}, ip={}, agent={}", threatType, method, uri, ip, userAgent);
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Potential threat detected: " + threatType);
            return;
        }

        logger.info("Incoming: method={}, uri={}, ip={}, agent={}", method, uri, ip, userAgent);

        filterChain.doFilter(request, response);
    }
}