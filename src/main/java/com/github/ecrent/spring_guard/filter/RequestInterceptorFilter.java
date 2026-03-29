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


@Component
public class RequestInterceptorFilter extends OncePerRequestFilter {
    private static final Logger logger = LoggerFactory.getLogger(RequestInterceptorFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String ip = request.getRemoteAddr();
        String method = request.getMethod();
        String uri = request.getRequestURI();
        String userAgent = request.getHeader("User-Agent");

        logger.info("Incoming: method={}, uri={}, ip={}, agent={}", method, uri, ip, userAgent);

        filterChain.doFilter(request, response);
    }
}