package com.github.ecrent.spring_guard.service;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.stereotype.Service;

@Service
public class RateLimiter {
    private static final long TIME_WINDOW = 60_000;
    private static final int MAX_REQUESTS = 5;

    private final ConcurrentHashMap<String, RequestInfo> requestCounts = new ConcurrentHashMap<>();

    public boolean isRateLimited(String ip) {
        boolean[] limited = {false};

        requestCounts.compute(ip, (key, info) -> {
            long now = System.currentTimeMillis();

            if (info == null || (now - info.windowStart) > TIME_WINDOW) {
                return new RequestInfo();
            }

            int count = info.count.incrementAndGet();
            if (count > MAX_REQUESTS) {
                limited[0] = true;
            }
            return info;
        });

        return limited[0];
    }

    private static class RequestInfo {
        private final AtomicInteger count = new AtomicInteger(1);
        private final long windowStart = System.currentTimeMillis();
    }
}