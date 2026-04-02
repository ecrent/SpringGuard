package com.github.ecrent.spring_guard.service;

import com.github.ecrent.spring_guard.model.SecurityEvent;
import com.github.ecrent.spring_guard.repository.SecurityEventRepository;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;

@Service
public class SecurityEventService {

    private final SecurityEventRepository repository;

    public SecurityEventService(SecurityEventRepository repository) {
        this.repository = repository;
    }

    public void logEvent(String ip, String method, String uri,
                         String userAgent, String action, String threatType) {
        SecurityEvent event = new SecurityEvent();
        event.setTimestamp(LocalDateTime.now());  // captured here intentionally
        event.setIp(ip);
        event.setMethod(method);
        event.setUri(uri);
        event.setUserAgent(userAgent);
        event.setAction(action);
        event.setThreatType(threatType);  // will be null for ALLOWED events — that's fine
        repository.save(event);
    }
}