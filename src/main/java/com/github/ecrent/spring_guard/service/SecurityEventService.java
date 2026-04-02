package com.github.ecrent.spring_guard.service;

import com.github.ecrent.spring_guard.dto.StatsDTO;
import com.github.ecrent.spring_guard.model.SecurityEvent;
import com.github.ecrent.spring_guard.repository.SecurityEventRepository;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

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

    public Page<SecurityEvent> getEvents(Pageable pageable) {
        return repository.findAll(pageable);
    }

    public StatsDTO getStats() {
        long total = repository.count();

        List<SecurityEvent> blocked = repository.findByAction("BLOCKED_THREAT");
        blocked.addAll(repository.findByAction("BLOCKED_RATE_LIMIT"));
        long blockedCount = blocked.size();

        Map<String, Long> ipCounts = blocked.stream()
                .collect(Collectors.groupingBy(SecurityEvent::getIp, Collectors.counting()));

        Map<String, Long> topAttackingIPs = ipCounts.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        Map.Entry::getValue,
                        (e1, e2) -> e1,
                        LinkedHashMap::new
                ));

        return new StatsDTO(total, blockedCount, topAttackingIPs);
    }
}