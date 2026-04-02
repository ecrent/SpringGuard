package com.github.ecrent.spring_guard.controller;

import com.github.ecrent.spring_guard.dto.SecurityEventDTO;
import com.github.ecrent.spring_guard.dto.StatsDTO;
import com.github.ecrent.spring_guard.service.SecurityEventService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/events")
public class SecurityEventController {

    private final SecurityEventService securityEventService;

    public SecurityEventController(SecurityEventService securityEventService) {
        this.securityEventService = securityEventService;
    }

    @GetMapping
    public Page<SecurityEventDTO> getEvents(Pageable pageable) {
        return securityEventService.getEvents(pageable).map(SecurityEventDTO::fromEntity);
    }

    @GetMapping("/stats")
    public StatsDTO getStats() {
        return securityEventService.getStats();
    }
}
