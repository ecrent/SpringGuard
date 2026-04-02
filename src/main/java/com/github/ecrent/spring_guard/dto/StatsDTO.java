package com.github.ecrent.spring_guard.dto;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class StatsDTO {
    private long totalEvents;
    private long blockedEvents;
    private Map<String, Long> topAttackingIPs;

}