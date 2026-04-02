package com.github.ecrent.spring_guard.dto;

import com.github.ecrent.spring_guard.model.SecurityEvent;
import java.time.LocalDateTime;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;


@Data
@NoArgsConstructor
@AllArgsConstructor
public class SecurityEventDTO {
    private Long id;
    private LocalDateTime timestamp ;
    private String ip;
    private String method;
    private String uri;
    private String action;
    private String threatType;

public static SecurityEventDTO fromEntity(SecurityEvent event) {
        return new SecurityEventDTO(
                event.getId(),
                event.getTimestamp(),
                event.getIp(),
                event.getMethod(),
                event.getUri(),
                event.getAction(),
                event.getThreatType()
        );
    }
}