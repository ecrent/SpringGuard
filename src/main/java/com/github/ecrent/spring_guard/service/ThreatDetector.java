package com.github.ecrent.spring_guard.service;

import org.springframework.stereotype.Service;
import java.util.List;
import java.util.regex.Pattern;

@Service
public class ThreatDetector {
    private static final List<Pattern> THREAT_PATTERNS = List.of(
            Pattern.compile("(?i)('\\s*(OR|AND)\\s+.*=)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)(;\\s*(DROP|ALTER|DELETE|UPDATE|INSERT))", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)(UNION\\s+SELECT)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(--)", Pattern.CASE_INSENSITIVE)
    );
    private static final List<Pattern> XSS_PATTERNS = List.of(
            Pattern.compile("(?i)(<\\s*script[\\s>])", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)(javascript\\s*:)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)(\\bon\\w+\\s*=)", Pattern.CASE_INSENSITIVE)
    );

    public String detectThreatType(String input) {
        if (input == null) {
            return null;
        }
        for (Pattern pattern : THREAT_PATTERNS) {
            if (pattern.matcher(input).find()) {
                return "SQL_INJECTION";
            }
        }
        for (Pattern pattern : XSS_PATTERNS) {
            if (pattern.matcher(input).find()) {
                return "XSS";
            }
        }
        return null;
    }

    public boolean isThreat(String input) {
        return detectThreatType(input) != null;
    }


}