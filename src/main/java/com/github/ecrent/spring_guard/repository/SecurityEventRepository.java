package com.github.ecrent.spring_guard.repository;

import com.github.ecrent.spring_guard.model.SecurityEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;



@Repository
public interface SecurityEventRepository extends JpaRepository<SecurityEvent, Long> {
List<SecurityEvent> findByAction(String action);
List<SecurityEvent> findByIp(String ip);
List<SecurityEvent> findTop10ByOrderByTimestampDesc();
}