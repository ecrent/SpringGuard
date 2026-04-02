package com.github.ecrent.spring_guard.repository;

import com.github.ecrent.spring_guard.model.SecurityEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SecurityEventRepository extends JpaRepository<SecurityEvent, Long> {

}