package com.reimagineafrica.auth.repository;

import com.reimagineafrica.auth.entity.AuthAuditLog;
import com.reimagineafrica.auth.enums.AuditAction;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface AuthAuditLogRepository extends JpaRepository<AuthAuditLog, UUID> {

    Page<AuthAuditLog> findByUserIdOrderByCreatedAtDesc(UUID userId, Pageable pageable);

    Page<AuthAuditLog> findBySaccoCodeOrderByCreatedAtDesc(String saccoCode, Pageable pageable);

    long countByUserIdAndActionAndSuccessFalse(UUID userId, AuditAction action);
}
