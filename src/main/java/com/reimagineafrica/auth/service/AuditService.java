package com.reimagineafrica.auth.service;

import com.reimagineafrica.auth.entity.AuthAuditLog;
import com.reimagineafrica.auth.enums.AuditAction;
import com.reimagineafrica.auth.repository.AuthAuditLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuditService {

    private final AuthAuditLogRepository auditLogRepository;

    @Async
    public void log(UUID userId, String username, String saccoCode,
                    AuditAction action, boolean success,
                    String details, String ipAddress, String userAgent) {

        AuthAuditLog log = AuthAuditLog.builder()
                .userId(userId)
                .username(username)
                .saccoCode(saccoCode)
                .action(action)
                .success(success)
                .failureReason(success ? null : details)
                .details(success ? details : null)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .build();

        auditLogRepository.save(log);
    }
}
