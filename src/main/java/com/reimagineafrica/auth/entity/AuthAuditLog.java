package com.reimagineafrica.auth.entity;

import com.reimagineafrica.auth.enums.AuditAction;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Immutable audit log — every authentication event is recorded here.
 * Required for COASCO compliance and BOT regulatory audit.
 */
@Entity
@Table(name = "auth_audit_logs")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class AuthAuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    private UUID userId;
    private String username;
    private String saccoCode;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AuditAction action;

    private boolean success;
    private String failureReason;

    private String ipAddress;
    private String userAgent;
    private String deviceInfo;

    // What changed (for USER_UPDATED, ROLE_ASSIGNED etc.)
    private String details;

    // Who performed the action (for admin actions)
    private UUID performedBy;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;
}
