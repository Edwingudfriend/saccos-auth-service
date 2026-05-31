package com.reimagineafrica.auth.entity;

import com.reimagineafrica.auth.enums.Role;
import com.reimagineafrica.auth.enums.UserStatus;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Entity
@Table(name = "users",
       uniqueConstraints = {
           @UniqueConstraint(columnNames = {"username", "sacco_code"}),
           @UniqueConstraint(columnNames = "phone")
       })
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    // Multi-tenant — username is unique per SACCO
    @Column(nullable = false)
    private String saccoCode;

    @Column(nullable = false)
    private String username;         // phone number or staff ID

    @Column(nullable = false, unique = true)
    private String phone;            // Primary identifier for SMS OTP

    private String email;

    @Column(nullable = false)
    private String fullName;

    @Column(nullable = false)
    private String passwordHash;

    // Roles — a user can have multiple roles
    @ElementCollection(targetClass = Role.class, fetch = FetchType.EAGER)
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Enumerated(EnumType.STRING)
    @Column(name = "role")
    @Builder.Default
    private Set<Role> roles = new HashSet<>();

    // Link to member-service (for MEMBER role users)
    private UUID memberId;
    private String memberNumber;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @Builder.Default
    private UserStatus status = UserStatus.ACTIVE;

    // Security tracking
    @Builder.Default
    private int failedLoginAttempts = 0;

    private LocalDateTime lockedUntil;
    private LocalDateTime lastLoginAt;
    private String lastLoginIp;
    private LocalDateTime passwordChangedAt;
    private boolean mustChangePassword;

    // Password reset
    private String passwordResetOtp;
    private LocalDateTime passwordResetOtpExpiry;

    @CreationTimestamp
    private LocalDateTime createdAt;

    @UpdateTimestamp
    private LocalDateTime updatedAt;

    private String createdBy;

    // ── UserDetails implementation ───────────────────────────────────

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.name()))
                .collect(Collectors.toSet());
    }

    @Override
    public String getPassword() { return passwordHash; }

    @Override
    public boolean isAccountNonExpired() { return true; }

    @Override
    public boolean isAccountNonLocked() {
        if (status == UserStatus.LOCKED) {
            return lockedUntil != null && LocalDateTime.now().isAfter(lockedUntil);
        }
        return status != UserStatus.SUSPENDED;
    }

    @Override
    public boolean isCredentialsNonExpired() { return true; }

    @Override
    public boolean isEnabled() {
        return status == UserStatus.ACTIVE || status == UserStatus.PENDING_SETUP;
    }

    // ── Helpers ──────────────────────────────────────────────────────

    public boolean hasRole(Role role) {
        return roles.contains(role);
    }

    public boolean isLocked() {
        return status == UserStatus.LOCKED
                && lockedUntil != null
                && LocalDateTime.now().isBefore(lockedUntil);
    }
}
