package com.reimagineafrica.auth.service;

import com.reimagineafrica.auth.dto.request.CreateUserRequest;
import com.reimagineafrica.auth.dto.request.UpdateUserRolesRequest;
import com.reimagineafrica.auth.entity.User;
import com.reimagineafrica.auth.enums.AuditAction;
import com.reimagineafrica.auth.enums.Role;
import com.reimagineafrica.auth.enums.UserStatus;
import com.reimagineafrica.auth.event.AuthEventPublisher;
import com.reimagineafrica.auth.exception.AuthException;
import com.reimagineafrica.auth.repository.RefreshTokenRepository;
import com.reimagineafrica.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserManagementService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;
    private final AuthEventPublisher eventPublisher;

    @Transactional
    public User createUser(CreateUserRequest request, String createdBy) {
        if (userRepository.existsByPhoneAndSaccoCode(request.getPhone(), request.getSaccoCode())) {
            throw new AuthException("A user with this phone number already exists in " + request.getSaccoCode());
        }

        // Generate a temporary password if not provided
        String tempPassword = request.getTemporaryPassword() != null
                ? request.getTemporaryPassword()
                : generateTempPassword();

        User user = User.builder()
                .saccoCode(request.getSaccoCode())
                .username(request.getPhone()) // Phone as default username
                .phone(request.getPhone())
                .email(request.getEmail())
                .fullName(request.getFullName())
                .passwordHash(passwordEncoder.encode(tempPassword))
                .roles(request.getRoles() != null ? request.getRoles() : Set.of(Role.MEMBER))
                .memberId(request.getMemberId())
                .memberNumber(request.getMemberNumber())
                .status(UserStatus.ACTIVE)
                .mustChangePassword(true)  // Force password change on first login
                .createdBy(createdBy)
                .build();

        userRepository.save(user);

        // Send credentials via SMS
        eventPublisher.publishUserCreated(user.getPhone(), user.getFullName(),
                user.getUsername(), tempPassword);

        auditService.log(user.getId(), user.getUsername(), user.getSaccoCode(),
                AuditAction.USER_CREATED, true,
                "Roles: " + user.getRoles(), null, null);

        log.info("User created: {} in SACCO {}", user.getUsername(), user.getSaccoCode());
        return user;
    }

    @Transactional
    public User updateRoles(UUID userId, UpdateUserRolesRequest request, UUID performedBy) {
        User user = findById(userId);

        Set<Role> oldRoles = user.getRoles();
        user.setRoles(request.getRoles());
        userRepository.save(user);

        // Revoke all tokens — user must re-login with new roles
        refreshTokenRepository.revokeAllUserTokens(userId, "ROLE_CHANGE");

        auditService.log(userId, user.getUsername(), user.getSaccoCode(),
                AuditAction.ROLE_ASSIGNED, true,
                "Old: " + oldRoles + " → New: " + request.getRoles(), null, null);

        log.info("Roles updated for user {}: {}", user.getUsername(), request.getRoles());
        return user;
    }

    @Transactional
    public void suspendUser(UUID userId, String reason, UUID performedBy) {
        User user = findById(userId);
        user.setStatus(UserStatus.SUSPENDED);
        userRepository.save(user);

        // Revoke all sessions
        refreshTokenRepository.revokeAllUserTokens(userId, "ACCOUNT_SUSPENDED");

        auditService.log(userId, user.getUsername(), user.getSaccoCode(),
                AuditAction.ACCOUNT_SUSPENDED, true, reason, null, null);
    }

    @Transactional
    public void unlockUser(UUID userId, UUID performedBy) {
        User user = findById(userId);
        user.setStatus(UserStatus.ACTIVE);
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        userRepository.save(user);

        auditService.log(userId, user.getUsername(), user.getSaccoCode(),
                AuditAction.ACCOUNT_UNLOCKED, true, "Unlocked by admin", null, null);
    }

    public Page<User> getUsersBySacco(String saccoCode, Pageable pageable) {
        return userRepository.findBySaccoCode(saccoCode, pageable);
    }

    public User findById(UUID userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new AuthException("User not found: " + userId));
    }

    private String generateTempPassword() {
        // 8-character alphanumeric temp password
        String chars = "ABCDEFGHIJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            sb.append(chars.charAt((int)(Math.random() * chars.length())));
        }
        return sb.toString();
    }
}
