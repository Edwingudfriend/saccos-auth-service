package com.reimagineafrica.auth.service;

import com.reimagineafrica.auth.dto.request.*;
import com.reimagineafrica.auth.dto.response.AuthResponse;
import com.reimagineafrica.auth.entity.RefreshToken;
import com.reimagineafrica.auth.entity.User;
import com.reimagineafrica.auth.enums.AuditAction;
import com.reimagineafrica.auth.enums.UserStatus;
import com.reimagineafrica.auth.event.AuthEventPublisher;
import com.reimagineafrica.auth.exception.AuthException;
import com.reimagineafrica.auth.repository.RefreshTokenRepository;
import com.reimagineafrica.auth.repository.UserRepository;
import com.reimagineafrica.auth.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuditService auditService;
    private final AuthEventPublisher eventPublisher;
    private final RedisTemplate<String, String> redisTemplate;

    @Value("${security.max-failed-attempts:5}")
    private int maxFailedAttempts;

    @Value("${security.lockout-minutes:30}")
    private int lockoutMinutes;

    private static final String BLACKLIST_PREFIX = "jwt:blacklist:";

    // ── Login ────────────────────────────────────────────────────────

    @Transactional
    public AuthResponse login(LoginRequest request, String ipAddress, String userAgent) {
        User user = userRepository.findByUsernameAndSaccoCode(request.getUsername(), request.getSaccoCode())
                .orElseThrow(() -> {
                    auditService.log(null, request.getUsername(), request.getSaccoCode(),
                            AuditAction.LOGIN_FAILED, false, "User not found", ipAddress, userAgent);
                    return new AuthException("Invalid credentials.");
                });

        // Check account status
        if (user.isLocked()) {
            throw new AuthException("Account is locked. Try again after " + user.getLockedUntil());
        }
        if (user.getStatus() == UserStatus.SUSPENDED) {
            throw new AuthException("Account is suspended. Contact your SACCO administrator.");
        }
        if (user.getStatus() == UserStatus.INACTIVE) {
            throw new AuthException("Account is inactive.");
        }

        // Validate password
        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            handleFailedAttempt(user, ipAddress, userAgent);
            throw new AuthException("Invalid credentials.");
        }

        // Reset failed attempts on successful login
        user.setFailedLoginAttempts(0);
        user.setLastLoginAt(LocalDateTime.now());
        user.setLastLoginIp(ipAddress);
        userRepository.save(user);

        // Generate tokens
        String accessToken = jwtUtil.generateAccessToken(user);
        String refreshTokenValue = jwtUtil.generateRefreshToken();

        // Persist refresh token
        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(refreshTokenValue)
                .expiresAt(LocalDateTime.now().plusDays(jwtUtil.getRefreshTokenExpiryDays()))
                .deviceInfo(userAgent)
                .ipAddress(ipAddress)
                .build();
        refreshTokenRepository.save(refreshToken);

        auditService.log(user.getId(), user.getUsername(), user.getSaccoCode(),
                AuditAction.LOGIN_SUCCESS, true, null, ipAddress, userAgent);

        log.info("User {} logged in from {}", user.getUsername(), ipAddress);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshTokenValue)
                .tokenType("Bearer")
                .expiresIn(jwtUtil.getAccessTokenExpirySeconds())
                .userId(user.getId())
                .username(user.getUsername())
                .fullName(user.getFullName())
                .saccoCode(user.getSaccoCode())
                .roles(user.getRoles().stream().map(Enum::name).toList())
                .memberId(user.getMemberId())
                .memberNumber(user.getMemberNumber())
                .mustChangePassword(user.isMustChangePassword())
                .build();
    }

    // ── Refresh token ────────────────────────────────────────────────

    @Transactional
    public AuthResponse refresh(String refreshTokenValue, String ipAddress) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(refreshTokenValue)
                .orElseThrow(() -> new AuthException("Invalid refresh token."));

        if (!refreshToken.isValid()) {
            throw new AuthException("Refresh token is expired or revoked.");
        }

        User user = refreshToken.getUser();

        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new AuthException("Account is not active.");
        }

        // Rotate refresh token — revoke old, issue new
        refreshToken.setRevoked(true);
        refreshToken.setRevokedReason("ROTATED");
        refreshTokenRepository.save(refreshToken);

        String newRefreshTokenValue = jwtUtil.generateRefreshToken();
        RefreshToken newRefreshToken = RefreshToken.builder()
                .user(user)
                .token(newRefreshTokenValue)
                .expiresAt(LocalDateTime.now().plusDays(jwtUtil.getRefreshTokenExpiryDays()))
                .ipAddress(ipAddress)
                .build();
        refreshTokenRepository.save(newRefreshToken);

        String newAccessToken = jwtUtil.generateAccessToken(user);

        auditService.log(user.getId(), user.getUsername(), user.getSaccoCode(),
                AuditAction.TOKEN_REFRESHED, true, null, ipAddress, null);

        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshTokenValue)
                .tokenType("Bearer")
                .expiresIn(jwtUtil.getAccessTokenExpirySeconds())
                .userId(user.getId())
                .username(user.getUsername())
                .fullName(user.getFullName())
                .saccoCode(user.getSaccoCode())
                .roles(user.getRoles().stream().map(Enum::name).toList())
                .build();
    }

    // ── Logout ───────────────────────────────────────────────────────

    @Transactional
    public void logout(String accessToken, String refreshTokenValue, String ipAddress) {
        // Blacklist the access token in Redis until it expires
        blacklistAccessToken(accessToken);

        // Revoke refresh token
        refreshTokenRepository.findByToken(refreshTokenValue).ifPresent(rt -> {
            rt.setRevoked(true);
            rt.setRevokedReason("LOGOUT");
            refreshTokenRepository.save(rt);
        });

        String userId = jwtUtil.extractUserId(accessToken);
        userRepository.findById(java.util.UUID.fromString(userId)).ifPresent(user ->
                auditService.log(user.getId(), user.getUsername(), user.getSaccoCode(),
                        AuditAction.LOGOUT, true, null, ipAddress, null));

        log.info("User {} logged out", userId);
    }

    // ── Password reset via SMS OTP ───────────────────────────────────

    @Transactional
    public void requestPasswordReset(String phone) {
        User user = userRepository.findByPhone(phone)
                .orElseThrow(() -> new AuthException("No account registered with this phone number."));

        // Generate 6-digit OTP
        String otp = String.format("%06d", (int)(Math.random() * 1000000));
        user.setPasswordResetOtp(passwordEncoder.encode(otp));
        user.setPasswordResetOtpExpiry(LocalDateTime.now().plusMinutes(15));
        userRepository.save(user);

        // Publish event — notification-service sends the OTP via SMS
        eventPublisher.publishPasswordResetOtp(user.getPhone(), user.getFullName(), otp);

        auditService.log(user.getId(), user.getUsername(), user.getSaccoCode(),
                AuditAction.PASSWORD_RESET_REQUESTED, true, null, null, null);

        log.info("Password reset OTP sent to {}", maskPhone(phone));
    }

    @Transactional
    public void resetPassword(ResetPasswordRequest request) {
        User user = userRepository.findByPhone(request.getPhone())
                .orElseThrow(() -> new AuthException("Invalid request."));

        if (user.getPasswordResetOtp() == null
                || user.getPasswordResetOtpExpiry() == null
                || LocalDateTime.now().isAfter(user.getPasswordResetOtpExpiry())) {
            throw new AuthException("OTP has expired. Request a new one.");
        }

        if (!passwordEncoder.matches(request.getOtp(), user.getPasswordResetOtp())) {
            throw new AuthException("Invalid OTP.");
        }

        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        user.setPasswordResetOtp(null);
        user.setPasswordResetOtpExpiry(null);
        user.setPasswordChangedAt(LocalDateTime.now());
        user.setMustChangePassword(false);
        userRepository.save(user);

        // Revoke all existing refresh tokens (force re-login everywhere)
        refreshTokenRepository.revokeAllUserTokens(user.getId(), "PASSWORD_RESET");

        auditService.log(user.getId(), user.getUsername(), user.getSaccoCode(),
                AuditAction.PASSWORD_RESET_COMPLETED, true, null, null, null);

        log.info("Password reset completed for user {}", user.getUsername());
    }

    @Transactional
    public void changePassword(ChangePasswordRequest request, String userId) {
        User user = userRepository.findById(java.util.UUID.fromString(userId))
                .orElseThrow(() -> new AuthException("User not found."));

        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPasswordHash())) {
            throw new AuthException("Current password is incorrect.");
        }

        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        user.setPasswordChangedAt(LocalDateTime.now());
        user.setMustChangePassword(false);
        userRepository.save(user);

        // Revoke all refresh tokens except current session
        refreshTokenRepository.revokeAllUserTokens(user.getId(), "PASSWORD_CHANGE");

        auditService.log(user.getId(), user.getUsername(), user.getSaccoCode(),
                AuditAction.PASSWORD_CHANGED, true, null, null, null);
    }

    // ── Token validation endpoint (for other services) ───────────────

    public boolean validateToken(String token) {
        if (!jwtUtil.validateToken(token)) return false;
        // Check Redis blacklist
        String blacklistKey = BLACKLIST_PREFIX + token.substring(token.length() - 20);
        return Boolean.FALSE.equals(redisTemplate.hasKey(blacklistKey));
    }

    // ── Private helpers ──────────────────────────────────────────────

    private void handleFailedAttempt(User user, String ipAddress, String userAgent) {
        user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);

        if (user.getFailedLoginAttempts() >= maxFailedAttempts) {
            user.setStatus(UserStatus.LOCKED);
            user.setLockedUntil(LocalDateTime.now().plusMinutes(lockoutMinutes));
            log.warn("User {} locked after {} failed attempts", user.getUsername(), maxFailedAttempts);
            auditService.log(user.getId(), user.getUsername(), user.getSaccoCode(),
                    AuditAction.ACCOUNT_LOCKED, true,
                    "Locked after " + maxFailedAttempts + " failed attempts", ipAddress, userAgent);
        } else {
            auditService.log(user.getId(), user.getUsername(), user.getSaccoCode(),
                    AuditAction.LOGIN_FAILED, false, "Invalid password", ipAddress, userAgent);
        }

        userRepository.save(user);
    }

    private void blacklistAccessToken(String token) {
        try {
            long expirySeconds = (jwtUtil.extractExpiry(token).getTime() - System.currentTimeMillis()) / 1000;
            if (expirySeconds > 0) {
                String key = BLACKLIST_PREFIX + token.substring(token.length() - 20);
                redisTemplate.opsForValue().set(key, "blacklisted", expirySeconds, TimeUnit.SECONDS);
            }
        } catch (Exception e) {
            log.warn("Could not blacklist token: {}", e.getMessage());
        }
    }

    private String maskPhone(String phone) {
        if (phone == null || phone.length() < 6) return "***";
        return phone.substring(0, 3) + "***" + phone.substring(phone.length() - 3);
    }
}
