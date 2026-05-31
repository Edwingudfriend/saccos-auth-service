package com.reimagineafrica.auth.util;

import com.reimagineafrica.auth.entity.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

@Component
@Slf4j
public class JwtUtil {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.access-token-expiry-minutes:60}")
    private long accessTokenExpiryMinutes;

    @Value("${jwt.refresh-token-expiry-days:7}")
    private long refreshTokenExpiryDays;

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Generate access token — short-lived, carries all claims needed by downstream services.
     *
     * Claims included:
     * - sub: userId
     * - username: login username
     * - saccoCode: which SACCO this user belongs to
     * - roles: list of roles e.g. ["MEMBER", "COMMITTEE_MEMBER"]
     * - memberId: UUID of member record (for MEMBER role users)
     * - fullName: display name
     */
    public String generateAccessToken(User user) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + accessTokenExpiryMinutes * 60 * 1000);

        List<String> roleNames = user.getRoles().stream()
                .map(Enum::name)
                .collect(Collectors.toList());

        Map<String, Object> claims = new HashMap<>();
        claims.put("username", user.getUsername());
        claims.put("saccoCode", user.getSaccoCode());
        claims.put("roles", roleNames);
        claims.put("fullName", user.getFullName());
        claims.put("phone", user.getPhone());

        if (user.getMemberId() != null) {
            claims.put("memberId", user.getMemberId().toString());
            claims.put("memberNumber", user.getMemberNumber());
        }

        return Jwts.builder()
                .subject(user.getId().toString())
                .claims(claims)
                .issuedAt(now)
                .expiration(expiry)
                .issuer("saccos-auth-service")
                .signWith(getSigningKey())
                .compact();
    }

    /**
     * Generate refresh token — opaque UUID stored in DB.
     * Not a JWT — just a random token that maps to a user session.
     */
    public String generateRefreshToken() {
        return UUID.randomUUID().toString() + "-" + UUID.randomUUID().toString();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().verifyWith(getSigningKey()).build().parseSignedClaims(token);
            return true;
        } catch (ExpiredJwtException e) {
            log.warn("JWT expired: {}", e.getMessage());
        } catch (JwtException e) {
            log.warn("Invalid JWT: {}", e.getMessage());
        }
        return false;
    }

    public Claims extractClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String extractUserId(String token) {
        return extractClaims(token).getSubject();
    }

    public String extractSaccoCode(String token) {
        return (String) extractClaims(token).get("saccoCode");
    }

    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) {
        return (List<String>) extractClaims(token).get("roles");
    }

    public Date extractExpiry(String token) {
        return extractClaims(token).getExpiration();
    }

    public long getAccessTokenExpirySeconds() {
        return accessTokenExpiryMinutes * 60;
    }

    public long getRefreshTokenExpiryDays() {
        return refreshTokenExpiryDays;
    }
}
