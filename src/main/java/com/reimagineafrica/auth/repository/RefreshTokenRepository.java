package com.reimagineafrica.auth.repository;

import com.reimagineafrica.auth.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByToken(String token);

    @Modifying
    @Query("UPDATE RefreshToken r SET r.revoked = true, r.revokedReason = :reason WHERE r.user.id = :userId AND r.revoked = false")
    void revokeAllUserTokens(UUID userId, String reason);

    long countByUserIdAndRevokedFalse(UUID userId);
}
