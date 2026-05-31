package com.reimagineafrica.auth.repository;

import com.reimagineafrica.auth.entity.User;
import com.reimagineafrica.auth.enums.UserStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByUsernameAndSaccoCode(String username, String saccoCode);

    Optional<User> findByPhone(String phone);

    Optional<User> findByMemberId(UUID memberId);

    boolean existsByPhoneAndSaccoCode(String phone, String saccoCode);

    Page<User> findBySaccoCode(String saccoCode, Pageable pageable);

    Page<User> findBySaccoCodeAndStatus(String saccoCode, UserStatus status, Pageable pageable);
}
