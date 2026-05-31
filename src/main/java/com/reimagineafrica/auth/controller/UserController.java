package com.reimagineafrica.auth.controller;

import com.reimagineafrica.auth.dto.request.CreateUserRequest;
import com.reimagineafrica.auth.dto.request.UpdateUserRolesRequest;
import com.reimagineafrica.auth.entity.User;
import com.reimagineafrica.auth.service.UserManagementService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserManagementService userManagementService;

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<User> createUser(
            @Valid @RequestBody CreateUserRequest request,
            @AuthenticationPrincipal String userId) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(userManagementService.createUser(request, userId));
    }

    @GetMapping("/sacco/{saccoCode}")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    public ResponseEntity<Page<User>> getUsersBySacco(
            @PathVariable String saccoCode, Pageable pageable) {
        return ResponseEntity.ok(userManagementService.getUsersBySacco(saccoCode, pageable));
    }

    @GetMapping("/{userId}")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER') or #userId == authentication.principal")
    public ResponseEntity<User> getUser(@PathVariable UUID userId) {
        return ResponseEntity.ok(userManagementService.findById(userId));
    }

    @PutMapping("/{userId}/roles")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<User> updateRoles(
            @PathVariable UUID userId,
            @Valid @RequestBody UpdateUserRolesRequest request,
            @AuthenticationPrincipal String performedBy) {
        return ResponseEntity.ok(
                userManagementService.updateRoles(userId, request, UUID.fromString(performedBy)));
    }

    @PostMapping("/{userId}/suspend")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> suspend(
            @PathVariable UUID userId,
            @RequestParam String reason,
            @AuthenticationPrincipal String performedBy) {
        userManagementService.suspendUser(userId, reason, UUID.fromString(performedBy));
        return ResponseEntity.ok().build();
    }

    @PostMapping("/{userId}/unlock")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> unlock(
            @PathVariable UUID userId,
            @AuthenticationPrincipal String performedBy) {
        userManagementService.unlockUser(userId, UUID.fromString(performedBy));
        return ResponseEntity.ok().build();
    }
}
