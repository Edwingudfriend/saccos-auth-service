package com.reimagineafrica.auth.dto.request;

import com.reimagineafrica.auth.enums.Role;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;

import java.util.Set;
import java.util.UUID;

@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class CreateUserRequest {
    @NotBlank private String saccoCode;
    @NotBlank private String phone;
    @NotBlank private String fullName;
    private String email;
    private Set<Role> roles;
    private UUID memberId;
    private String memberNumber;
    private String temporaryPassword;
}
