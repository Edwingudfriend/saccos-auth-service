package com.reimagineafrica.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class LoginRequest {
    @NotBlank private String username;
    @NotBlank private String password;
    @NotBlank private String saccoCode;
}
