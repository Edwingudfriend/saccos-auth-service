package com.reimagineafrica.auth.dto.response;

import lombok.*;
import java.util.List;
import java.util.UUID;

@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class AuthResponse {
    private String accessToken;
    private String refreshToken;
    private String tokenType;
    private long expiresIn;
    private UUID userId;
    private String username;
    private String fullName;
    private String saccoCode;
    private List<String> roles;
    private UUID memberId;
    private String memberNumber;
    private boolean mustChangePassword;
}
