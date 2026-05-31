package com.reimagineafrica.auth.dto.request;
import jakarta.validation.constraints.*;
import lombok.*;
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class ChangePasswordRequest {
    @NotBlank private String currentPassword;
    @NotBlank @Size(min=8) private String newPassword;
}
