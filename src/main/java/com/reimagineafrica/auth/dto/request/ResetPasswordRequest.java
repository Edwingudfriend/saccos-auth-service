package com.reimagineafrica.auth.dto.request;
import jakarta.validation.constraints.*;
import lombok.*;
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class ResetPasswordRequest {
    @NotBlank private String phone;
    @NotBlank private String otp;
    @NotBlank @Size(min=8) private String newPassword;
}
