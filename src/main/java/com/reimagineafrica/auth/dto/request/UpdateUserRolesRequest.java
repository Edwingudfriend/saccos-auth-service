package com.reimagineafrica.auth.dto.request;
import com.reimagineafrica.auth.enums.Role;
import jakarta.validation.constraints.NotNull;
import lombok.*;
import java.util.Set;
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class UpdateUserRolesRequest { @NotNull private Set<Role> roles; }
