package com.allan.authvault.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
  @NotBlank(message = "Username cannot be blank") String username,

  @NotBlank(message = "Password cannot be blank") @Size(min = 6, message = "Password must be at least 6 characters long") String password,

  @NotBlank(message = "Role cannot be blank") String role) {
}