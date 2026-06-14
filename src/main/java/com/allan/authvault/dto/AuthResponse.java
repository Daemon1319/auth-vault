package com.allan.authvault.dto;

public record AuthResponse(
  String accessToken,
  String username,
  String role
) {}
