package com.allan.authvault.controller;

import com.allan.authvault.dto.AuthRequest;
import com.allan.authvault.dto.AuthResponse;
import com.allan.authvault.dto.RegisterRequest;
import com.allan.authvault.service.AuthService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

  private final AuthService authService;

  public AuthController(AuthService authService) {
    this.authService = authService;
  }

  @PostMapping("/register")
  public ResponseEntity<AuthResponse> register(
      @Valid @RequestBody RegisterRequest request,
      HttpServletResponse response) {
    return ResponseEntity.ok(authService.register(request, response));
  }

  @PostMapping("/login")
  public ResponseEntity<AuthResponse> login(
      @Valid @RequestBody AuthRequest request,
      HttpServletResponse response) {
    return ResponseEntity.ok(authService.authenticate(request, response));
  }

  @PostMapping("/refresh")
  public ResponseEntity<AuthResponse> refresh(
      @CookieValue(name = "refresh_token", required = false) String refreshToken,
      HttpServletResponse response) {
    
    if (refreshToken == null || refreshToken.isBlank()) {
      throw new IllegalArgumentException("Refresh token is missing from cookies");
    }
    
    return ResponseEntity.ok(authService.refreshToken(refreshToken, response));
  }

  @PostMapping("/logout")
  public ResponseEntity<Map<String, String>> logout(
      @CookieValue(name = "refresh_token", required = false) String refreshToken,
      HttpServletResponse response) {
    
    authService.logout(refreshToken, response);
    return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
  }
}