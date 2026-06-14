package com.allan.authvault.service;

import com.allan.authvault.dto.AuthRequest;
import com.allan.authvault.dto.AuthResponse;
import com.allan.authvault.dto.RegisterRequest;
import com.allan.authvault.entity.RefreshToken;
import com.allan.authvault.entity.User;
import com.allan.authvault.repository.RefreshTokenRepository;
import com.allan.authvault.repository.UserRepository;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class AuthService {

  private final UserRepository userRepository;
  private final RefreshTokenRepository refreshTokenRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;
  private final long refreshTokenExpiryMs;

  @Value("${app.cookie.secure:false}")
  private boolean secureCookie;

  @Value("${app.cookie.same-site:Lax}")
  private String cookieSameSite;

  public AuthService(
      UserRepository userRepository,
      RefreshTokenRepository refreshTokenRepository,
      PasswordEncoder passwordEncoder,
      JwtService jwtService,
      @Value("${jwt.refresh-token-expiry-ms}") long refreshTokenExpiryMs) {
    this.userRepository = userRepository;
    this.refreshTokenRepository = refreshTokenRepository;
    this.passwordEncoder = passwordEncoder;
    this.jwtService = jwtService;
    this.refreshTokenExpiryMs = refreshTokenExpiryMs;
  }

  @Transactional
  public AuthResponse register(RegisterRequest request, HttpServletResponse response) {
    if (userRepository.findByUsername(request.username()).isPresent()) {
      throw new IllegalArgumentException("Username is already taken");
    }

    // THE FIX: Explicit Role Whitelisting
    String requestedRole = request.role().toUpperCase();
    if (!requestedRole.equals("USER") && !requestedRole.equals("ADMIN")) {
      throw new IllegalArgumentException("Invalid role. Must be USER or ADMIN");
    }

    User user = new User(
        request.username(),
        passwordEncoder.encode(request.password()),
        requestedRole,
        Instant.now()
    );
    userRepository.save(user);

    return generateAuthSession(user, UUID.randomUUID(), response);
  }

  @Transactional
  public AuthResponse authenticate(AuthRequest request, HttpServletResponse response) {
    Optional<User> userOptional = userRepository.findByUsername(request.username());

    if (userOptional.isEmpty()) {
      // Timing attack mitigation: process a fake hash to equalize response times
      passwordEncoder.matches(request.password(), "$2a$10$abcdefghijklmnopqrstuv");
      throw new IllegalArgumentException("Invalid username or password");
    }

    User user = userOptional.get();
    if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
      throw new IllegalArgumentException("Invalid username or password");
    }

    return generateAuthSession(user, UUID.randomUUID(), response);
  }

  @Transactional
  public AuthResponse refreshToken(String rawRefreshToken, HttpServletResponse response) {
    String tokenHash = jwtService.hashToken(rawRefreshToken);
    RefreshToken storedToken = refreshTokenRepository.findByTokenHash(tokenHash)
        .orElseThrow(() -> new IllegalArgumentException("Invalid refresh token"));

    User user = storedToken.getUser();

    // THEFT DETECTION: If token is already used, invalidate the entire family
    if (storedToken.isUsed()) {
      refreshTokenRepository.revokeAllByFamilyId(storedToken.getFamilyId());
      throw new SecurityException("Token reuse detected. Session terminated.");
    }

    // Expiration check MUST happen before marking as used
    if (storedToken.getExpiresAt().isBefore(Instant.now())) {
      throw new IllegalArgumentException("Refresh token has expired");
    }

    // Now it is safe to mark current token as used
    storedToken.setUsed(true);
    refreshTokenRepository.save(storedToken);

    // Issue new tokens maintaining the same family lineage
    return generateAuthSession(user, storedToken.getFamilyId(), response);
  }

  @Transactional
  public void logout(String rawRefreshToken, HttpServletResponse response) {
    if (rawRefreshToken != null) {
      String tokenHash = jwtService.hashToken(rawRefreshToken);
      refreshTokenRepository.findByTokenHash(tokenHash).ifPresent(token -> {
        refreshTokenRepository.revokeAllByFamilyId(token.getFamilyId());
      });
    }
    // Clear the cookie on the client side
    ResponseCookie cookie = ResponseCookie.from("refresh_token", "")
        .httpOnly(true)
        .secure(secureCookie)
        .sameSite(cookieSameSite)
        .path("/api/auth/refresh")
        .maxAge(0) // Expire instantly
        .build();
    response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
  }

  private AuthResponse generateAuthSession(User user, UUID familyId, HttpServletResponse response) {
    String accessToken = jwtService.generateAccessToken(user.getUsername(), user.getRole());
    
    // Generate a secure, random refresh token string
    String rawRefreshToken = UUID.randomUUID().toString() + "-" + UUID.randomUUID().toString();
    String tokenHash = jwtService.hashToken(rawRefreshToken);

    RefreshToken refreshToken = new RefreshToken(
        user,
        tokenHash,
        familyId,
        false,
        Instant.now().plusSeconds(refreshTokenExpiryMs / 1000),
        Instant.now()
    );
    refreshTokenRepository.save(refreshToken);

    // Set the HttpOnly cookie
    ResponseCookie cookie = ResponseCookie.from("refresh_token", rawRefreshToken)
        .httpOnly(true)
        .secure(secureCookie)
        .sameSite(cookieSameSite)
        .path("/api/auth/refresh")
        .maxAge(refreshTokenExpiryMs / 1000)
        .build();
    response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

    return new AuthResponse(accessToken, user.getUsername(), user.getRole());
  }
}