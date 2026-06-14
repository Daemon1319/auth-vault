package com.allan.authvault.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.HexFormat;

@Service
public class JwtService {

  private final SecretKey secretKey;
  private final long accessTokenExpiryMs;

  // Constructor-based injection of properties
  public JwtService(
      @Value("${jwt.secret}") String secret,
      @Value("${jwt.access-token-expiry-ms}") long accessTokenExpiryMs) {
    
    // THE FIX: Validate cryptographic strength at startup
    if (secret == null || secret.getBytes(StandardCharsets.UTF_8).length < 32) {
      throw new IllegalStateException("CRITICAL SECURITY ERROR: jwt.secret must be at least 32 bytes (characters) long for HS256.");
    }
    
    this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    this.accessTokenExpiryMs = accessTokenExpiryMs;
  }

  /**
   * Generates a stateless short-lived Access Token using JJWT 0.13.0 signatures.
   */
  public String generateAccessToken(String username, String role) {
    long now = System.currentTimeMillis();
    return Jwts.builder()
        .subject(username)
        .claim("role", role)
        .issuedAt(new Date(now))
        .expiration(new Date(now + accessTokenExpiryMs))
        .signWith(secretKey, Jwts.SIG.HS256)
        .compact();
  }

  /**
   * Extracts the subject (username) from a given Access Token.
   */
  public String extractUsername(String token) {
    return extractAllClaims(token).getSubject();
  }

  /**
   * Extracts custom claims (role) from a given Access Token.
   */
  public String extractRole(String token) {
    return extractAllClaims(token).get("role", String.class);
  }

  /**
   * Validates if the token signature is intact and has not expired.
   */
  public boolean isTokenValid(String token) {
    try {
      return !extractAllClaims(token).getExpiration().before(new Date());
    } catch (Exception e) {
      return false;
    }
  }

  /**
   * Strictly processes token parsing using the modernized verifyWith chain.
   */
  private Claims extractAllClaims(String token) {
    return Jwts.parser()
        .verifyWith(secretKey)
        .build()
        .parseSignedClaims(token)
        .getPayload();
  }

  /**
   * Helper utility to safely compute a deterministic SHA-256 hash of a token string.
   * This shields your database from storing plain text refresh token payloads.
   */
  public String hashToken(String token) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hashBytes = digest.digest(token.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(hashBytes);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 algorithm instance missing from runtime environment", e);
    }
  }
}