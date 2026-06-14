package com.allan.authvault.exception;

import io.jsonwebtoken.JwtException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

  @ExceptionHandler(IllegalArgumentException.class)
  public ResponseEntity<Map<String, String>> handleIllegalArgument(IllegalArgumentException ex) {
    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
        .body(Map.of("error", "Bad Request", "message", ex.getMessage()));
  }

  @ExceptionHandler(SecurityException.class)
  public ResponseEntity<Map<String, String>> handleSecurityException(SecurityException ex) {
    // Returns 403 Forbidden specifically for token theft or unauthorized access
    return ResponseEntity.status(HttpStatus.FORBIDDEN)
        .body(Map.of("error", "Security Breach / Forbidden", "message", ex.getMessage()));
  }

  // THE FIX: Catch malformed JSON requests (e.g., missing commas, wrong data types)
  @ExceptionHandler(HttpMessageNotReadableException.class)
  public ResponseEntity<Map<String, String>> handleMalformedBody(HttpMessageNotReadableException ex) {
    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
        .body(Map.of("error", "Bad Request", "message", "Malformed or unreadable request body"));
  }

  // THE FIX: Catch invalid, tampered, or structurally broken JWT tokens
  @ExceptionHandler(JwtException.class)
  public ResponseEntity<Map<String, String>> handleJwtException(JwtException ex) {
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
        .body(Map.of("error", "Unauthorized", "message", "Invalid or malformed token"));
  }

  @ExceptionHandler(Exception.class)
  public ResponseEntity<Map<String, String>> handleGeneralException(Exception ex) {
    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
        .body(Map.of("error", "Internal Server Error", "message", "An unexpected error occurred"));
  }
}