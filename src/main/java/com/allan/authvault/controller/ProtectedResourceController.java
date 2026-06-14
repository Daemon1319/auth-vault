package com.allan.authvault.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class ProtectedResourceController {
  @GetMapping("/public/status")
  public ResponseEntity<Map<String, String>> getPublicStatus() {
    return ResponseEntity.ok(Map.of(
        "status", "success",
        "message", "System is online. This is a public endpoint, no token required."
    ));
  }

  // Accessible to any authenticated user (ROLE_USER or ROLE_ADMIN)
  @GetMapping("/user/dashboard")
  public ResponseEntity<Map<String, String>> getUserDashboard() {
    return ResponseEntity.ok(Map.of(
        "status", "success",
        "message", "Welcome to the User Dashboard. Your access token is valid."
    ));
  }

  // Strictly restricted to users with ROLE_ADMIN via SecurityConfig
  @GetMapping("/admin/settings")
  public ResponseEntity<Map<String, String>> getAdminSettings() {
    return ResponseEntity.ok(Map.of(
        "status", "success",
        "message", "Welcome to the Admin Vault. You have verified ROLE_ADMIN privileges."
    ));
  }
}