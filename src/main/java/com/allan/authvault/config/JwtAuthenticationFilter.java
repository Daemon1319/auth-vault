package com.allan.authvault.config;

import com.allan.authvault.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  // THE FIX: Added an SLF4J logger for visibility
  private static final Logger filterLogger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

  private final JwtService jwtService;

  public JwtAuthenticationFilter(JwtService jwtService) {
    this.jwtService = jwtService;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request,
      HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {

    final String authHeader = request.getHeader("Authorization");

    // Skip if no bearer token is present (e.g., login/register endpoints)
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      filterChain.doFilter(request, response);
      return;
    }

    try {
      final String jwt = authHeader.substring(7);
      final String username = jwtService.extractUsername(jwt);

      // Proceed only if token is valid and context is not already authenticated
      if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
        if (jwtService.isTokenValid(jwt)) {
          
          String role = jwtService.extractRole(jwt);
          // Spring Security requires the ROLE_ prefix for hasRole() matchers
          SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_" + role);

          UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
              username,
              null,
              Collections.singletonList(authority)
          );
          authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
          SecurityContextHolder.getContext().setAuthentication(authToken);
        }
      }
    } catch (Exception e) {
      // THE FIX: Log the actual error message so it doesn't fail silently
      filterLogger.warn("JWT Validation failed for request {}: {}", request.getRequestURI(), e.getMessage());
      SecurityContextHolder.clearContext();
    }

    filterChain.doFilter(request, response);
  }
}