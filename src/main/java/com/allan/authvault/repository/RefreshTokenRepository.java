package com.allan.authvault.repository;

import com.allan.authvault.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

  Optional<RefreshToken> findByTokenHash(String tokenHash);

  // THE FIX: Highly efficient SQL update to prevent memory leaks during theft revocation
  @Modifying
  @Query("UPDATE RefreshToken t SET t.used = true WHERE t.familyId = :familyId AND t.used = false")
  void revokeAllByFamilyId(@Param("familyId") UUID familyId);

}