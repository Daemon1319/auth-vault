# AuthVault

A secure authentication REST API built with **Spring Boot 4** and **Spring Security**. Implements JWT-based stateless auth with rotating refresh tokens, role-based access control, and production security patterns.

## Key Features

- **JWT Access Tokens** — Short-lived, HS256-signed tokens with role claims (JJWT 0.13)
- **Rotating Refresh Tokens** — SHA-256 hashed, stored in HttpOnly cookies, with token family tracking for **theft detection**
- **Timing Attack Mitigation** — Dummy BCrypt comparison on invalid usernames to prevent user enumeration
- **RBAC** — Endpoint-level authorization (`USER` / `ADMIN` roles)

## Tech Stack

Java 17 · Spring Boot 4 · Spring Security · JJWT 0.13 · PostgreSQL · Spring Data JPA · BCrypt

## API Endpoints

| Method | Endpoint             | Description                        |
|--------|----------------------|------------------------------------|
| POST   | `/api/auth/register` | Register a new user with role      |
| POST   | `/api/auth/login`    | Authenticate and receive JWT       |
| POST   | `/api/auth/refresh`  | Rotate refresh token               |
| POST   | `/api/auth/logout`   | Revoke entire token family         |

