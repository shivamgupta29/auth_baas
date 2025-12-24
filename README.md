Auth Service – JWT Access & Refresh Authentication

A backend authentication service built with Node.js, Express, and PostgreSQL, implementing JWT-based access and refresh tokens with rotation, reuse detection, session revocation, and logout.

This project is designed as a foundation for an Auth BaaS (Authentication as a Service) and can be used as a standalone auth backend or extended to support multiple client applications.

🚀 Features

User registration with secure password hashing

Login with short-lived access tokens

Long-lived refresh tokens (hashed and stored server-side)

Refresh token rotation

Refresh token reuse detection

Server-side session revocation

Real logout (revokes refresh tokens)

Stateless access token verification via middleware

PostgreSQL-backed persistence

🧠 Design Principles

Stateless access tokens
Access tokens are never stored and expire quickly.

Stateful refresh tokens
Refresh tokens are hashed and stored in the database to allow:

revocation

rotation

reuse detection

Security-first error handling
Authentication failures return generic responses to avoid information leakage.

🏗 Tech Stack

Node.js

Express

PostgreSQL

bcrypt

jsonwebtoken

dotenv

🔐 Authentication Flow
1. Register

Creates a new user with a hashed password.

2. Login

Verifies credentials

Issues:

Access token (short-lived)

Refresh token (long-lived, stored hashed)

3. Protected Routes

Require a valid access token

Verified statelessly via middleware

4. Refresh Token

Validates refresh token

Detects reuse

Rotates refresh token

Issues new access & refresh tokens

5. Logout

Revokes the session by deleting the stored refresh token hash

Access tokens expire naturally

🗄 Database Schema (Simplified)
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    password_hashed TEXT NOT NULL,
    refresh_token_hashed TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
