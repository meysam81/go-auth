# Complete Authentication Example

A full-featured authentication system demonstrating all go-auth capabilities.

## Features

- **Basic Authentication** - Email/password with bcrypt
- **JWT Tokens** - Access and refresh tokens
- **TOTP 2FA** - Time-based one-time passwords with backup codes
- **WebAuthn/Passkeys** - FIDO2 passwordless authentication
- **Google SSO** - OAuth2/OIDC integration
- **Password Reset** - Token-based recovery flow
- **Session Management** - Secure session handling
- **Audit Logging** - Compliance-ready logging with stdlib `log/slog`
- **PostgreSQL Storage** - Production-ready database implementations

## Quick Start (In-Memory Mode)

Run without any external dependencies:

```bash
cd examples/complete
go run main.go -memory
```

Test registration and login:

```bash
# Register a new user
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","username":"testuser","password":"password123","name":"Test User"}'

# Login
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'

# Access protected endpoint (use the access_token from login response)
curl -H "Authorization: Bearer <access_token>" http://localhost:8080/api/me
```

## PostgreSQL Setup

### 1. Create Database

```bash
createdb go_auth_example
```

### 2. Run Schema Migration

```bash
psql go_auth_example < schema.sql
```

### 3. Start Server

```bash
export DATABASE_URL="postgres://user:password@localhost/go_auth_example?sslmode=disable"
go run main.go
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `DATABASE_URL` | PostgreSQL connection string | Yes (unless using `-memory`) |
| `JWT_SIGNING_KEY` | Secret key for JWT signing | No (auto-generated if not set) |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | No (SSO disabled if not set) |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret | No (SSO disabled if not set) |
| `WEBAUTHN_RP_ID` | WebAuthn Relying Party ID | No (defaults to `localhost`) |

## API Endpoints

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/register` | Register new user |
| POST | `/auth/login` | Login with email/password |
| POST | `/auth/refresh` | Refresh access token |
| POST | `/auth/logout` | Logout (revoke refresh token) |

### Password Reset

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/password/reset/request` | Request password reset email |
| POST | `/auth/password/reset/confirm` | Confirm reset with token |

### TOTP Two-Factor Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/totp/setup` | Generate TOTP secret and backup codes |
| POST | `/auth/totp/verify` | Verify TOTP code |
| POST | `/auth/totp/disable` | Disable TOTP for user |

### WebAuthn/Passkeys

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/webauthn/register/begin` | Start passkey registration |
| POST | `/auth/webauthn/register/finish` | Complete passkey registration |
| POST | `/auth/webauthn/login/begin` | Start passkey login |
| POST | `/auth/webauthn/login/finish` | Complete passkey login |

### Google SSO

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/auth/google/login` | Redirect to Google login |
| GET | `/auth/google/callback` | OAuth callback handler |

### Protected Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/me` | Get current user profile |
| GET | `/api/protected` | Example protected resource |

## Usage Examples

### Register and Login

```bash
# Register
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "username": "myuser",
    "password": "securepass123",
    "name": "John Doe"
  }'

# Response includes tokens
{
  "user": {...},
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "expires_in": 900
}
```

### Setup TOTP 2FA

```bash
# Setup (returns QR code URL and backup codes)
curl -X POST http://localhost:8080/auth/totp/setup \
  -H "Content-Type: application/json" \
  -d '{"user_id": "user123", "account_name": "user@example.com"}'

# Response
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code_url": "otpauth://totp/GoAuthExample:user@example.com?...",
  "backup_codes": ["ABCD-1234", "EFGH-5678", ...]
}

# Login with 2FA
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepass123",
    "totp_code": "123456"
  }'
```

### Password Reset

```bash
# Request reset
curl -X POST http://localhost:8080/auth/password/reset/request \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'

# Confirm reset (use token from response/email)
curl -X POST http://localhost:8080/auth/password/reset/confirm \
  -H "Content-Type: application/json" \
  -d '{
    "token": "abc123...",
    "new_password": "newsecurepass456"
  }'
```

### Token Refresh

```bash
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "eyJ..."}'
```

## Google SSO Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable the Google OAuth 2.0 API
4. Go to Credentials > Create Credentials > OAuth 2.0 Client ID
5. Set Authorized redirect URIs to `http://localhost:8080/auth/google/callback`
6. Copy Client ID and Client Secret
7. Set environment variables:

```bash
export GOOGLE_CLIENT_ID="your-client-id"
export GOOGLE_CLIENT_SECRET="your-client-secret"
```

## Audit Logging

All authentication events are logged in JSON format using `log/slog`:

```json
{
  "time": "2024-01-15T10:30:00Z",
  "level": "INFO",
  "msg": "audit",
  "event_type": "auth.login",
  "result": "success",
  "user_id": "user123",
  "email": "user@example.com",
  "provider": "local",
  "ip": "127.0.0.1:54321",
  "user_agent": "curl/7.64.1"
}
```

Event types include:
- `auth.register`, `auth.login`, `auth.logout`
- `auth.password_reset.request`, `auth.password_reset.confirm`
- `auth.totp.setup`, `auth.totp.verify`, `auth.totp.disable`
- `auth.sso.google`
- `token.refresh`

## Security Notes

- **JWT Signing Key**: Always set `JWT_SIGNING_KEY` in production
- **HTTPS**: Use HTTPS in production for all endpoints
- **Password Reset Tokens**: In production, send via email (don't return in response)
- **Rate Limiting**: Add rate limiting middleware for production
- **CORS**: Configure appropriate CORS policies

## Database Schema

See `schema.sql` for the complete PostgreSQL schema including:
- Users table with metadata
- Password hashes
- Password reset tokens
- TOTP secrets and backup codes
- WebAuthn credentials
- Sessions
- Refresh tokens
- OIDC states
- Audit logs

## License

Apache 2.0 - See LICENSE file in root directory
