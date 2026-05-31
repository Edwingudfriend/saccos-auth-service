# SACCOS Auth Service

JWT authentication, RBAC, multi-tenant user management, audit logging and SMS-based password reset for the full SACCOS platform.

## Roles

| Role | Who | Access |
|---|---|---|
| `MEMBER` | SACCO member | Self-service — apply loans, view statements, consent as guarantor |
| `LOAN_OFFICER` | Credit staff | Review and approve/reject loans at officer level |
| `COMMITTEE_MEMBER` | Credit committee | Vote on loan applications |
| `CHAIRPERSON` | SACCO chairperson | Final loan approval sign-off |
| `TREASURER` | Finance staff | Dividends, reconciliation, financial reports |
| `BOARD_MEMBER` | Board director | Board votes, dividend declarations |
| `MANAGER` | Management | Dashboards, reports, oversight — no transaction authority |
| `AUDITOR` | Internal/external auditor | Read-only access to all financial data |
| `ADMIN` | System administrator | Full access — user management, SACCO config |
| `SYSTEM` | Service accounts | Internal microservice-to-microservice calls |

## Token Structure

```json
{
  "sub": "user-uuid",
  "username": "0712345678",
  "saccoCode": "KISASA",
  "roles": ["MEMBER"],
  "fullName": "Amina Rashidi",
  "phone": "0712345678",
  "memberId": "member-uuid",
  "memberNumber": "KSS-0042",
  "iat": 1748700000,
  "exp": 1748703600,
  "iss": "saccos-auth-service"
}
```

## API Endpoints

| Method | Path | Auth | Action |
|--------|------|------|--------|
| POST | `/api/auth/login` | Public | Login → access + refresh token |
| POST | `/api/auth/refresh` | Public | Refresh access token |
| POST | `/api/auth/logout` | Bearer | Blacklist token + revoke refresh |
| POST | `/api/auth/password/forgot` | Public | Send OTP via SMS |
| POST | `/api/auth/password/reset` | Public | Reset with OTP |
| POST | `/api/auth/password/change` | Bearer | Change own password |
| GET | `/api/auth/validate` | Bearer | Validate token (for API gateway) |
| POST | `/api/users` | ADMIN | Create user |
| GET | `/api/users/sacco/{code}` | ADMIN/MANAGER | List SACCO users |
| PUT | `/api/users/{id}/roles` | ADMIN | Update user roles |
| POST | `/api/users/{id}/suspend` | ADMIN | Suspend user |
| POST | `/api/users/{id}/unlock` | ADMIN | Unlock account |

## Security Features

- BCrypt password hashing (cost factor 12)
- Account lockout after 5 failed attempts (configurable)
- JWT blacklisting in Redis on logout
- Refresh token rotation — new token on every refresh
- All sessions revoked on password change or role update
- Immutable audit log for every authentication event
- OTP expires in 15 minutes

## How other services use this

Every downstream service has a `JwtAuthFilter` that reads the `Authorization: Bearer <token>` header. The token claims (`roles`, `saccoCode`, `memberId`) are used for `@PreAuthorize` checks — no call back to auth service needed on every request.

For token blacklist checking, services can call `GET /api/auth/validate` or include the same Redis check locally.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `JWT_SECRET` | (change this!) | HS512 signing key — min 64 chars |
| `JWT_ACCESS_EXPIRY_MINUTES` | 60 | Access token lifetime |
| `JWT_REFRESH_EXPIRY_DAYS` | 7 | Refresh token lifetime |
| `MAX_FAILED_ATTEMPTS` | 5 | Before account locks |
| `LOCKOUT_MINUTES` | 30 | Lockout duration |
