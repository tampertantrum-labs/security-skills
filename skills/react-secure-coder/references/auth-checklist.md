# Authentication Security Checklist

Use this checklist when implementing or reviewing authentication in React applications.

---

## Token Storage

| Requirement | Status | Notes |
|-------------|--------|-------|
| Access tokens in httpOnly cookies | ☐ | Never localStorage |
| Secure flag on cookies (HTTPS only) | ☐ | |
| SameSite=Strict or Lax | ☐ | Prevents CSRF |
| Short-lived access tokens (≤15 min) | ☐ | |
| Refresh tokens have longer expiry | ☐ | 7-30 days typical |
| Refresh token rotation enabled | ☐ | New token on each refresh |

---

## Password Requirements

| Requirement | Status | Notes |
|-------------|--------|-------|
| Minimum 12 characters | ☐ | NIST recommendation |
| Maximum 128 characters | ☐ | Prevent DoS |
| Require complexity (upper, lower, number, special) | ☐ | |
| Check against breach databases | ☐ | Use HaveIBeenPwned API |
| No password hints | ☐ | Security risk |
| Secure password reset flow | ☐ | Token-based, time-limited |

---

## Login Security

| Requirement | Status | Notes |
|-------------|--------|-------|
| Rate limiting on login endpoint | ☐ | 5 attempts per 15 min |
| Account lockout after failures | ☐ | Temporary, not permanent |
| Generic error messages | ☐ | Don't reveal if user exists |
| Log all auth events | ☐ | Success and failure |
| CAPTCHA after failed attempts | ☐ | Optional but recommended |
| MFA option available | ☐ | TOTP or WebAuthn |

---

## Session Management

| Requirement | Status | Notes |
|-------------|--------|-------|
| Session invalidation on logout | ☐ | Server-side |
| "Logout everywhere" option | ☐ | Invalidate all sessions |
| Session timeout (idle) | ☐ | 15-30 min for sensitive apps |
| Session timeout (absolute) | ☐ | 8-24 hours max |
| New session on privilege change | ☐ | After login, role change |
| Secure session ID generation | ☐ | Cryptographically random |

---

## Client-Side Security

| Requirement | Status | Notes |
|-------------|--------|-------|
| Auth state in context, not global | ☐ | Prevent accidental exposure |
| Protected routes check server | ☐ | Not just client state |
| Clear sensitive data on logout | ☐ | State, forms, cache |
| Handle session expiry gracefully | ☐ | Redirect to login |
| CSRF protection for auth endpoints | ☐ | Token in header |
| No auth data in URL parameters | ☐ | Tokens leak in logs/referrer |

---

## API Security

| Requirement | Status | Notes |
|-------------|--------|-------|
| Validate token on every request | ☐ | Don't trust client |
| Check token expiry server-side | ☐ | |
| Verify token signature | ☐ | Prevent tampering |
| Include credentials in fetch | ☐ | `credentials: 'include'` |
| Handle 401 responses | ☐ | Attempt refresh or logout |
| Don't cache authenticated responses | ☐ | `Cache-Control: no-store` |

---

## Password Reset Flow

```
1. User requests reset → Generate secure token
2. Store hashed token with expiry (1 hour max)
3. Send reset link via email (HTTPS only)
4. User clicks link → Validate token
5. User sets new password → Invalidate token
6. Invalidate all existing sessions
7. Send confirmation email
```

| Requirement | Status |
|-------------|--------|
| Token is cryptographically random | ☐ |
| Token is hashed in database | ☐ |
| Token expires in ≤1 hour | ☐ |
| Token is single-use | ☐ |
| Old sessions invalidated | ☐ |
| User notified of password change | ☐ |

---

## OAuth/Social Login

| Requirement | Status | Notes |
|-------------|--------|-------|
| Use PKCE flow | ☐ | Prevents code interception |
| Validate state parameter | ☐ | CSRF protection |
| Verify ID token signature | ☐ | |
| Check token issuer and audience | ☐ | |
| Link accounts securely | ☐ | Verify email ownership |
| Handle account conflicts | ☐ | Same email, different provider |

---

## Multi-Factor Authentication

| Requirement | Status | Notes |
|-------------|--------|-------|
| TOTP support (Google Auth, etc.) | ☐ | |
| Backup codes provided | ☐ | 10 single-use codes |
| Backup codes are hashed | ☐ | |
| Recovery flow is secure | ☐ | |
| MFA can be required per role | ☐ | Admins must use MFA |
| WebAuthn/Passkey support | ☐ | Most secure option |

---

## Security Headers

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
```

---

## Quick Auth Context Template

```tsx
interface AuthState {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
}

interface AuthActions {
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
}

// Combine in context
type AuthContextType = AuthState & AuthActions;
```

---

## Common Mistakes

| Mistake | Risk | Fix |
|---------|------|-----|
| JWT in localStorage | XSS steals token | httpOnly cookie |
| No token expiry | Stolen token works forever | Short-lived + refresh |
| Client-side only auth | Easy bypass | Always verify server |
| "Remember me" = never expire | Long attack window | Max 30 days + re-auth for sensitive |
| Email as sole password reset | Email compromise = account loss | Add security questions or MFA |
| No brute force protection | Password guessing | Rate limit + lockout |

---

## Testing Checklist

- [ ] Try accessing protected routes without auth
- [ ] Try accessing protected routes with expired token
- [ ] Try accessing admin routes as regular user
- [ ] Try SQL injection in login form
- [ ] Try brute forcing login (should be rate limited)
- [ ] Verify logout actually invalidates session
- [ ] Test password reset with expired/invalid token
- [ ] Check that auth errors don't leak user existence
