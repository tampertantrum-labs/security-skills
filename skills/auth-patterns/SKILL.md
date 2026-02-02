---
name: auth-patterns
description: Authentication patterns done right. JWT, sessions, refresh tokens, OAuth, and password handling with security best practices.
---

# Auth Patterns

Implement authentication that's actually secure. Covers JWT, sessions, refresh token rotation, OAuth, password hashing, and MFA.

## When to Use This Skill

- Implementing user authentication
- Building login/signup flows
- Integrating OAuth providers
- Managing sessions and tokens
- Implementing password reset flows
- Adding MFA/2FA

## When NOT to Use This Skill

- Public-only applications
- Using fully managed auth (Auth0, Clerk) - follow their docs

---

## JWT Authentication

### Token Generation

```typescript
// lib/jwt.ts
import { SignJWT, jwtVerify } from 'jose';

const ACCESS_TOKEN_SECRET = new TextEncoder().encode(process.env.JWT_SECRET!);
const REFRESH_TOKEN_SECRET = new TextEncoder().encode(process.env.REFRESH_SECRET!);

interface TokenPayload {
  userId: string;
  role: 'user' | 'admin';
}

// Short-lived access token (15 minutes)
export async function generateAccessToken(payload: TokenPayload): Promise<string> {
  return new SignJWT({ ...payload })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('15m')
    .setJti(crypto.randomUUID()) // Unique token ID
    .sign(ACCESS_TOKEN_SECRET);
}

// Longer-lived refresh token (7 days)
export async function generateRefreshToken(userId: string): Promise<string> {
  return new SignJWT({ userId })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('7d')
    .setJti(crypto.randomUUID())
    .sign(REFRESH_TOKEN_SECRET);
}

export async function verifyAccessToken(token: string): Promise<TokenPayload | null> {
  try {
    const { payload } = await jwtVerify(token, ACCESS_TOKEN_SECRET);
    return payload as TokenPayload;
  } catch {
    return null;
  }
}

export async function verifyRefreshToken(token: string): Promise<{ userId: string } | null> {
  try {
    const { payload } = await jwtVerify(token, REFRESH_TOKEN_SECRET);
    return payload as { userId: string };
  } catch {
    return null;
  }
}
```

### Token Storage (httpOnly Cookies)

```typescript
// ❌ BAD: localStorage (vulnerable to XSS)
localStorage.setItem('accessToken', token);

// ✅ GOOD: httpOnly cookies (not accessible via JS)
// app/api/auth/login/route.ts
import { cookies } from 'next/headers';

export async function POST(request: Request) {
  // ... validate credentials

  const accessToken = await generateAccessToken({ userId: user.id, role: user.role });
  const refreshToken = await generateRefreshToken(user.id);

  // Store refresh token hash in database (for revocation)
  await db.refreshToken.create({
    data: {
      userId: user.id,
      tokenHash: await hashToken(refreshToken),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    },
  });

  // Set cookies
  cookies().set('accessToken', accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 15 * 60, // 15 minutes
    path: '/',
  });

  cookies().set('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60, // 7 days
    path: '/api/auth', // Only sent to auth endpoints
  });

  return Response.json({ success: true, user: { id: user.id, email: user.email } });
}
```

### Refresh Token Rotation

```typescript
// app/api/auth/refresh/route.ts
import { cookies } from 'next/headers';

export async function POST() {
  const refreshToken = cookies().get('refreshToken')?.value;
  
  if (!refreshToken) {
    return Response.json({ error: 'No refresh token' }, { status: 401 });
  }

  // Verify token
  const payload = await verifyRefreshToken(refreshToken);
  if (!payload) {
    // Clear cookies on invalid token
    cookies().delete('accessToken');
    cookies().delete('refreshToken');
    return Response.json({ error: 'Invalid refresh token' }, { status: 401 });
  }

  // Check if token exists in database (not revoked)
  const storedToken = await db.refreshToken.findFirst({
    where: {
      userId: payload.userId,
      tokenHash: await hashToken(refreshToken),
      expiresAt: { gt: new Date() },
      revokedAt: null,
    },
  });

  if (!storedToken) {
    // Token reuse detected - revoke all tokens for this user
    await db.refreshToken.updateMany({
      where: { userId: payload.userId },
      data: { revokedAt: new Date() },
    });
    
    cookies().delete('accessToken');
    cookies().delete('refreshToken');
    
    // Log security event
    console.warn('Refresh token reuse detected:', { userId: payload.userId });
    
    return Response.json({ error: 'Token reuse detected' }, { status: 401 });
  }

  // Rotate: Revoke old token, issue new pair
  await db.refreshToken.update({
    where: { id: storedToken.id },
    data: { revokedAt: new Date() },
  });

  const user = await db.user.findUnique({ where: { id: payload.userId } });
  if (!user) {
    return Response.json({ error: 'User not found' }, { status: 401 });
  }

  // Generate new tokens
  const newAccessToken = await generateAccessToken({ userId: user.id, role: user.role });
  const newRefreshToken = await generateRefreshToken(user.id);

  // Store new refresh token
  await db.refreshToken.create({
    data: {
      userId: user.id,
      tokenHash: await hashToken(newRefreshToken),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    },
  });

  // Set new cookies
  cookies().set('accessToken', newAccessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 15 * 60,
    path: '/',
  });

  cookies().set('refreshToken', newRefreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60,
    path: '/api/auth',
  });

  return Response.json({ success: true });
}
```

---

## Session-Based Authentication

### Secure Session Setup

```typescript
// lib/session.ts
import { cookies } from 'next/headers';
import { db } from './db';
import crypto from 'crypto';

const SESSION_COOKIE = 'session_id';
const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hours

export async function createSession(userId: string): Promise<string> {
  // Generate cryptographically secure session ID
  const sessionId = crypto.randomBytes(32).toString('hex');
  
  // Store in database
  await db.session.create({
    data: {
      id: sessionId,
      userId,
      expiresAt: new Date(Date.now() + SESSION_DURATION),
      createdAt: new Date(),
      userAgent: '', // Can store for anomaly detection
      ipAddress: '', // Can store for anomaly detection
    },
  });

  // Set cookie
  cookies().set(SESSION_COOKIE, sessionId, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: SESSION_DURATION / 1000,
    path: '/',
  });

  return sessionId;
}

export async function getSession(): Promise<{ userId: string; role: string } | null> {
  const sessionId = cookies().get(SESSION_COOKIE)?.value;
  if (!sessionId) return null;

  const session = await db.session.findUnique({
    where: { id: sessionId },
    include: { user: { select: { id: true, role: true } } },
  });

  if (!session || session.expiresAt < new Date()) {
    cookies().delete(SESSION_COOKIE);
    return null;
  }

  // Extend session on activity (sliding expiration)
  await db.session.update({
    where: { id: sessionId },
    data: { expiresAt: new Date(Date.now() + SESSION_DURATION) },
  });

  return { userId: session.user.id, role: session.user.role };
}

export async function destroySession(): Promise<void> {
  const sessionId = cookies().get(SESSION_COOKIE)?.value;
  
  if (sessionId) {
    await db.session.delete({ where: { id: sessionId } }).catch(() => {});
  }
  
  cookies().delete(SESSION_COOKIE);
}

// Destroy all sessions for a user (logout everywhere)
export async function destroyAllSessions(userId: string): Promise<void> {
  await db.session.deleteMany({ where: { userId } });
}
```

---

## Password Handling

### Hashing with Argon2

```typescript
// lib/password.ts
import { hash, verify } from 'argon2';

// Argon2id is recommended for password hashing
const ARGON_OPTIONS = {
  type: 2, // argon2id
  memoryCost: 65536, // 64MB
  timeCost: 3,
  parallelism: 4,
};

export async function hashPassword(password: string): Promise<string> {
  return hash(password, ARGON_OPTIONS);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  try {
    return await verify(hash, password);
  } catch {
    return false;
  }
}
```

### Hashing with bcrypt (Alternative)

```typescript
// lib/password.ts
import bcrypt from 'bcrypt';

const SALT_ROUNDS = 12; // Adjust based on your server's performance

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}
```

### Password Requirements

```typescript
import { z } from 'zod';

export const passwordSchema = z
  .string()
  .min(12, 'Password must be at least 12 characters')
  .max(128, 'Password too long')
  .regex(/[A-Z]/, 'Must contain at least one uppercase letter')
  .regex(/[a-z]/, 'Must contain at least one lowercase letter')
  .regex(/[0-9]/, 'Must contain at least one number')
  .regex(/[^A-Za-z0-9]/, 'Must contain at least one special character')
  .refine(
    (password) => !commonPasswords.includes(password.toLowerCase()),
    'This password is too common'
  );

// Check against breach databases
import { pwnedPassword } from 'hibp';

export async function isPasswordBreached(password: string): Promise<boolean> {
  const count = await pwnedPassword(password);
  return count > 0;
}
```

---

## OAuth Integration

### OAuth 2.0 + PKCE Flow

```typescript
// lib/oauth.ts
import crypto from 'crypto';

// Generate PKCE code verifier and challenge
export function generatePKCE(): { verifier: string; challenge: string } {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto
    .createHash('sha256')
    .update(verifier)
    .digest('base64url');
  
  return { verifier, challenge };
}

// Generate state parameter (CSRF protection)
export function generateState(): string {
  return crypto.randomBytes(16).toString('hex');
}

// Build authorization URL
export function buildAuthUrl(provider: 'google' | 'github'): {
  url: string;
  state: string;
  codeVerifier: string;
} {
  const { verifier, challenge } = generatePKCE();
  const state = generateState();

  const configs = {
    google: {
      authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
      clientId: process.env.GOOGLE_CLIENT_ID!,
      scopes: ['openid', 'email', 'profile'],
    },
    github: {
      authUrl: 'https://github.com/login/oauth/authorize',
      clientId: process.env.GITHUB_CLIENT_ID!,
      scopes: ['read:user', 'user:email'],
    },
  };

  const config = configs[provider];
  const params = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: `${process.env.APP_URL}/api/auth/callback/${provider}`,
    response_type: 'code',
    scope: config.scopes.join(' '),
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });

  return {
    url: `${config.authUrl}?${params}`,
    state,
    codeVerifier: verifier,
  };
}
```

### OAuth Callback Handler

```typescript
// app/api/auth/callback/[provider]/route.ts
import { cookies } from 'next/headers';
import { db } from '@/lib/db';
import { createSession } from '@/lib/session';

export async function GET(
  request: Request,
  { params }: { params: { provider: string } }
) {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const error = url.searchParams.get('error');

  // Check for OAuth error
  if (error) {
    return Response.redirect(`${process.env.APP_URL}/login?error=oauth_denied`);
  }

  // Verify state (CSRF protection)
  const storedState = cookies().get('oauth_state')?.value;
  const codeVerifier = cookies().get('oauth_verifier')?.value;

  if (!state || !storedState || state !== storedState) {
    return Response.redirect(`${process.env.APP_URL}/login?error=invalid_state`);
  }

  // Clear OAuth cookies
  cookies().delete('oauth_state');
  cookies().delete('oauth_verifier');

  if (!code || !codeVerifier) {
    return Response.redirect(`${process.env.APP_URL}/login?error=missing_code`);
  }

  try {
    // Exchange code for tokens
    const tokens = await exchangeCodeForTokens(params.provider, code, codeVerifier);
    
    // Get user info from provider
    const providerUser = await getProviderUser(params.provider, tokens.access_token);
    
    // Find or create user
    let user = await db.user.findFirst({
      where: {
        accounts: {
          some: {
            provider: params.provider,
            providerAccountId: providerUser.id,
          },
        },
      },
    });

    if (!user) {
      // Create new user
      user = await db.user.create({
        data: {
          email: providerUser.email,
          name: providerUser.name,
          emailVerified: new Date(), // OAuth emails are verified
          accounts: {
            create: {
              provider: params.provider,
              providerAccountId: providerUser.id,
              accessToken: tokens.access_token,
              refreshToken: tokens.refresh_token,
            },
          },
        },
      });
    }

    // Create session
    await createSession(user.id);

    return Response.redirect(`${process.env.APP_URL}/dashboard`);
  } catch (error) {
    console.error('OAuth error:', error);
    return Response.redirect(`${process.env.APP_URL}/login?error=oauth_failed`);
  }
}
```

---

## Multi-Factor Authentication (MFA)

### TOTP Setup

```typescript
// lib/mfa.ts
import { authenticator } from 'otplib';
import QRCode from 'qrcode';

export async function generateMfaSecret(email: string): Promise<{
  secret: string;
  qrCode: string;
  backupCodes: string[];
}> {
  // Generate secret
  const secret = authenticator.generateSecret();
  
  // Generate QR code URL
  const otpauth = authenticator.keyuri(email, 'YourApp', secret);
  const qrCode = await QRCode.toDataURL(otpauth);
  
  // Generate backup codes
  const backupCodes = Array.from({ length: 10 }, () =>
    crypto.randomBytes(4).toString('hex').toUpperCase()
  );

  return { secret, qrCode, backupCodes };
}

export function verifyTotp(token: string, secret: string): boolean {
  return authenticator.verify({ token, secret });
}

export async function verifyBackupCode(
  userId: string,
  code: string
): Promise<boolean> {
  const hashedCode = await hashToken(code);
  
  const backupCode = await db.backupCode.findFirst({
    where: {
      userId,
      codeHash: hashedCode,
      usedAt: null,
    },
  });

  if (!backupCode) return false;

  // Mark as used
  await db.backupCode.update({
    where: { id: backupCode.id },
    data: { usedAt: new Date() },
  });

  return true;
}
```

### MFA-Protected Login Flow

```typescript
// app/api/auth/login/route.ts
export async function POST(request: Request) {
  const { email, password, mfaToken } = await request.json();

  // 1. Verify credentials
  const user = await db.user.findUnique({ where: { email } });
  if (!user || !await verifyPassword(password, user.passwordHash)) {
    // Don't reveal if user exists
    return Response.json({ error: 'Invalid credentials' }, { status: 401 });
  }

  // 2. Check if MFA is enabled
  if (user.mfaEnabled) {
    if (!mfaToken) {
      // Return indication that MFA is required
      return Response.json({ 
        requiresMfa: true,
        // Optionally return a temp token to continue the flow
      }, { status: 200 });
    }

    // Verify MFA token
    const isValidMfa = verifyTotp(mfaToken, user.mfaSecret!) ||
                       await verifyBackupCode(user.id, mfaToken);
    
    if (!isValidMfa) {
      return Response.json({ error: 'Invalid MFA token' }, { status: 401 });
    }
  }

  // 3. Create session
  await createSession(user.id);

  return Response.json({ success: true });
}
```

---

## Password Reset Flow

```typescript
// app/api/auth/forgot-password/route.ts
import { randomBytes } from 'crypto';

export async function POST(request: Request) {
  const { email } = await request.json();

  // Always return success to prevent email enumeration
  const successResponse = Response.json({ 
    message: 'If that email exists, a reset link has been sent.' 
  });

  const user = await db.user.findUnique({ where: { email } });
  if (!user) return successResponse;

  // Generate secure token
  const token = randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

  // Store hashed token (don't store plain token)
  await db.passwordReset.create({
    data: {
      userId: user.id,
      tokenHash: await hashToken(token),
      expiresAt,
    },
  });

  // Send email with token
  await sendEmail({
    to: email,
    subject: 'Password Reset',
    html: `
      <p>Click the link below to reset your password:</p>
      <a href="${process.env.APP_URL}/reset-password?token=${token}">
        Reset Password
      </a>
      <p>This link expires in 1 hour.</p>
    `,
  });

  return successResponse;
}

// app/api/auth/reset-password/route.ts
export async function POST(request: Request) {
  const { token, newPassword } = await request.json();

  // Validate password
  const passwordResult = passwordSchema.safeParse(newPassword);
  if (!passwordResult.success) {
    return Response.json({ error: 'Invalid password' }, { status: 400 });
  }

  // Find valid reset token
  const resetRecord = await db.passwordReset.findFirst({
    where: {
      tokenHash: await hashToken(token),
      expiresAt: { gt: new Date() },
      usedAt: null,
    },
    include: { user: true },
  });

  if (!resetRecord) {
    return Response.json({ error: 'Invalid or expired token' }, { status: 400 });
  }

  // Update password
  const hashedPassword = await hashPassword(newPassword);
  
  await db.$transaction([
    // Update password
    db.user.update({
      where: { id: resetRecord.userId },
      data: { passwordHash: hashedPassword },
    }),
    // Mark token as used
    db.passwordReset.update({
      where: { id: resetRecord.id },
      data: { usedAt: new Date() },
    }),
    // Invalidate all sessions (logout everywhere)
    db.session.deleteMany({
      where: { userId: resetRecord.userId },
    }),
  ]);

  return Response.json({ success: true });
}
```

---

## Rate Limiting Auth Endpoints

```typescript
// middleware.ts
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

const authRatelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(5, '15 m'), // 5 attempts per 15 min
});

const passwordResetRatelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(3, '1 h'), // 3 requests per hour
});

export async function middleware(request: NextRequest) {
  const ip = request.ip ?? 'unknown';
  
  if (request.nextUrl.pathname === '/api/auth/login') {
    const { success } = await authRatelimit.limit(ip);
    if (!success) {
      return Response.json(
        { error: 'Too many login attempts. Try again later.' },
        { status: 429 }
      );
    }
  }
  
  if (request.nextUrl.pathname === '/api/auth/forgot-password') {
    const { success } = await passwordResetRatelimit.limit(ip);
    if (!success) {
      return Response.json(
        { error: 'Too many requests. Try again later.' },
        { status: 429 }
      );
    }
  }
}
```

---

## Anti-Patterns

| Anti-Pattern | Risk | Solution |
|--------------|------|----------|
| Storing JWT in localStorage | XSS can steal tokens | httpOnly cookies |
| Long-lived access tokens | Extended exposure if stolen | Short-lived (15 min) + refresh |
| No refresh token rotation | Token reuse attacks | Rotate on every refresh |
| MD5/SHA1 for passwords | Rainbow table attacks | bcrypt/argon2 |
| Same response for all auth errors | User enumeration | Generic "Invalid credentials" |
| No MFA option | Account takeover | Offer TOTP MFA |
| Password reset tokens in URL forever | Token theft | Short expiry, one-time use |
| No rate limiting on auth | Brute force | Rate limit by IP |

---

## References

- [references/jwt-best-practices.md](references/jwt-best-practices.md) - JWT deep dive
- [references/oauth-providers.md](references/oauth-providers.md) - Provider-specific setup
- [references/mfa-implementation.md](references/mfa-implementation.md) - MFA patterns

---

*This skill is maintained by [TamperTantrum Labs](https://tampertantrum.com) — making application security accessible, human, and empowering.*
