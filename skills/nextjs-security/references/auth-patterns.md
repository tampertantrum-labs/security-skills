# Authentication Patterns for Next.js App Router

A comprehensive reference for implementing secure authentication in Next.js 16+ applications using the App Router. All examples use TypeScript and `pnpm`.

> **Next.js 16+ async APIs:** `cookies()`, `headers()`, and `params` all return Promises. Always `await` them. Examples throughout this document follow this requirement.

---

## Table of Contents

1. [Auth.js (NextAuth v5) Setup](#1-authjs-nextauth-v5-setup)
2. [Custom JWT Auth with jose](#2-custom-jwt-auth-with-jose)
3. [Session Management](#3-session-management)
4. [Role-Based Access Control (RBAC)](#4-role-based-access-control-rbac)
5. [Data Access Layer (DAL)](#5-data-access-layer-dal)
6. [OAuth PKCE Flow](#6-oauth-pkce-flow)
7. [Token Refresh Pattern](#7-token-refresh-pattern)
8. [Multi-Factor Authentication (MFA)](#8-multi-factor-authentication-mfa)
9. [Logout and Session Invalidation](#9-logout-and-session-invalidation)

---

## 1. Auth.js (NextAuth v5) Setup

Auth.js is the rebranded Next Auth v5. It is the recommended choice for most Next.js applications because it handles OAuth, credential, and magic-link providers with sensible secure defaults, and is designed for the App Router.

Install with pnpm:

```bash
pnpm add next-auth@beta
```

### auth.ts — Core Configuration

```typescript
// auth.ts (project root)
import NextAuth from 'next-auth';
import GitHub from 'next-auth/providers/github';
import Credentials from 'next-auth/providers/credentials';
import { PrismaAdapter } from '@auth/prisma-adapter';
import { prisma } from '@/lib/db';
import { verifyPassword } from '@/lib/password';
import { z } from 'zod';

const credentialsSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

export const { handlers, auth, signIn, signOut } = NextAuth({
  adapter: PrismaAdapter(prisma),
  session: {
    strategy: 'jwt', // Use 'database' if you need server-side revocation
    maxAge: 30 * 24 * 60 * 60, // 30 days
  },
  pages: {
    signIn: '/login',
    error: '/login',
  },
  providers: [
    GitHub({
      clientId: process.env.GITHUB_ID!,
      clientSecret: process.env.GITHUB_SECRET!,
    }),
    Credentials({
      credentials: {
        email: { label: 'Email', type: 'email' },
        password: { label: 'Password', type: 'password' },
      },
      async authorize(credentials) {
        // Validate input shape first
        const parsed = credentialsSchema.safeParse(credentials);
        if (!parsed.success) return null;

        const user = await prisma.user.findUnique({
          where: { email: parsed.data.email },
          select: { id: true, email: true, name: true, role: true, passwordHash: true },
        });

        // Use a constant-time comparison path — always call verifyPassword
        // even when user is null to prevent timing-based user enumeration
        const dummyHash = '$argon2id$v=19$m=65536,t=3,p=4$placeholder';
        const isValid = user
          ? await verifyPassword(parsed.data.password, user.passwordHash)
          : await verifyPassword(parsed.data.password, dummyHash).then(() => false);

        if (!user || !isValid) return null;

        return {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
        };
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user }) {
      // Attach role to JWT on initial sign-in
      if (user) {
        token.role = (user as { role: string }).role;
        token.id = user.id;
      }
      return token;
    },
    async session({ session, token }) {
      // Expose role and id on the session object
      if (token) {
        session.user.role = token.role as string;
        session.user.id = token.id as string;
      }
      return session;
    },
  },
});
```

### Middleware Integration

```typescript
// middleware.ts
export { auth as middleware } from '@/auth';

export const config = {
  matcher: [
    // Protect all routes except static files, images, and auth routes
    '/((?!_next/static|_next/image|favicon.ico|api/auth).*)',
  ],
};
```

For more granular control, wrap the exported `auth` middleware:

```typescript
// middleware.ts
import { auth } from '@/auth';
import { NextResponse } from 'next/server';

export default auth((req) => {
  const isLoggedIn = !!req.auth;
  const isAuthPage = req.nextUrl.pathname.startsWith('/login');
  const isAdminRoute = req.nextUrl.pathname.startsWith('/admin');

  if (!isLoggedIn && !isAuthPage) {
    return NextResponse.redirect(new URL('/login', req.url));
  }

  if (isAdminRoute && req.auth?.user?.role !== 'admin') {
    return NextResponse.redirect(new URL('/unauthorized', req.url));
  }

  return NextResponse.next();
});

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico|api/auth).*)'],
};
```

### Session Access in Server Components

```typescript
// app/dashboard/page.tsx
import { auth } from '@/auth';
import { redirect } from 'next/navigation';

export default async function DashboardPage() {
  const session = await auth();

  if (!session?.user) {
    redirect('/login');
  }

  return (
    <main>
      <h1>Welcome, {session.user.name}</h1>
      <p>Role: {session.user.role}</p>
    </main>
  );
}
```

### Type Augmentation for Custom Session Fields

```typescript
// types/next-auth.d.ts
import type { DefaultSession } from 'next-auth';

declare module 'next-auth' {
  interface Session {
    user: DefaultSession['user'] & {
      id: string;
      role: string;
    };
  }
}
```

---

## 2. Custom JWT Auth with jose

Use `jose` when you need edge-compatible JWT handling without the overhead of Auth.js, or when integrating with an external identity system. `jose` supports the Web Crypto API and runs in the Edge Runtime.

```bash
pnpm add jose
```

### Token Creation and Verification

```typescript
// lib/jwt.ts
import { SignJWT, jwtVerify, type JWTPayload } from 'jose';

// Encode secrets as Uint8Array — required by jose
const getAccessSecret = () =>
  new TextEncoder().encode(process.env.JWT_ACCESS_SECRET!);
const getRefreshSecret = () =>
  new TextEncoder().encode(process.env.JWT_REFRESH_SECRET!);

export interface AccessTokenPayload extends JWTPayload {
  sub: string;       // user ID
  email: string;
  role: string;
}

export async function signAccessToken(payload: {
  sub: string;
  email: string;
  role: string;
}): Promise<string> {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('15m')  // Short-lived
    .setJti(crypto.randomUUID())
    .sign(getAccessSecret());
}

export async function signRefreshToken(userId: string): Promise<string> {
  return new SignJWT({ sub: userId })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('7d')
    .setJti(crypto.randomUUID())
    .sign(getRefreshSecret());
}

export async function verifyAccessToken(
  token: string,
): Promise<AccessTokenPayload | null> {
  try {
    const { payload } = await jwtVerify(token, getAccessSecret());
    return payload as AccessTokenPayload;
  } catch {
    // Invalid, expired, or tampered — return null, never throw
    return null;
  }
}

export async function verifyRefreshToken(
  token: string,
): Promise<{ sub: string } | null> {
  try {
    const { payload } = await jwtVerify(token, getRefreshSecret());
    return { sub: payload.sub as string };
  } catch {
    return null;
  }
}
```

### Cookie Management — Security Attributes

```typescript
// lib/auth-cookies.ts
import { cookies } from 'next/headers';

const IS_PRODUCTION = process.env.NODE_ENV === 'production';

export async function setAuthCookies(
  accessToken: string,
  refreshToken: string,
): Promise<void> {
  const cookieStore = await cookies(); // await required in Next.js 16+

  cookieStore.set('access_token', accessToken, {
    httpOnly: true,                          // Not accessible via document.cookie
    secure: IS_PRODUCTION,                   // HTTPS only in production
    sameSite: 'lax',                         // CSRF protection for navigations
    path: '/',
    maxAge: 15 * 60,                         // 15 minutes — matches token TTL
  });

  cookieStore.set('refresh_token', refreshToken, {
    httpOnly: true,
    secure: IS_PRODUCTION,
    sameSite: 'lax',
    path: '/api/auth',                       // Scoped — only sent to auth endpoints
    maxAge: 7 * 24 * 60 * 60,               // 7 days — matches token TTL
  });
}

export async function clearAuthCookies(): Promise<void> {
  const cookieStore = await cookies();
  cookieStore.delete('access_token');
  cookieStore.delete('refresh_token');
}

export async function getAccessToken(): Promise<string | undefined> {
  const cookieStore = await cookies();
  return cookieStore.get('access_token')?.value;
}

export async function getRefreshToken(): Promise<string | undefined> {
  const cookieStore = await cookies();
  return cookieStore.get('refresh_token')?.value;
}
```

### Middleware Integration

```typescript
// middleware.ts
import { NextRequest, NextResponse } from 'next/server';
import { verifyAccessToken } from '@/lib/jwt';

const PUBLIC_PATHS = ['/', '/login', '/register', '/api/auth'];

function isPublic(pathname: string): boolean {
  return PUBLIC_PATHS.some((p) => pathname === p || pathname.startsWith(p + '/'));
}

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  if (isPublic(pathname)) {
    return NextResponse.next();
  }

  const token = request.cookies.get('access_token')?.value;

  if (!token) {
    // Differentiate page requests from API requests
    if (pathname.startsWith('/api/')) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    return NextResponse.redirect(new URL('/login', request.url));
  }

  const payload = await verifyAccessToken(token);

  if (!payload) {
    const response = pathname.startsWith('/api/')
      ? NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
      : NextResponse.redirect(new URL('/login', request.url));

    // Clear invalid/expired cookie so the client re-authenticates
    response.cookies.delete('access_token');
    return response;
  }

  // Forward verified identity downstream via request headers
  // These are server-internal headers — they are NOT exposed to the browser
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-user-id', payload.sub);
  requestHeaders.set('x-user-role', payload.role);
  requestHeaders.set('x-user-email', payload.email);

  return NextResponse.next({ request: { headers: requestHeaders } });
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
```

---

## 3. Session Management

Database-backed sessions are appropriate when you need server-side revocation (e.g., force-logout all devices, revoke on password change). The session ID is an opaque token — user data lives in the database, not in the cookie.

```bash
pnpm add crypto  # built-in to Node.js, no install needed
```

### Session Store

```typescript
// lib/session.ts
import 'server-only';
import { cookies } from 'next/headers';
import { prisma } from '@/lib/db';
import crypto from 'node:crypto';
import { cache } from 'react';

const SESSION_COOKIE = 'session_id';
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;       // 24 hours
const SESSION_TTL_S = SESSION_TTL_MS / 1000;

// --- Create ---

export async function createSession(
  userId: string,
  metadata?: { userAgent?: string; ipAddress?: string },
): Promise<void> {
  // Cryptographically secure random session ID
  const sessionId = crypto.randomBytes(32).toString('hex');

  await prisma.session.create({
    data: {
      id: sessionId,
      userId,
      expiresAt: new Date(Date.now() + SESSION_TTL_MS),
      userAgent: metadata?.userAgent ?? null,
      ipAddress: metadata?.ipAddress ?? null,
    },
  });

  const cookieStore = await cookies(); // await required in Next.js 16+
  cookieStore.set(SESSION_COOKIE, sessionId, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    maxAge: SESSION_TTL_S,
  });
}

// --- Read ---

// cache() deduplicates calls within a single request — safe to call in
// multiple Server Components without extra DB round-trips
export const getSession = cache(async () => {
  const cookieStore = await cookies();
  const sessionId = cookieStore.get(SESSION_COOKIE)?.value;
  if (!sessionId) return null;

  const session = await prisma.session.findUnique({
    where: { id: sessionId },
    include: {
      user: { select: { id: true, email: true, role: true, name: true } },
    },
  });

  if (!session || session.expiresAt < new Date()) {
    // Expired — clean up
    if (session) {
      await prisma.session.delete({ where: { id: sessionId } }).catch(() => {});
    }
    (await cookies()).delete(SESSION_COOKIE);
    return null;
  }

  return session;
});

// --- Session Rotation on Privilege Change ---

export async function rotateSession(userId: string): Promise<void> {
  const cookieStore = await cookies();
  const oldSessionId = cookieStore.get(SESSION_COOKIE)?.value;

  // Invalidate old session
  if (oldSessionId) {
    await prisma.session.delete({ where: { id: oldSessionId } }).catch(() => {});
  }

  // Issue new session — prevents session fixation attacks
  await createSession(userId);
}

// --- Destroy ---

export async function destroySession(): Promise<void> {
  const cookieStore = await cookies();
  const sessionId = cookieStore.get(SESSION_COOKIE)?.value;

  if (sessionId) {
    await prisma.session.delete({ where: { id: sessionId } }).catch(() => {});
  }

  cookieStore.delete(SESSION_COOKIE);
}

export async function destroyAllSessions(userId: string): Promise<void> {
  await prisma.session.deleteMany({ where: { userId } });
  (await cookies()).delete(SESSION_COOKIE);
}
```

### Cookie Security Attributes Explained

| Attribute | Value | Why |
|---|---|---|
| `httpOnly` | `true` | JavaScript cannot read the cookie — prevents XSS token theft |
| `secure` | `true` in production | Cookie only sent over HTTPS |
| `sameSite` | `'lax'` | Sent on top-level navigations but not cross-site sub-requests — CSRF protection |
| `path` | `'/'` | Available across the whole app |
| `maxAge` | Matches session TTL | Browser clears cookie after expiry |

**BAD — missing security attributes:**

```typescript
// BAD: No httpOnly, no sameSite, no secure
cookieStore.set('session_id', sessionId);
```

**GOOD — all security attributes set:**

```typescript
// GOOD
cookieStore.set('session_id', sessionId, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax',
  path: '/',
  maxAge: 86400,
});
```

---

## 4. Role-Based Access Control (RBAC)

### Role Hierarchy

Define roles as a numeric hierarchy so you can express "at least moderator" checks simply.

```typescript
// lib/rbac.ts
export const ROLES = {
  user: 1,
  moderator: 2,
  admin: 3,
} as const;

export type Role = keyof typeof ROLES;

export function hasRole(userRole: Role, requiredRole: Role): boolean {
  return ROLES[userRole] >= ROLES[requiredRole];
}

export function requireRole(userRole: Role | undefined, required: Role): void {
  if (!userRole || !hasRole(userRole, required)) {
    throw new Error('Forbidden');
  }
}
```

### Middleware Enforcement

```typescript
// middleware.ts (RBAC layer — builds on the JWT middleware from section 2)
import { NextRequest, NextResponse } from 'next/server';
import { verifyAccessToken } from '@/lib/jwt';
import { hasRole, type Role } from '@/lib/rbac';

// Map route prefixes to minimum required role
const ROUTE_ROLES: Array<{ prefix: string; role: Role }> = [
  { prefix: '/admin', role: 'admin' },
  { prefix: '/api/admin', role: 'admin' },
  { prefix: '/moderation', role: 'moderator' },
  { prefix: '/api/moderation', role: 'moderator' },
];

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const token = request.cookies.get('access_token')?.value;

  if (!token) {
    return pathname.startsWith('/api/')
      ? NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
      : NextResponse.redirect(new URL('/login', request.url));
  }

  const payload = await verifyAccessToken(token);
  if (!payload) {
    return pathname.startsWith('/api/')
      ? NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
      : NextResponse.redirect(new URL('/login', request.url));
  }

  // Check if this route requires an elevated role
  const routeRule = ROUTE_ROLES.find((r) => pathname.startsWith(r.prefix));
  if (routeRule && !hasRole(payload.role as Role, routeRule.role)) {
    return pathname.startsWith('/api/')
      ? NextResponse.json({ error: 'Forbidden' }, { status: 403 })
      : NextResponse.redirect(new URL('/unauthorized', request.url));
  }

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-user-id', payload.sub);
  requestHeaders.set('x-user-role', payload.role);

  return NextResponse.next({ request: { headers: requestHeaders } });
}
```

### Server Component Guards

**BAD — client-side only role check:**

```typescript
// BAD: Client component checks role — user can manipulate this
'use client';

export function AdminPanel({ userRole }: { userRole: string }) {
  if (userRole !== 'admin') return null; // Data still sent to client!
  return <SensitiveAdminContent />;
}
```

**GOOD — server-side role enforcement:**

```typescript
// GOOD: Server Component verifies role before rendering
// app/admin/page.tsx
import { auth } from '@/lib/auth';
import { hasRole } from '@/lib/rbac';
import { redirect } from 'next/navigation';

export default async function AdminPage() {
  const session = await auth();

  if (!session?.user) {
    redirect('/login');
  }

  if (!hasRole(session.user.role as Role, 'admin')) {
    redirect('/unauthorized');
  }

  return <AdminDashboard />;
}
```

### Server Action Authorization

```typescript
// actions/admin.ts
'use server';

import { auth } from '@/lib/auth';
import { hasRole, type Role } from '@/lib/rbac';
import { z } from 'zod';

const banUserSchema = z.object({
  userId: z.string().cuid(),
  reason: z.string().min(1).max(500),
});

export async function banUser(formData: FormData) {
  // 1. Authenticate
  const session = await auth();
  if (!session?.user) {
    throw new Error('Unauthorized');
  }

  // 2. Authorize — require moderator or above
  if (!hasRole(session.user.role as Role, 'moderator')) {
    throw new Error('Forbidden');
  }

  // 3. Validate input
  const parsed = banUserSchema.safeParse({
    userId: formData.get('userId'),
    reason: formData.get('reason'),
  });
  if (!parsed.success) {
    return { error: 'Invalid input' };
  }

  // 4. Prevent self-ban
  if (parsed.data.userId === session.user.id) {
    return { error: 'Cannot ban yourself' };
  }

  // 5. Execute with scoped action
  await prisma.user.update({
    where: { id: parsed.data.userId },
    data: { bannedAt: new Date(), banReason: parsed.data.reason },
  });

  return { success: true };
}
```

---

## 5. Data Access Layer (DAL)

The DAL centralizes all authorized data fetching. It uses `server-only` to prevent client imports and React's `cache()` to deduplicate DB queries within a single request.

```bash
pnpm add server-only
```

```typescript
// lib/dal.ts
import 'server-only';
import { cache } from 'react';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/db';
import { hasRole, type Role } from '@/lib/rbac';

// --- Current User ---

// cache() ensures this DB call runs at most once per request,
// regardless of how many Server Components call it
export const getCurrentUser = cache(async () => {
  const session = await auth();
  if (!session?.user?.id) return null;

  return prisma.user.findUnique({
    where: { id: session.user.id },
    select: {
      id: true,
      email: true,
      name: true,
      role: true,
      createdAt: true,
      // Never select passwordHash, mfaSecret, or other sensitive fields
    },
  });
});

// --- Projects (scoped to authenticated user) ---

export const getUserProjects = cache(async () => {
  const user = await getCurrentUser();
  if (!user) throw new Error('Unauthorized');

  // Always scope queries to the authenticated user
  return prisma.project.findMany({
    where: { userId: user.id },
    select: {
      id: true,
      name: true,
      description: true,
      createdAt: true,
    },
    orderBy: { createdAt: 'desc' },
  });
});

// --- Single Project (with ownership check) ---

export const getProject = cache(async (projectId: string) => {
  const user = await getCurrentUser();
  if (!user) throw new Error('Unauthorized');

  const project = await prisma.project.findFirst({
    where: {
      id: projectId,
      userId: user.id, // Ownership check — prevents IDOR
    },
  });

  return project ?? null;
});

// --- Admin-Only Query ---

export const getAllUsers = cache(async () => {
  const user = await getCurrentUser();
  if (!user) throw new Error('Unauthorized');
  if (!hasRole(user.role as Role, 'admin')) throw new Error('Forbidden');

  return prisma.user.findMany({
    select: {
      id: true,
      email: true,
      name: true,
      role: true,
      createdAt: true,
      // Still never select passwordHash
    },
    orderBy: { createdAt: 'desc' },
  });
});
```

**Usage in Server Components — call DAL functions directly:**

```typescript
// app/projects/page.tsx
import { getUserProjects } from '@/lib/dal';
import { redirect } from 'next/navigation';

export default async function ProjectsPage() {
  let projects;
  try {
    projects = await getUserProjects();
  } catch (error) {
    redirect('/login');
  }

  return (
    <ul>
      {projects.map((p) => (
        <li key={p.id}>{p.name}</li>
      ))}
    </ul>
  );
}
```

**Why this pattern is secure:**

- `server-only` throws a build-time error if any Client Component imports from `lib/dal.ts`
- Auth check is embedded in every function — no way to accidentally call an unprotected version
- `cache()` prevents N+1 auth queries when the same user is needed by multiple components

---

## 6. OAuth PKCE Flow

PKCE (Proof Key for Code Exchange) prevents authorization code interception attacks. Always use PKCE for OAuth flows in Next.js, even with confidential clients.

### PKCE Helpers

```typescript
// lib/pkce.ts
import crypto from 'node:crypto';

export function generateCodeVerifier(): string {
  // RFC 7636 — 43-128 character base64url string
  return crypto.randomBytes(32).toString('base64url');
}

export function generateCodeChallenge(verifier: string): string {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

export function generateState(): string {
  // Cryptographically random state — used as CSRF token for the OAuth flow
  return crypto.randomBytes(16).toString('hex');
}
```

### Authorization Route — Initiate the Flow

```typescript
// app/api/auth/oauth/[provider]/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { generateCodeVerifier, generateCodeChallenge, generateState } from '@/lib/pkce';
import { z } from 'zod';

const PROVIDER_CONFIGS = {
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
} as const;

type Provider = keyof typeof PROVIDER_CONFIGS;

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ provider: string }> },
) {
  const { provider } = await params; // await required in Next.js 16+

  if (!(provider in PROVIDER_CONFIGS)) {
    return NextResponse.json({ error: 'Unknown provider' }, { status: 400 });
  }

  const config = PROVIDER_CONFIGS[provider as Provider];
  const verifier = generateCodeVerifier();
  const challenge = generateCodeChallenge(verifier);
  const state = generateState();

  const cookieStore = await cookies();

  // Store verifier and state in short-lived httpOnly cookies
  cookieStore.set('pkce_verifier', verifier, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    maxAge: 10 * 60, // 10 minutes — OAuth flow must complete in this time
  });

  cookieStore.set('oauth_state', state, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    maxAge: 10 * 60,
  });

  const params_ = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: `${process.env.APP_URL}/api/auth/callback/${provider}`,
    response_type: 'code',
    scope: config.scopes.join(' '),
    state,                             // CSRF protection
    code_challenge: challenge,         // PKCE
    code_challenge_method: 'S256',
  });

  return NextResponse.redirect(`${config.authUrl}?${params_}`);
}
```

### Callback Route — Complete the Flow

```typescript
// app/api/auth/callback/[provider]/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { prisma } from '@/lib/db';
import { createSession } from '@/lib/session';

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ provider: string }> },
) {
  const { provider } = await params;
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const returnedState = url.searchParams.get('state');
  const error = url.searchParams.get('error');

  const cookieStore = await cookies();
  const storedState = cookieStore.get('oauth_state')?.value;
  const verifier = cookieStore.get('pkce_verifier')?.value;

  // Always clear OAuth cookies immediately — one-time use
  cookieStore.delete('oauth_state');
  cookieStore.delete('pkce_verifier');

  if (error) {
    return NextResponse.redirect(`${process.env.APP_URL}/login?error=oauth_denied`);
  }

  // Verify state — CSRF check
  if (!returnedState || !storedState || returnedState !== storedState) {
    return NextResponse.redirect(`${process.env.APP_URL}/login?error=invalid_state`);
  }

  if (!code || !verifier) {
    return NextResponse.redirect(`${process.env.APP_URL}/login?error=missing_code`);
  }

  try {
    // Exchange code for tokens using PKCE verifier
    const tokenResponse = await fetch(getTokenUrl(provider), {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: getClientId(provider),
        client_secret: getClientSecret(provider),
        code,
        redirect_uri: `${process.env.APP_URL}/api/auth/callback/${provider}`,
        code_verifier: verifier, // PKCE verification
      }),
    });

    if (!tokenResponse.ok) {
      throw new Error('Token exchange failed');
    }

    const tokens = await tokenResponse.json();
    const providerUser = await fetchProviderUser(provider, tokens.access_token);

    // Upsert user in database
    const user = await prisma.user.upsert({
      where: {
        providerAccount: {
          provider,
          providerAccountId: String(providerUser.id),
        },
      },
      create: {
        email: providerUser.email,
        name: providerUser.name,
        emailVerified: new Date(),
        accounts: {
          create: {
            provider,
            providerAccountId: String(providerUser.id),
          },
        },
      },
      update: {
        name: providerUser.name,
      },
    });

    await createSession(user.id);

    return NextResponse.redirect(`${process.env.APP_URL}/dashboard`);
  } catch (err) {
    console.error('OAuth callback error:', { provider, error: err });
    return NextResponse.redirect(`${process.env.APP_URL}/login?error=oauth_failed`);
  }
}
```

---

## 7. Token Refresh Pattern

Middleware-based silent refresh keeps users logged in without requiring them to re-authenticate when their short-lived access token expires.

```typescript
// middleware.ts
import { NextRequest, NextResponse } from 'next/server';
import {
  verifyAccessToken,
  verifyRefreshToken,
  signAccessToken,
  signRefreshToken,
} from '@/lib/jwt';
import { prisma } from '@/lib/db';
import crypto from 'node:crypto';

async function hashToken(token: string): Promise<string> {
  return crypto.createHash('sha256').update(token).digest('hex');
}

export async function middleware(request: NextRequest) {
  const accessToken = request.cookies.get('access_token')?.value;
  const refreshToken = request.cookies.get('refresh_token')?.value;

  // 1. Try the access token first
  if (accessToken) {
    const payload = await verifyAccessToken(accessToken);
    if (payload) {
      // Valid access token — pass identity downstream
      const headers = new Headers(request.headers);
      headers.set('x-user-id', payload.sub);
      headers.set('x-user-role', payload.role);
      return NextResponse.next({ request: { headers } });
    }
  }

  // 2. Access token missing or expired — try the refresh token
  if (refreshToken) {
    const refreshPayload = await verifyRefreshToken(refreshToken);

    if (refreshPayload) {
      // Verify the refresh token exists in the database (not revoked)
      const storedToken = await prisma.refreshToken.findFirst({
        where: {
          userId: refreshPayload.sub,
          tokenHash: await hashToken(refreshToken),
          expiresAt: { gt: new Date() },
          revokedAt: null,
        },
        include: {
          user: { select: { id: true, email: true, role: true } },
        },
      });

      if (storedToken) {
        // Rotate: revoke old refresh token, issue new pair
        await prisma.refreshToken.update({
          where: { id: storedToken.id },
          data: { revokedAt: new Date() },
        });

        const newAccessToken = await signAccessToken({
          sub: storedToken.user.id,
          email: storedToken.user.email,
          role: storedToken.user.role,
        });
        const newRefreshToken = await signRefreshToken(storedToken.user.id);

        await prisma.refreshToken.create({
          data: {
            userId: storedToken.user.id,
            tokenHash: await hashToken(newRefreshToken),
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
          },
        });

        const response = NextResponse.next({
          request: {
            headers: new Headers({
              ...Object.fromEntries(request.headers),
              'x-user-id': storedToken.user.id,
              'x-user-role': storedToken.user.role,
            }),
          },
        });

        // Set new cookies on the response
        const IS_PRODUCTION = process.env.NODE_ENV === 'production';
        response.cookies.set('access_token', newAccessToken, {
          httpOnly: true,
          secure: IS_PRODUCTION,
          sameSite: 'lax',
          path: '/',
          maxAge: 15 * 60,
        });
        response.cookies.set('refresh_token', newRefreshToken, {
          httpOnly: true,
          secure: IS_PRODUCTION,
          sameSite: 'lax',
          path: '/api/auth',
          maxAge: 7 * 24 * 60 * 60,
        });

        return response;
      }

      // Refresh token reuse detected — revoke all tokens for this user
      console.warn('Possible refresh token reuse:', { userId: refreshPayload.sub });
      await prisma.refreshToken.updateMany({
        where: { userId: refreshPayload.sub },
        data: { revokedAt: new Date() },
      });
    }
  }

  // 3. No valid tokens — redirect or 401
  const { pathname } = request.nextUrl;
  if (pathname.startsWith('/api/')) {
    const response = NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    response.cookies.delete('access_token');
    response.cookies.delete('refresh_token');
    return response;
  }

  const response = NextResponse.redirect(new URL('/login', request.url));
  response.cookies.delete('access_token');
  response.cookies.delete('refresh_token');
  return response;
}
```

---

## 8. Multi-Factor Authentication (MFA)

### Dependencies

```bash
pnpm add otplib qrcode
pnpm add -D @types/qrcode
```

### TOTP Setup Flow

```typescript
// lib/mfa.ts
import 'server-only';
import { authenticator } from 'otplib';
import QRCode from 'qrcode';
import crypto from 'node:crypto';
import { prisma } from '@/lib/db';

authenticator.options = {
  window: 1, // Accept current and ±1 time step (30s tolerance)
};

// --- Setup ---

export async function initiateMfaSetup(
  userId: string,
  email: string,
): Promise<{ qrCodeDataUrl: string; secret: string; backupCodes: string[] }> {
  const secret = authenticator.generateSecret(32);
  const otpauth = authenticator.keyuri(email, process.env.APP_NAME ?? 'App', secret);
  const qrCodeDataUrl = await QRCode.toDataURL(otpauth);

  // Generate 10 single-use backup codes
  const backupCodes = Array.from({ length: 10 }, () =>
    crypto.randomBytes(5).toString('hex').toUpperCase(),
  );

  // Hash backup codes before storing — treat them like passwords
  const hashedBackupCodes = await Promise.all(
    backupCodes.map(async (code) => ({
      userId,
      codeHash: crypto.createHash('sha256').update(code).digest('hex'),
    })),
  );

  // Store pending setup — not enabled until verified
  await prisma.$transaction([
    prisma.mfaPending.upsert({
      where: { userId },
      create: { userId, secret },
      update: { secret, createdAt: new Date() },
    }),
    prisma.backupCode.deleteMany({ where: { userId } }),
    prisma.backupCode.createMany({ data: hashedBackupCodes }),
  ]);

  return { qrCodeDataUrl, secret, backupCodes };
}

// --- Verify and Enable ---

export async function confirmMfaSetup(
  userId: string,
  totpCode: string,
): Promise<boolean> {
  const pending = await prisma.mfaPending.findUnique({ where: { userId } });
  if (!pending) return false;

  const isValid = authenticator.verify({ token: totpCode, secret: pending.secret });
  if (!isValid) return false;

  // Activate MFA
  await prisma.$transaction([
    prisma.user.update({
      where: { id: userId },
      data: { mfaEnabled: true, mfaSecret: pending.secret },
    }),
    prisma.mfaPending.delete({ where: { userId } }),
  ]);

  return true;
}

// --- Verify TOTP ---

export async function verifyTotp(
  userId: string,
  token: string,
): Promise<boolean> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { mfaSecret: true },
  });

  if (!user?.mfaSecret) return false;
  return authenticator.verify({ token, secret: user.mfaSecret });
}

// --- Verify Backup Code ---

export async function verifyBackupCode(
  userId: string,
  code: string,
): Promise<boolean> {
  const codeHash = crypto.createHash('sha256').update(code.toUpperCase()).digest('hex');

  const record = await prisma.backupCode.findFirst({
    where: { userId, codeHash, usedAt: null },
  });

  if (!record) return false;

  // Single-use — mark as consumed immediately
  await prisma.backupCode.update({
    where: { id: record.id },
    data: { usedAt: new Date() },
  });

  return true;
}
```

### MFA Login Route

```typescript
// app/api/auth/login/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { verifyPassword } from '@/lib/password';
import { verifyTotp, verifyBackupCode } from '@/lib/mfa';
import { createSession } from '@/lib/session';
import { z } from 'zod';

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
  totpCode: z.string().optional(),
});

const GENERIC_ERROR = 'Invalid credentials';

export async function POST(request: NextRequest) {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
  }

  const parsed = loginSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: GENERIC_ERROR }, { status: 401 });
  }

  const { email, password, totpCode } = parsed.data;

  const user = await prisma.user.findUnique({
    where: { email },
    select: {
      id: true,
      email: true,
      passwordHash: true,
      mfaEnabled: true,
    },
  });

  // Always call verifyPassword to prevent timing-based enumeration
  const dummyHash = '$argon2id$v=19$m=65536,t=3,p=4$placeholder$placeholder';
  const passwordValid = user
    ? await verifyPassword(password, user.passwordHash)
    : await verifyPassword(password, dummyHash).then(() => false);

  if (!user || !passwordValid) {
    return NextResponse.json({ error: GENERIC_ERROR }, { status: 401 });
  }

  // MFA check
  if (user.mfaEnabled) {
    if (!totpCode) {
      // Signal to the client that MFA is required for this account
      return NextResponse.json({ mfaRequired: true }, { status: 200 });
    }

    const mfaValid =
      (await verifyTotp(user.id, totpCode)) ||
      (await verifyBackupCode(user.id, totpCode));

    if (!mfaValid) {
      return NextResponse.json({ error: 'Invalid MFA code' }, { status: 401 });
    }
  }

  await createSession(user.id);
  return NextResponse.json({ success: true });
}
```

---

## 9. Logout and Session Invalidation

A proper logout must: delete the cookie, invalidate the server-side session record, and revalidate any cached pages that contain user-specific data.

### Logout Server Action

```typescript
// actions/auth.ts
'use server';

import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { revalidatePath } from 'next/cache';
import { prisma } from '@/lib/db';
import { auth } from '@/lib/auth';

export async function logout() {
  const session = await auth();

  const cookieStore = await cookies(); // await required in Next.js 16+
  const sessionId = cookieStore.get('session_id')?.value;

  // 1. Delete server-side session record — prevents reuse even if cookie is replayed
  if (sessionId) {
    await prisma.session.delete({ where: { id: sessionId } }).catch(() => {});
  }

  // 2. Clear all auth cookies
  cookieStore.delete('session_id');
  cookieStore.delete('access_token');
  cookieStore.delete('refresh_token');

  // 3. Revoke all refresh tokens for this user (optional: logout everywhere)
  if (session?.user?.id) {
    await prisma.refreshToken.updateMany({
      where: { userId: session.user.id, revokedAt: null },
      data: { revokedAt: new Date() },
    });
  }

  // 4. Revalidate cached pages so stale user data is not served
  revalidatePath('/', 'layout'); // Revalidates all pages under the root layout

  // 5. Redirect to login
  redirect('/login');
}
```

### Logout Route Handler (for API clients)

```typescript
// app/api/auth/logout/route.ts
import { NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { prisma } from '@/lib/db';
import { verifyAccessToken } from '@/lib/jwt';

export async function POST() {
  const cookieStore = await cookies();

  const accessToken = cookieStore.get('access_token')?.value;
  const refreshToken = cookieStore.get('refresh_token')?.value;

  // Revoke refresh token in database
  if (refreshToken) {
    const payload = await verifyAccessToken(accessToken ?? '');
    if (payload) {
      await prisma.refreshToken.updateMany({
        where: { userId: payload.sub, revokedAt: null },
        data: { revokedAt: new Date() },
      });
    }
  }

  // Build response and clear cookies by setting maxAge=0
  const response = NextResponse.json({ success: true });
  response.cookies.set('access_token', '', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    maxAge: 0, // Immediately expired — browser deletes the cookie
  });
  response.cookies.set('refresh_token', '', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/api/auth',
    maxAge: 0,
  });

  return response;
}
```

### Why `revalidatePath` Matters

Next.js caches page renders. Without revalidation after logout, a user visiting a cached route could see another user's data if the cache is shared or if the response is served from the CDN.

**BAD — logout without cache invalidation:**

```typescript
// BAD: Cookie deleted but cached pages may still serve stale user data
export async function logout() {
  (await cookies()).delete('session_id');
  redirect('/login');
}
```

**GOOD — invalidate cache on logout:**

```typescript
// GOOD
export async function logout() {
  (await cookies()).delete('session_id');
  revalidatePath('/', 'layout'); // Clear all cached page renders
  redirect('/login');
}
```

---

## Security Checklist for Auth Implementations

Before shipping any authentication feature:

- [ ] Passwords hashed with argon2id or bcrypt (cost >= 12) — never stored plaintext
- [ ] Auth tokens stored in `httpOnly` cookies, never `localStorage`
- [ ] Cookies set with `secure: true` in production, `sameSite: 'lax'`, and `path`
- [ ] Short-lived access tokens (15 minutes), longer refresh tokens (7 days)
- [ ] Refresh tokens rotated on every use and invalidated on logout
- [ ] All auth endpoints rate-limited (login, register, password reset)
- [ ] Constant-time credential comparison to prevent timing-based user enumeration
- [ ] Generic error messages on failed auth (`'Invalid credentials'`, not `'User not found'`)
- [ ] Session invalidated server-side on logout — not just cookie deletion
- [ ] `revalidatePath` called after auth state changes to clear cached renders
- [ ] PKCE used for all OAuth flows
- [ ] State parameter verified on OAuth callbacks (CSRF protection)
- [ ] MFA verification applied before session creation, not after
- [ ] DAL functions import `server-only` to prevent client-side use
- [ ] All `cookies()`, `headers()`, and `params` awaited (Next.js 16+)

---

## Quick Reference — Library Versions

Check current versions before installing:

```bash
pnpm info next-auth version       # Auth.js v5+
pnpm info jose version
pnpm info otplib version
pnpm info qrcode version
pnpm info @upstash/ratelimit version
pnpm info @upstash/redis version
pnpm info zod version
```

---

*This reference is maintained by [TamperTantrum Labs](https://tampertantrum.com) — making application security accessible, human, and empowering.*
