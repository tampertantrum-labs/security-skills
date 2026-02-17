# Next.js Middleware Recipes

A comprehensive collection of copy-pasteable middleware recipes for Next.js 16+ App Router.

> **Version note:** These examples target Next.js 16+. In this version, `headers()`, `cookies()`, and route `params` are all async and must be awaited in Server Components and Route Handlers. In `middleware.ts` itself, `request.cookies` remains synchronous because it is a property on the `NextRequest` object, not the `cookies()` function from `next/headers`.

---

## Table of Contents

1. [Auth Guard Middleware](#1-auth-guard-middleware)
2. [CSP Nonce Middleware](#2-csp-nonce-middleware)
3. [Rate Limiting Middleware](#3-rate-limiting-middleware)
4. [Geo-Blocking and IP Filtering](#4-geo-blocking-and-ip-filtering)
5. [Bot Detection Middleware](#5-bot-detection-middleware)
6. [CORS Middleware](#6-cors-middleware)
7. [Redirect Middleware](#7-redirect-middleware)
8. [Request Logging and Audit Trail](#8-request-logging-and-audit-trail)
9. [Composing Multiple Middlewares](#9-composing-multiple-middlewares)
10. [Security Headers Middleware](#10-security-headers-middleware)

---

## 1. Auth Guard Middleware

Protects routes by authentication status. Redirects unauthenticated users to `/login` for page routes and returns 401 for API routes. Admins are checked separately.

```typescript
// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { verifyToken } from '@/lib/jwt';

/**
 * Route classification:
 * - publicRoutes: No auth required — anyone may access.
 * - protectedRoutes: Authenticated users only.
 * - adminRoutes: Admin role required.
 *
 * Matching is prefix-based. Order matters for overlapping prefixes.
 */
const publicRoutes = ['/', '/login', '/register', '/api/auth'];
const adminRoutes = ['/admin', '/api/admin'];

function isPublic(pathname: string): boolean {
  return publicRoutes.some((route) => pathname === route || pathname.startsWith(`${route}/`));
}

function isAdmin(pathname: string): boolean {
  return adminRoutes.some((route) => pathname === route || pathname.startsWith(`${route}/`));
}

function isApiRoute(pathname: string): boolean {
  return pathname.startsWith('/api/');
}

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Public routes — skip auth entirely.
  if (isPublic(pathname)) {
    return NextResponse.next();
  }

  // Read session token from cookie.
  // request.cookies is synchronous in middleware — it is on NextRequest, not next/headers.
  const token = request.cookies.get('session')?.value;

  if (!token) {
    if (isApiRoute(pathname)) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    // Encode the originally requested path so login can redirect back after success.
    const loginUrl = new URL('/login', request.url);
    loginUrl.searchParams.set('redirect', pathname);
    return NextResponse.redirect(loginUrl);
  }

  // Verify token. verifyToken returns null on failure — never throws to the middleware.
  const payload = await verifyToken(token);

  if (!payload) {
    // Token is invalid or expired. Clear it and send the user to login.
    if (isApiRoute(pathname)) {
      const response = NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
      response.cookies.delete('session');
      return response;
    }
    const response = NextResponse.redirect(new URL('/login', request.url));
    response.cookies.delete('session');
    return response;
  }

  // Admin routes — require explicit role check.
  if (isAdmin(pathname) && payload.role !== 'admin') {
    if (isApiRoute(pathname)) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
    }
    return NextResponse.redirect(new URL('/unauthorized', request.url));
  }

  // Forward verified identity to Server Components via request headers.
  // These headers are server-internal — they never reach the client.
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-user-id', payload.sub);
  requestHeaders.set('x-user-role', payload.role);

  return NextResponse.next({ request: { headers: requestHeaders } });
}

export const config = {
  matcher: [
    /*
     * Match every route except:
     * - _next/static  (static assets)
     * - _next/image   (image optimization)
     * - favicon.ico
     * - Files with a common static extension
     */
    '/((?!_next/static|_next/image|favicon\\.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico|css|js|woff2?)$).*)',
  ],
};
```

**Reading the forwarded identity in a Server Component:**

```typescript
// app/dashboard/page.tsx
import { headers } from 'next/headers';

export default async function DashboardPage() {
  const headerStore = await headers();
  const userId = headerStore.get('x-user-id');
  const role = headerStore.get('x-user-role');

  // userId and role are guaranteed present — middleware already checked auth.
  return <div>User {userId} ({role})</div>;
}
```

---

## 2. CSP Nonce Middleware

Generates a per-request cryptographic nonce and wires it into the Content Security Policy header. The nonce is placed on **request** headers so Server Components can read it via `await headers()`. It must never appear on response headers — that would leak it to the network and defeat its purpose.

```typescript
// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  // Generate a fresh nonce for every request.
  const nonce = Buffer.from(crypto.randomUUID()).toString('base64');

  const csp = buildCsp(nonce);

  // Set nonce on REQUEST headers — server-internal only, never sent to the browser.
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);

  // Apply CSP on the RESPONSE — this is what the browser enforces.
  // The nonce value in the CSP policy must match the nonce attribute on inline scripts.
  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set('Content-Security-Policy', csp);

  return response;
}

function buildCsp(nonce: string): string {
  return [
    `default-src 'self'`,
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`,
    `style-src 'self' 'nonce-${nonce}'`,
    `img-src 'self' blob: data:`,
    `font-src 'self'`,
    `connect-src 'self'`,
    `object-src 'none'`,
    `base-uri 'self'`,
    `form-action 'self'`,
    `frame-ancestors 'none'`,
    `upgrade-insecure-requests`,
  ]
    .join('; ')
    .trim();
}

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon\\.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)',
  ],
};
```

**Reading the nonce in the root layout:**

```tsx
// app/layout.tsx
import { headers } from 'next/headers';

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  // headers() is async in Next.js 16+.
  const nonce = (await headers()).get('x-nonce') ?? '';

  return (
    <html lang="en">
      <body>
        {children}
        {/* The nonce attribute must match the value embedded in the CSP header. */}
        <script nonce={nonce} src="/scripts/analytics.js" />
      </body>
    </html>
  );
}
```

> **Why request headers and not response headers?**
> The browser enforces the nonce by comparing the `nonce` attribute on inline `<script>` tags against the value in the `Content-Security-Policy` response header. If you also exposed the nonce on the response headers (e.g., `x-nonce`), a network attacker or injected script could read it and use it to bypass the policy. Keeping the nonce exclusively on request headers means only server-side code (Server Components, Route Handlers) can see it.

---

## 3. Rate Limiting Middleware

Uses `@upstash/ratelimit` with Redis. Applies stricter limits to authentication endpoints and standard limits to general API routes. Falls back to IP-based limiting for unauthenticated requests and user-based limiting when a session is present.

**Install dependencies:**

```bash
pnpm add @upstash/ratelimit @upstash/redis
```

**Ratelimit configuration:**

```typescript
// lib/ratelimit.ts
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

const redis = Redis.fromEnv();

// General API: 60 requests per minute per identifier.
export const apiRatelimit = new Ratelimit({
  redis,
  limiter: Ratelimit.slidingWindow(60, '1 m'),
  prefix: 'rl:api',
});

// Auth endpoints: 5 attempts per 15 minutes per identifier.
// This limits brute-force and credential stuffing attacks.
export const authRatelimit = new Ratelimit({
  redis,
  limiter: Ratelimit.slidingWindow(5, '15 m'),
  prefix: 'rl:auth',
});
```

**Middleware:**

```typescript
// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { apiRatelimit, authRatelimit } from '@/lib/ratelimit';

function getIdentifier(request: NextRequest): string {
  // Prefer the user ID from a verified session header if already set upstream.
  const userId = request.headers.get('x-user-id');
  if (userId) return `user:${userId}`;

  // Fall back to IP address.
  const ip =
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ??
    request.ip ??
    'unknown';
  return `ip:${ip}`;
}

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Only rate-limit API routes.
  if (!pathname.startsWith('/api/')) {
    return NextResponse.next();
  }

  const identifier = getIdentifier(request);
  const isAuthPath = pathname.startsWith('/api/auth');

  const { success, limit, remaining, reset } = isAuthPath
    ? await authRatelimit.limit(identifier)
    : await apiRatelimit.limit(identifier);

  if (!success) {
    return NextResponse.json(
      { error: 'Too many requests. Please try again later.' },
      {
        status: 429,
        headers: {
          'X-RateLimit-Limit': String(limit),
          'X-RateLimit-Remaining': '0',
          'X-RateLimit-Reset': String(reset),
          'Retry-After': String(Math.ceil((reset - Date.now()) / 1000)),
        },
      }
    );
  }

  const response = NextResponse.next();
  response.headers.set('X-RateLimit-Limit', String(limit));
  response.headers.set('X-RateLimit-Remaining', String(remaining));
  response.headers.set('X-RateLimit-Reset', String(reset));
  return response;
}

export const config = {
  matcher: ['/api/:path*'],
};
```

> **Environment variables required:**
> ```bash
> UPSTASH_REDIS_REST_URL="https://..."
> UPSTASH_REDIS_REST_TOKEN="..."
> ```

---

## 4. Geo-Blocking and IP Filtering

Uses `request.geo` (populated by Vercel's edge network) and `request.ip` for access control. Shows both a country blocklist and an IP allowlist pattern. On non-Vercel deployments, populate geo data via a trusted header from your CDN or load balancer.

```typescript
// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// Countries blocked from accessing this application.
// Use ISO 3166-1 alpha-2 codes.
const BLOCKED_COUNTRIES = new Set(['XX', 'YY']);

// Trusted IPs always allowed regardless of other rules (e.g., office IPs, monitoring).
const ALLOWED_IPS = new Set(['203.0.113.10', '198.51.100.42']);

// Blocked IPs (known bad actors, abuse reports, etc.).
const BLOCKED_IPS = new Set(['192.0.2.1', '10.0.0.0']);

export function middleware(request: NextRequest) {
  const ip =
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ??
    request.ip ??
    null;

  // IP allowlist takes highest precedence.
  if (ip && ALLOWED_IPS.has(ip)) {
    return NextResponse.next();
  }

  // IP blocklist.
  if (ip && BLOCKED_IPS.has(ip)) {
    return new NextResponse('Access denied.', { status: 403 });
  }

  // Country blocklist.
  // request.geo is populated by the Vercel edge runtime.
  const country = request.geo?.country;
  if (country && BLOCKED_COUNTRIES.has(country)) {
    return new NextResponse('This service is not available in your region.', {
      status: 451, // 451 Unavailable For Legal Reasons
    });
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon\\.ico).*)'],
};
```

> **Self-hosted deployments:** `request.geo` is `undefined` outside Vercel. Use a GeoIP service (e.g., MaxMind GeoIP2) in a separate lookup, or forward a trusted `CF-IPCountry` header from Cloudflare.

---

## 5. Bot Detection Middleware

Filters known bad user agents and routes suspicious traffic to a challenge page. This is a lightweight first pass — complement it with a CAPTCHA or turnstile service for higher-assurance scenarios.

```typescript
// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// Patterns that identify malicious or unwanted bots.
// This list is illustrative — maintain your own based on observed traffic.
const BLOCKED_UA_PATTERNS = [
  /sqlmap/i,
  /nikto/i,
  /masscan/i,
  /zgrab/i,
  /nmap/i,
  /python-requests\/[01]\./i, // Very old requests versions used by scrapers
  /go-http-client\/1\.0/i,
];

// Known good bots that should be allowed (search engines, monitoring, etc.).
const ALLOWED_BOT_PATTERNS = [
  /Googlebot/i,
  /Bingbot/i,
  /Slurp/i, // Yahoo
  /DuckDuckBot/i,
  /facebookexternalhit/i,
  /Twitterbot/i,
  /UptimeRobot/i,
];

function classifyRequest(userAgent: string): 'allowed' | 'blocked' | 'challenge' {
  if (!userAgent) return 'challenge';

  // Explicitly allowed bots skip all checks.
  if (ALLOWED_BOT_PATTERNS.some((pattern) => pattern.test(userAgent))) {
    return 'allowed';
  }

  // Explicitly blocked patterns.
  if (BLOCKED_UA_PATTERNS.some((pattern) => pattern.test(userAgent))) {
    return 'blocked';
  }

  // No user agent at all is suspicious but may be a legitimate headless client.
  return 'allowed';
}

export function middleware(request: NextRequest) {
  const userAgent = request.headers.get('user-agent') ?? '';
  const classification = classifyRequest(userAgent);

  if (classification === 'blocked') {
    return new NextResponse('Forbidden', { status: 403 });
  }

  if (classification === 'challenge') {
    // Redirect to a challenge page that can present a CAPTCHA.
    const challengeUrl = new URL('/challenge', request.url);
    challengeUrl.searchParams.set('redirect', request.nextUrl.pathname);
    return NextResponse.redirect(challengeUrl);
  }

  return NextResponse.next();
}

export const config = {
  // Apply to all page routes. Exclude static files and API routes if desired.
  matcher: ['/((?!_next/static|_next/image|favicon\\.ico|api/).*)'],
};
```

---

## 6. CORS Middleware

Handles cross-origin requests for API routes. Processes preflight `OPTIONS` requests and adds the appropriate `Access-Control-*` headers to actual requests. Validates the `Origin` header against an allowlist rather than using a wildcard.

```typescript
// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

const ALLOWED_ORIGINS = new Set([
  'https://app.example.com',
  'https://www.example.com',
  // Add development origins when NODE_ENV is development:
  ...(process.env.NODE_ENV === 'development'
    ? ['http://localhost:3000', 'http://localhost:3001']
    : []),
]);

const ALLOWED_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];
const ALLOWED_HEADERS = ['Content-Type', 'Authorization', 'X-Requested-With'];
const MAX_AGE = 86400; // 24 hours — how long browsers cache preflight results

function getCorsHeaders(origin: string | null): Record<string, string> {
  const isAllowed = origin !== null && ALLOWED_ORIGINS.has(origin);

  return {
    'Access-Control-Allow-Origin': isAllowed ? origin! : '',
    'Access-Control-Allow-Methods': ALLOWED_METHODS.join(', '),
    'Access-Control-Allow-Headers': ALLOWED_HEADERS.join(', '),
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Max-Age': String(MAX_AGE),
    Vary: 'Origin', // Required when the allowed origin is dynamic, not '*'
  };
}

export function middleware(request: NextRequest) {
  const origin = request.headers.get('origin');
  const corsHeaders = getCorsHeaders(origin);

  // Remove empty header values — an empty Allow-Origin is equivalent to blocking.
  const cleanHeaders = Object.fromEntries(
    Object.entries(corsHeaders).filter(([, v]) => v !== '')
  );

  // Preflight request — respond immediately with CORS headers and no body.
  if (request.method === 'OPTIONS') {
    return new NextResponse(null, { status: 204, headers: cleanHeaders });
  }

  // For actual requests, forward to the route handler and attach CORS headers.
  const response = NextResponse.next();
  Object.entries(cleanHeaders).forEach(([key, value]) => {
    response.headers.set(key, value);
  });

  return response;
}

export const config = {
  matcher: ['/api/:path*'],
};
```

> **Never use `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`.** Browsers reject this combination. Always use an explicit allowlist when credentials (cookies, Authorization headers) are involved.

---

## 7. Redirect Middleware

Handles redirects safely. The critical rule: when the redirect destination comes from user-supplied input (e.g., a `?redirect=` query parameter), always validate that the URL is same-origin before redirecting. Failing to do this creates an open redirect vulnerability.

```typescript
// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { verifyToken } from '@/lib/jwt';

/**
 * Validates that a redirect path is safe to follow.
 * Returns the path if safe, or a fallback if not.
 *
 * Safe means:
 * - It is a relative path (starts with '/').
 * - It does not start with '//' (which browsers interpret as protocol-relative).
 * - It does not contain a scheme (e.g., 'javascript:').
 */
function getSafeRedirect(candidate: string | null, fallback = '/'): string {
  if (!candidate) return fallback;

  // Decode to catch encoded variants like %2F%2Fevil.com or javascript%3A
  let decoded: string;
  try {
    decoded = decodeURIComponent(candidate);
  } catch {
    return fallback;
  }

  // Must start with exactly one slash (relative path) and not contain a colon
  // before the first slash (which would indicate a scheme).
  const isSafePath = /^\/(?!\/)/.test(decoded) && !/^[^/]*:/.test(decoded);

  return isSafePath ? decoded : fallback;
}

export async function middleware(request: NextRequest) {
  const { pathname, searchParams } = request.nextUrl;

  // After successful login, redirect the user back to where they came from.
  if (pathname === '/login') {
    const token = request.cookies.get('session')?.value;
    if (token) {
      const payload = await verifyToken(token);
      if (payload) {
        // User is already authenticated — send them to the intended destination.
        const redirectParam = searchParams.get('redirect');
        const destination = getSafeRedirect(redirectParam, '/dashboard');
        return NextResponse.redirect(new URL(destination, request.url));
      }
    }
    return NextResponse.next();
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/login'],
};
```

**Bad patterns this prevents:**

```
// Open redirect via absolute URL
/login?redirect=https://evil.com/phishing

// Protocol-relative redirect
/login?redirect=//evil.com/phishing

// javascript: scheme
/login?redirect=javascript:alert(1)

// Encoded variants
/login?redirect=%2F%2Fevil.com
/login?redirect=javascript%3Aalert(1)
```

---

## 8. Request Logging and Audit Trail

Logs request metadata for security monitoring and audit purposes. Captures path, method, user identity, IP, and response status. Never logs tokens, passwords, cookies, or request bodies.

```typescript
// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

interface AuditEntry {
  timestamp: string;
  method: string;
  path: string;
  userId: string | null;
  ip: string | null;
  userAgent: string | null;
  requestId: string;
}

function buildAuditEntry(request: NextRequest): AuditEntry {
  return {
    timestamp: new Date().toISOString(),
    method: request.method,
    // Log the pathname only — never log query strings (may contain tokens or PII).
    path: request.nextUrl.pathname,
    // User ID forwarded from auth middleware (already verified).
    userId: request.headers.get('x-user-id'),
    // Take only the first IP from x-forwarded-for (closest client).
    ip:
      request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ??
      request.ip ??
      null,
    // Truncate user agent to prevent log injection via oversized strings.
    userAgent: (request.headers.get('user-agent') ?? '').slice(0, 256) || null,
    requestId: request.headers.get('x-request-id') ?? crypto.randomUUID(),
  };
}

export async function middleware(request: NextRequest) {
  const entry = buildAuditEntry(request);

  // Assign a request ID so the entry can be correlated with downstream logs.
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-request-id', entry.requestId);

  const response = NextResponse.next({ request: { headers: requestHeaders } });

  // Log after the response is constructed so we have the status code available.
  // In production, replace console.log with your structured logging service.
  console.log(JSON.stringify({ ...entry, status: response.status }));

  return response;
}

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon\\.ico).*)',
  ],
};
```

**What to log:**

| Field | Log? | Reason |
|---|---|---|
| Request path (no query string) | Yes | Needed for audit trail |
| HTTP method | Yes | Needed for audit trail |
| User ID (from verified session) | Yes | Needed for accountability |
| IP address | Yes | Needed for abuse detection |
| User agent (truncated) | Yes | Helps detect bots and anomalies |
| Request ID | Yes | Correlates logs across services |
| Session token / cookie value | Never | Allows session hijacking if logs leak |
| Authorization header value | Never | Same as above |
| Query string | Never | May contain tokens, reset codes, PII |
| Request body | Never | May contain passwords, PII |

---

## 9. Composing Multiple Middlewares

Next.js only supports a single `middleware.ts` file. This pattern composes multiple independent middleware functions into one clean pipeline. Each function receives the request and the next handler, allowing it to short-circuit the chain by returning early.

```typescript
// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// Type for a middleware function in the composition chain.
type MiddlewareFn = (
  request: NextRequest,
  next: () => Promise<NextResponse>
) => Promise<NextResponse>;

/**
 * Composes an array of middleware functions into a single handler.
 * Each function can either call `next()` to continue the chain
 * or return a response directly to short-circuit it.
 */
function compose(...fns: MiddlewareFn[]) {
  return async function composedMiddleware(request: NextRequest): Promise<NextResponse> {
    let index = -1;

    async function dispatch(i: number): Promise<NextResponse> {
      if (i <= index) {
        throw new Error('next() called multiple times in the same middleware');
      }
      index = i;

      if (i >= fns.length) {
        return NextResponse.next();
      }

      return fns[i](request, () => dispatch(i + 1));
    }

    return dispatch(0);
  };
}

// --- Individual middleware functions ---

const withSecurityHeaders: MiddlewareFn = async (request, next) => {
  const response = await next();
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  return response;
};

const withRateLimit: MiddlewareFn = async (request, next) => {
  // Insert rate-limiting logic here (see Recipe 3).
  // Return 429 to short-circuit, or call next() to continue.
  return next();
};

const withAuthGuard: MiddlewareFn = async (request, next) => {
  const { pathname } = request.nextUrl;
  const publicPaths = ['/', '/login', '/register', '/api/auth'];

  if (publicPaths.some((p) => pathname === p || pathname.startsWith(`${p}/`))) {
    return next();
  }

  const token = request.cookies.get('session')?.value;
  if (!token) {
    if (pathname.startsWith('/api/')) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    return NextResponse.redirect(new URL('/login', request.url));
  }

  return next();
};

const withAuditLog: MiddlewareFn = async (request, next) => {
  const start = Date.now();
  const response = await next();
  const duration = Date.now() - start;
  console.log(
    JSON.stringify({
      method: request.method,
      path: request.nextUrl.pathname,
      status: response.status,
      duration,
    })
  );
  return response;
};

// --- Composed handler ---

const handler = compose(
  withAuditLog,       // Outermost: wraps everything, measures duration
  withSecurityHeaders, // Applied to all responses
  withRateLimit,      // Before auth so even unauthenticated requests are limited
  withAuthGuard       // Innermost: only runs if not rate-limited
);

export function middleware(request: NextRequest): Promise<NextResponse> {
  return handler(request);
}

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon\\.ico).*)',
  ],
};
```

---

## 10. Security Headers Middleware

Sets the full suite of recommended HTTP security headers on every response. These complement CSP (Recipe 2) and should be applied globally.

```typescript
// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

/**
 * Security headers applied to all responses.
 *
 * Reference:
 *   - OWASP Secure Headers Project
 *   - https://securityheaders.com
 */
const SECURITY_HEADERS: Record<string, string> = {
  // Force HTTPS for 2 years, including subdomains, and submit to preload list.
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',

  // Prevent this page from being embedded in a frame on any other origin.
  // Use 'SAMEORIGIN' if you need same-origin framing (e.g., internal dashboards).
  'X-Frame-Options': 'DENY',

  // Stop browsers from MIME-sniffing away from the declared Content-Type.
  'X-Content-Type-Options': 'nosniff',

  // Send origin, path, and query string for same-origin; origin-only for cross-origin HTTPS;
  // nothing for cross-origin HTTP.
  'Referrer-Policy': 'strict-origin-when-cross-origin',

  // Restrict access to browser features. Adjust based on what your app actually needs.
  'Permissions-Policy': [
    'camera=()',
    'microphone=()',
    'geolocation=()',
    'payment=()',
    'usb=()',
    'interest-cohort=()', // Opt out of FLoC
  ].join(', '),

  // Tell browsers not to perform DNS prefetch (minor privacy improvement).
  'X-DNS-Prefetch-Control': 'off',

  // Disable the IE/Edge built-in XSS filter — it can itself introduce vulnerabilities.
  // Modern browsers have this disabled by default. CSP is the correct mitigation.
  'X-XSS-Protection': '0',
};

export function middleware(request: NextRequest) {
  const response = NextResponse.next();

  for (const [key, value] of Object.entries(SECURITY_HEADERS)) {
    response.headers.set(key, value);
  }

  return response;
}

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon\\.ico).*)',
  ],
};
```

> **`next.config.ts` vs. middleware:** Both can set headers. `next.config.ts` is simpler for static headers that never change. Middleware is required when headers must be dynamic per request (e.g., CSP with a nonce, CORS with a validated origin). For Security Headers Middleware where values are static, either approach works — middleware is shown here for consistency with the composition pattern in Recipe 9.

---

## Installation Reference

All packages used across these recipes:

```bash
pnpm add @upstash/ratelimit @upstash/redis
```

| Recipe | Package |
|---|---|
| Rate Limiting (3) | `@upstash/ratelimit`, `@upstash/redis` |
| All others | Next.js built-ins only |

---

## Quick-Reference: `request.cookies` vs. `cookies()`

| Context | How to read cookies | Sync or async |
|---|---|---|
| `middleware.ts` | `request.cookies.get('name')` | Synchronous |
| Server Component | `(await cookies()).get('name')` | Async (Next.js 16+) |
| Route Handler | `(await cookies()).get('name')` | Async (Next.js 16+) |
| Server Action | `(await cookies()).get('name')` | Async (Next.js 16+) |

---

*This reference is maintained by [TamperTantrum Labs](https://tampertantrum.com) — making application security accessible, human, and empowering.*
