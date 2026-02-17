---
name: nextjs-security
description: Security patterns for Next.js applications. App Router, Server Components, Server Actions, middleware auth, and API routes done right.
---

# Next.js Security

Build secure Next.js applications with proper authentication, authorization, and data protection patterns for the App Router.

## When to Use This Skill

- Building Next.js 16+ applications (App Router)
- Implementing authentication/authorization
- Creating API routes
- Using Server Components and Server Actions
- Setting up middleware
- Configuring security headers

## When NOT to Use This Skill

- Pages Router (legacy) - patterns differ
- Non-Next.js React apps - use `react-secure-coder`
- API-only backends - use `api-security`

---

## Server Components Security

### Never Pass Secrets to Client Components

```tsx
// ❌ BAD: Secret exposed to client
// app/dashboard/page.tsx
import ClientComponent from './client-component';

export default async function Page() {
  const apiKey = process.env.API_KEY; // Server-only
  return <ClientComponent apiKey={apiKey} />; // Leaked to client!
}

// ✅ GOOD: Fetch data on server, pass only safe data
// app/dashboard/page.tsx
import ClientComponent from './client-component';
import { fetchUserData } from '@/lib/api';

export default async function Page() {
  const user = await fetchUserData(); // Uses API_KEY internally
  return <ClientComponent user={user} />; // Only safe data
}
```

### Server-Only Modules

```tsx
// lib/secrets.ts
import 'server-only'; // Throws error if imported in client component

export const API_KEY = process.env.API_KEY!;
export const DATABASE_URL = process.env.DATABASE_URL!;

// This file can NEVER be imported in a client component
```

### Data Access Layer Pattern

```tsx
// lib/dal.ts (Data Access Layer)
import 'server-only';
import { db } from './db';
import { auth } from './auth';
import { cache } from 'react';

// Cached and authorized data fetching
export const getCurrentUser = cache(async () => {
  const session = await auth();
  if (!session?.user?.id) return null;
  
  return db.user.findUnique({
    where: { id: session.user.id },
    select: { id: true, email: true, role: true }, // Only safe fields
  });
});

// Authorization check built into data access
export const getUserProjects = cache(async () => {
  const user = await getCurrentUser();
  if (!user) throw new Error('Unauthorized');
  
  return db.project.findMany({
    where: { userId: user.id }, // Scoped to user
  });
});
```

---

## Server Actions Security

> **Server Actions are public HTTP endpoints.** Any function marked with `'use server'` becomes callable by anyone via POST request — even if it's only used in one form. Always authenticate and validate inside every Server Action. Next.js includes automatic CSRF protection (origin checking), but authorization is your responsibility.

### Always Validate Input

```tsx
'use server';

import { z } from 'zod';
import { auth } from '@/lib/auth';
import { db } from '@/lib/db';

const createPostSchema = z.object({
  title: z.string().min(1).max(200),
  content: z.string().min(1).max(10000),
  published: z.boolean().default(false),
});

export async function createPost(formData: FormData) {
  // 1. Authenticate
  const session = await auth();
  if (!session?.user?.id) {
    throw new Error('Unauthorized');
  }

  // 2. Validate input
  const rawData = {
    title: formData.get('title'),
    content: formData.get('content'),
    published: formData.get('published') === 'true',
  };

  const result = createPostSchema.safeParse(rawData);
  if (!result.success) {
    return { error: 'Invalid input', details: result.error.issues };
  }

  // 3. Authorized action
  const post = await db.post.create({
    data: {
      ...result.data,
      userId: session.user.id, // Always set from session, never from input
    },
  });

  return { success: true, postId: post.id };
}
```

### Prevent IDOR in Server Actions

```tsx
'use server';

import { auth } from '@/lib/auth';
import { db } from '@/lib/db';

// ❌ BAD: No ownership check
export async function deletePost(postId: string) {
  await db.post.delete({ where: { id: postId } });
}

// ✅ GOOD: Verify ownership
export async function deletePost(postId: string) {
  const session = await auth();
  if (!session?.user?.id) {
    throw new Error('Unauthorized');
  }

  // Only delete if user owns the post
  const deleted = await db.post.deleteMany({
    where: {
      id: postId,
      userId: session.user.id, // Ownership check
    },
  });

  if (deleted.count === 0) {
    throw new Error('Post not found or unauthorized');
  }

  return { success: true };
}
```

### Rate Limit Server Actions

```tsx
'use server';

import { auth } from '@/lib/auth';
import { ratelimit } from '@/lib/ratelimit';
import { headers } from 'next/headers';

export async function sensitiveAction(data: FormData) {
  const session = await auth();
  if (!session?.user?.id) {
    throw new Error('Unauthorized');
  }

  // Rate limit by user ID
  const { success, remaining } = await ratelimit.limit(session.user.id);
  if (!success) {
    throw new Error('Too many requests. Please try again later.');
  }

  // ... action logic
}

// lib/ratelimit.ts
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

export const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(10, '1 m'), // 10 requests per minute
});
```

---

## Middleware Authentication

### Protect Routes with Middleware

```tsx
// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { verifyToken } from '@/lib/auth';

// Routes that require authentication
const protectedRoutes = ['/dashboard', '/settings', '/api/user'];
// Routes that require admin role
const adminRoutes = ['/admin', '/api/admin'];
// Public routes (skip auth check)
const publicRoutes = ['/', '/login', '/register', '/api/auth'];

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Skip public routes
  if (publicRoutes.some(route => pathname.startsWith(route))) {
    return NextResponse.next();
  }

  // Get token from cookie
  const token = request.cookies.get('session')?.value;

  if (!token) {
    // Redirect to login for page requests
    if (!pathname.startsWith('/api/')) {
      return NextResponse.redirect(new URL('/login', request.url));
    }
    // Return 401 for API requests
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  // Verify token
  const payload = await verifyToken(token);
  if (!payload) {
    // Clear invalid cookie and redirect
    const response = NextResponse.redirect(new URL('/login', request.url));
    response.cookies.delete('session');
    return response;
  }

  // Check admin routes
  if (adminRoutes.some(route => pathname.startsWith(route))) {
    if (payload.role !== 'admin') {
      if (!pathname.startsWith('/api/')) {
        return NextResponse.redirect(new URL('/unauthorized', request.url));
      }
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
    }
  }

  // Add user info to headers for downstream use
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-user-id', payload.userId);
  requestHeaders.set('x-user-role', payload.role);

  return NextResponse.next({
    request: { headers: requestHeaders },
  });
}

export const config = {
  matcher: [
    // Match all routes except static files
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
};
```

### Auth Helper for Server Components

```tsx
// lib/auth.ts
import { cookies } from 'next/headers';
import { cache } from 'react';
import { verifyToken } from './jwt';

export const auth = cache(async () => {
  const cookieStore = await cookies();
  const token = cookieStore.get('session')?.value;

  if (!token) return null;

  const payload = await verifyToken(token);
  if (!payload) return null;

  return {
    user: {
      id: payload.userId,
      email: payload.email,
      role: payload.role,
    },
  };
});

// Usage in Server Component
// app/dashboard/page.tsx
import { auth } from '@/lib/auth';
import { redirect } from 'next/navigation';

export default async function DashboardPage() {
  const session = await auth();
  
  if (!session) {
    redirect('/login');
  }

  return <div>Welcome, {session.user.email}</div>;
}
```

---

## API Routes Security

### Route Handlers with Auth

```tsx
// app/api/posts/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { db } from '@/lib/db';
import { z } from 'zod';

// GET /api/posts
export async function GET(request: NextRequest) {
  const session = await auth();
  if (!session) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const posts = await db.post.findMany({
    where: { userId: session.user.id },
    select: { id: true, title: true, createdAt: true },
  });

  return NextResponse.json(posts);
}

// POST /api/posts
const createSchema = z.object({
  title: z.string().min(1).max(200),
  content: z.string().max(10000),
});

export async function POST(request: NextRequest) {
  const session = await auth();
  if (!session) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Invalid JSON' }, { status: 400 });
  }

  const result = createSchema.safeParse(body);
  if (!result.success) {
    return NextResponse.json(
      { error: 'Validation failed', details: result.error.issues },
      { status: 400 }
    );
  }

  const post = await db.post.create({
    data: {
      ...result.data,
      userId: session.user.id,
    },
  });

  return NextResponse.json(post, { status: 201 });
}
```

### Dynamic Route with Ownership Check

```tsx
// app/api/posts/[id]/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { db } from '@/lib/db';

export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const session = await auth();
  if (!session) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  // params is a Promise in Next.js 15+ — must be awaited
  const { id } = await params;

  // Validate ID format
  if (!id || typeof id !== 'string') {
    return NextResponse.json({ error: 'Invalid ID' }, { status: 400 });
  }

  // Delete with ownership check
  const deleted = await db.post.deleteMany({
    where: {
      id,
      userId: session.user.id,
    },
  });

  if (deleted.count === 0) {
    return NextResponse.json({ error: 'Not found' }, { status: 404 });
  }

  return new NextResponse(null, { status: 204 });
}
```

---

## Security Headers

### Security Headers via next.config.ts

Next.js 15+ supports TypeScript config natively. Use `next.config.ts` for type-safe configuration.

```ts
// next.config.ts
import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          {
            key: 'X-DNS-Prefetch-Control',
            value: 'on',
          },
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=63072000; includeSubDomains; preload',
          },
          {
            key: 'X-Frame-Options',
            value: 'SAMEORIGIN',
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin',
          },
          {
            key: 'Permissions-Policy',
            value: 'camera=(), microphone=(), geolocation=()',
          },
        ],
      },
    ];
  },
};

export default nextConfig;
```

### Content Security Policy

```tsx
// middleware.ts (CSP via middleware for nonce support)
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString('base64');

  const cspHeader = `
    default-src 'self';
    script-src 'self' 'nonce-${nonce}' 'strict-dynamic';
    style-src 'self' 'nonce-${nonce}';
    img-src 'self' blob: data:;
    font-src 'self';
    object-src 'none';
    base-uri 'self';
    form-action 'self';
    frame-ancestors 'none';
    upgrade-insecure-requests;
  `.replace(/\s{2,}/g, ' ').trim();

  // Set nonce on REQUEST headers (server-internal only — never exposed to network)
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);

  // Set CSP on RESPONSE headers (sent to browser)
  const response = NextResponse.next({
    request: { headers: requestHeaders },
  });
  response.headers.set('Content-Security-Policy', cspHeader);

  return response;
}

// app/layout.tsx - Read nonce from request headers
import { headers } from 'next/headers';

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const nonce = (await headers()).get('x-nonce') ?? '';

  return (
    <html lang="en">
      <body>
        {children}
        <script nonce={nonce} src="/analytics.js" />
      </body>
    </html>
  );
}
```

> **Why request headers?** The nonce must reach Server Components (via `headers()`) but must never be exposed on the network. Setting it on request headers keeps it server-internal. Setting it on response headers would leak the nonce to any network observer, defeating the purpose of CSP nonce-based protection.

---

## Environment Variables

### Proper Env Var Usage

```bash
# .env.local (NEVER commit this)

# Server-only (no NEXT_PUBLIC_ prefix)
DATABASE_URL="postgresql://..."
API_SECRET_KEY="sk_live_..."
JWT_SECRET="your-256-bit-secret"

# Client-safe (NEXT_PUBLIC_ prefix)
NEXT_PUBLIC_APP_URL="https://myapp.com"
NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY="pk_live_..."
```

```tsx
// ✅ GOOD: Server-only access
// lib/db.ts
const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) throw new Error('DATABASE_URL is required');

// ❌ BAD: Don't check server vars on client
// components/SomeComponent.tsx (client component)
const secret = process.env.API_SECRET_KEY; // undefined on client!

// ✅ GOOD: Use NEXT_PUBLIC_ for client vars
// components/SomeComponent.tsx
const appUrl = process.env.NEXT_PUBLIC_APP_URL;
```

### Runtime Config Validation

```tsx
// lib/env.ts
import { z } from 'zod';

const serverEnvSchema = z.object({
  DATABASE_URL: z.string().url(),
  JWT_SECRET: z.string().min(32),
  NODE_ENV: z.enum(['development', 'production', 'test']),
});

const clientEnvSchema = z.object({
  NEXT_PUBLIC_APP_URL: z.string().url(),
});

// Validate at startup
export const serverEnv = serverEnvSchema.parse(process.env);
export const clientEnv = clientEnvSchema.parse({
  NEXT_PUBLIC_APP_URL: process.env.NEXT_PUBLIC_APP_URL,
});
```

---

## Open Redirect Prevention

Redirects based on user input are a common source of open redirect vulnerabilities.

```tsx
// ❌ BAD: Redirect to user-controlled URL
import { redirect } from 'next/navigation';

export default async function LoginPage({ searchParams }: {
  searchParams: Promise<{ redirect?: string }>;
}) {
  const session = await auth();
  const { redirect: redirectTo } = await searchParams;

  if (session) {
    redirect(redirectTo ?? '/dashboard'); // Open redirect!
  }
  // ...
}

// ✅ GOOD: Validate redirect is same-origin
const SAFE_REDIRECT_PATTERN = /^\/[a-zA-Z0-9\-_/]*$/;

function getSafeRedirect(url: string | undefined, fallback = '/dashboard'): string {
  if (!url) return fallback;
  // Only allow relative paths starting with /
  // Block protocol-relative URLs (//evil.com), javascript:, data:, etc.
  if (!SAFE_REDIRECT_PATTERN.test(url)) return fallback;
  return url;
}

export default async function LoginPage({ searchParams }: {
  searchParams: Promise<{ redirect?: string }>;
}) {
  const session = await auth();
  const { redirect: redirectTo } = await searchParams;

  if (session) {
    redirect(getSafeRedirect(redirectTo));
  }
  // ...
}
```

---

## Taint API (Experimental)

React's `taintObjectReference` and `taintUniqueValue` prevent secrets from accidentally reaching Client Components. This is a defense-in-depth layer on top of `server-only`.

```tsx
// lib/auth.ts
import 'server-only';
import { experimental_taintObjectReference as taintObjectReference } from 'react';

export async function getFullUser(id: string) {
  const user = await db.user.findUnique({ where: { id } });

  // Prevent the full user object from being passed to a Client Component
  taintObjectReference(
    'Do not pass the full user object to Client Components. Select only the fields you need.',
    user
  );

  return user;
}

// If a Server Component tries to pass this object as a prop to a Client Component,
// React will throw an error with the message above.
```

> Enable in `next.config.ts` with `experimental: { taint: true }`. This is still experimental but provides strong protection against accidental secret leakage.

---

## Error Handling

### Error Boundaries with error.tsx

```tsx
// app/dashboard/error.tsx
'use client'; // Error boundaries must be Client Components

export default function DashboardError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  // NEVER show error.message to users in production — it may contain
  // internal details (stack traces, SQL, file paths)
  return (
    <div role="alert">
      <h2>Something went wrong</h2>
      <p>An unexpected error occurred. Please try again.</p>
      <button onClick={reset}>Try again</button>
    </div>
  );
}

// app/global-error.tsx — catches errors in the root layout
'use client';

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  // Log error server-side only (via error reporting service)
  // error.digest is a hash — safe to log or display for support reference
  return (
    <html>
      <body>
        <h2>Something went wrong</h2>
        <p>Error reference: {error.digest}</p>
        <button onClick={reset}>Try again</button>
      </body>
    </html>
  );
}
```

### Custom Not Found Page

```tsx
// app/not-found.tsx
export default function NotFound() {
  return (
    <div>
      <h2>Page Not Found</h2>
      <p>The page you are looking for does not exist.</p>
    </div>
  );
}
```

> Use `notFound()` from `next/navigation` to trigger the not-found page from Server Components or Server Actions when a resource doesn't exist. This prevents information leakage from 404 responses.

---

## CORS for API Routes

Next.js does not set CORS headers by default. For API routes that accept cross-origin requests:

```tsx
// app/api/public/route.ts
import { NextRequest, NextResponse } from 'next/server';

const ALLOWED_ORIGINS = [
  'https://myapp.com',
  'https://staging.myapp.com',
];

function getCorsHeaders(origin: string | null) {
  // Only reflect allowed origins — never use '*' with credentials
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    return {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400',
    };
  }
  return {};
}

// Handle preflight
export async function OPTIONS(request: NextRequest) {
  const origin = request.headers.get('origin');
  return new NextResponse(null, {
    status: 204,
    headers: getCorsHeaders(origin),
  });
}

export async function GET(request: NextRequest) {
  const origin = request.headers.get('origin');
  const data = { message: 'Hello' };

  return NextResponse.json(data, {
    headers: getCorsHeaders(origin),
  });
}
```

> For routes that should only be called same-origin (most routes), do not add CORS headers. The browser's same-origin policy is your default protection.

---

## File Uploads in Route Handlers

```tsx
// app/api/upload/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';

const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB
const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'];

export async function POST(request: NextRequest) {
  const session = await auth();
  if (!session) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const formData = await request.formData();
  const file = formData.get('file') as File | null;

  if (!file) {
    return NextResponse.json({ error: 'No file provided' }, { status: 400 });
  }

  // Validate file size
  if (file.size > MAX_FILE_SIZE) {
    return NextResponse.json({ error: 'File too large' }, { status: 413 });
  }

  // Validate MIME type (check both the declared type AND magic bytes for images)
  if (!ALLOWED_TYPES.includes(file.type)) {
    return NextResponse.json({ error: 'File type not allowed' }, { status: 415 });
  }

  // Generate a safe filename — never use the original filename directly
  const ext = file.type.split('/')[1];
  const safeFilename = `${crypto.randomUUID()}.${ext}`;

  // Upload to storage (S3, R2, etc.) — never write to the public/ directory
  const buffer = Buffer.from(await file.arrayBuffer());
  await uploadToStorage(safeFilename, buffer, file.type);

  return NextResponse.json({ filename: safeFilename }, { status: 201 });
}
```

> Never trust the client-provided filename — it can contain path traversal (`../../../etc/passwd`) or XSS payloads. Always generate a safe filename server-side.

---

## Cache Security

### Preventing Sensitive Data in Shared Caches

```tsx
// ❌ BAD: User-specific data cached globally
// app/dashboard/page.tsx
export default async function Dashboard() {
  // This page may be cached and served to other users!
  const user = await getCurrentUser();
  return <div>Balance: {user.balance}</div>;
}

// ✅ GOOD: Opt out of caching for user-specific pages
import { unstable_noStore as noStore } from 'next/cache';

export default async function Dashboard() {
  noStore(); // Prevent caching — this page has user-specific data
  const user = await getCurrentUser();
  return <div>Balance: {user.balance}</div>;
}
```

### Cache Key Isolation

```tsx
// ✅ GOOD: Use React cache() scoped to the request
import { cache } from 'react';

// This is per-request — different users get different results
export const getCurrentUser = cache(async () => {
  const session = await auth();
  if (!session?.user?.id) return null;
  return db.user.findUnique({ where: { id: session.user.id } });
});
```

> `React.cache()` is request-scoped — it deduplicates within a single request but does not share across users. `fetch()` caching and `unstable_cache()` are shared across requests — never store user-specific data in them without a user-specific cache key.

---

## next/script with CSP Nonce

When using third-party scripts with nonce-based CSP, pass the nonce to `<Script>`:

```tsx
// app/layout.tsx
import Script from 'next/script';
import { headers } from 'next/headers';

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const nonce = (await headers()).get('x-nonce') ?? '';

  return (
    <html lang="en">
      <body>
        {children}
        {/* Third-party scripts need the nonce to execute under CSP */}
        <Script
          src="https://www.googletagmanager.com/gtag/js?id=G-XXXXX"
          strategy="afterInteractive"
          nonce={nonce}
        />
      </body>
    </html>
  );
}
```

> Without the nonce, third-party scripts will be blocked by `script-src 'nonce-...' 'strict-dynamic'`. Always pass the nonce to every `<Script>` component.

---

## Common Pitfalls

### 1. Trusting Client-Side Route Protection

```tsx
// ❌ BAD: Only checking auth on client
'use client';

export default function Dashboard() {
  const { user, loading } = useAuth();
  
  if (loading) return <Loading />;
  if (!user) return <Redirect to="/login" />;
  
  return <SecretData />; // Data already sent to client!
}

// ✅ GOOD: Check auth on server
// app/dashboard/page.tsx (Server Component)
import { auth } from '@/lib/auth';
import { redirect } from 'next/navigation';

export default async function Dashboard() {
  const session = await auth();
  if (!session) redirect('/login');
  
  return <DashboardContent user={session.user} />;
}
```

### 2. Exposing Sensitive Data in Server Component Props

```tsx
// ❌ BAD: Full user object passed to client
export default async function Page() {
  const user = await db.user.findUnique({ where: { id } });
  return <ClientComponent user={user} />; // password hash, etc exposed!
}

// ✅ GOOD: Select only needed fields
export default async function Page() {
  const user = await db.user.findUnique({
    where: { id },
    select: { id: true, name: true, avatar: true },
  });
  return <ClientComponent user={user} />;
}
```

### 3. Missing Revalidation on Auth State Change

```tsx
// After logout, revalidate cached data
'use server';

import { cookies } from 'next/headers';
import { revalidatePath } from 'next/cache';

export async function logout() {
  (await cookies()).delete('session');
  revalidatePath('/', 'layout'); // Clear all cached pages
}
```

---

## Recommended Libraries

| Purpose | Library | Why |
|---------|---------|-----|
| Auth | `next-auth@5` (Auth.js) | Battle-tested, Next.js optimized. v5 is the App Router rewrite (rebranded as Auth.js) |
| Validation | `zod` | TypeScript-first, runtime validation |
| Rate Limiting | `@upstash/ratelimit` | Edge-compatible, serverless |
| Database | `prisma` / `drizzle-orm` | Type-safe ORM with good DX |
| Encryption | `jose` | Edge-compatible JWT/JWE/JWS |
| Sanitization | `dompurify` + `isomorphic-dompurify` | XSS prevention for user HTML |
| CSRF | Built-in | Server Actions include CSRF tokens automatically |

---

## Anti-Patterns

| # | Anti-Pattern | Why It's Dangerous | Do This Instead |
|---|---|---|---|
| 1 | Client-side only auth checks | Data already sent to client before redirect | Verify auth in Server Components/middleware |
| 2 | Passing full DB objects to Client Components | Leaks password hashes, internal IDs, PII | `select:` only the fields the UI needs |
| 3 | Hardcoded secrets in source code | Committed to git, visible in client bundle | Use `process.env` (no `NEXT_PUBLIC_` prefix for secrets) |
| 4 | Skipping validation in Server Actions | Server Actions are public HTTP endpoints | Always validate with Zod in every action |
| 5 | No ownership checks on mutations | IDOR — any user can modify any resource | Include `userId: session.user.id` in every WHERE clause |
| 6 | Dynamic code execution from user strings | XSS / remote code execution | Use structured data, sanitize HTML with DOMPurify |
| 7 | Exposing error details to users | Stack traces reveal internals, DB schema, file paths | Use error.tsx with generic messages; log details server-side |
| 8 | Setting CSP nonce on response headers | Leaks nonce to network, defeats CSP protection | Set nonce on request headers (server-internal only) |
| 9 | Synchronous `cookies()`/`headers()` calls | Broken in Next.js 15+, removed in 16 | Always `await cookies()`, `await headers()` |
| 10 | Redirecting to user-controlled URLs | Open redirect — phishing via your domain | Validate redirect is same-origin relative path |
| 11 | Using original filename for uploads | Path traversal, XSS in filenames | Generate `crypto.randomUUID()` filenames server-side |
| 12 | User-specific data in shared cache | Cache poisoning — user A sees user B's data | Use `noStore()` or user-scoped cache keys |
| 13 | Server Action without auth check | Anyone can call it via POST request | Always authenticate as first step in every action |
| 14 | Missing `server-only` on sensitive modules | Secrets may be bundled into client code | `import 'server-only'` in every file with secrets |
| 15 | Using `NEXT_PUBLIC_` for sensitive values | Exposed in client bundle, visible in page source | Only use `NEXT_PUBLIC_` for truly public config |
| 16 | No rate limiting on Server Actions | Brute force, spam, DoS | Use `@upstash/ratelimit` keyed by user ID or IP |
| 17 | Missing CORS on public API routes | Either too open or missing preflight handling | Explicit origin allowlist, never `*` with credentials |

---

## References

- [references/auth-patterns.md](references/auth-patterns.md) - Auth implementation patterns
- [references/middleware-examples.md](references/middleware-examples.md) - Middleware recipes
- [references/csp-guide.md](references/csp-guide.md) - CSP configuration guide

---

*This skill is maintained by [TamperTantrum Labs](https://tampertantrum.com) — making application security accessible, human, and empowering.*
