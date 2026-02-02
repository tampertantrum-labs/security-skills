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
    return { error: 'Invalid input', details: result.error.flatten() };
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
  const cookieStore = cookies();
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
      { error: 'Validation failed', details: result.error.flatten() },
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

interface Params {
  params: { id: string };
}

export async function DELETE(request: NextRequest, { params }: Params) {
  const session = await auth();
  if (!session) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  // Validate ID format
  if (!params.id || typeof params.id !== 'string') {
    return NextResponse.json({ error: 'Invalid ID' }, { status: 400 });
  }

  // Delete with ownership check
  const deleted = await db.post.deleteMany({
    where: {
      id: params.id,
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

### next.config.js Headers

```js
// next.config.js
/** @type {import('next').NextConfig} */
const nextConfig = {
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

module.exports = nextConfig;
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

  const response = NextResponse.next();

  response.headers.set('Content-Security-Policy', cspHeader);
  response.headers.set('x-nonce', nonce);

  return response;
}

// app/layout.tsx - Use nonce in scripts
import { headers } from 'next/headers';

export default function RootLayout({ children }: { children: React.ReactNode }) {
  const nonce = headers().get('x-nonce') ?? '';

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
  cookies().delete('session');
  revalidatePath('/', 'layout'); // Clear all cached pages
}
```

---

## Recommended Libraries

| Purpose | Library | Why |
|---------|---------|-----|
| Auth | `next-auth` / `lucia` | Battle-tested, Next.js optimized |
| Validation | `zod` | TypeScript-first, runtime validation |
| Rate Limiting | `@upstash/ratelimit` | Edge-compatible, serverless |
| Database | `prisma` | Type-safe, good DX |
| Encryption | `jose` | Edge-compatible JWT/JWE |

---

## Anti-Patterns

1. **Client-side only auth** - Always verify on server
2. **Passing full database objects to client** - Select specific fields
3. **Hardcoded secrets in code** - Use environment variables
4. **Skipping input validation in Server Actions** - Always validate with Zod
5. **No ownership checks on mutations** - Always verify user owns resource
6. **Using `eval()` or `dangerouslySetInnerHTML`** - Find alternatives
7. **Exposing stack traces in production** - Use error boundaries

---

## References

- [references/auth-patterns.md](references/auth-patterns.md) - Auth implementation patterns
- [references/middleware-examples.md](references/middleware-examples.md) - Middleware recipes
- [references/csp-guide.md](references/csp-guide.md) - CSP configuration guide

---

*This skill is maintained by [TamperTantrum Labs](https://tampertantrum.com) — making application security accessible, human, and empowering.*
