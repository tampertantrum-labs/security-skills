---
name: react-secure-coder
description: Security-first React/TypeScript development patterns. Prevents XSS, injection, and auth vulnerabilities by default.
---

# React Secure Coder

Build secure React applications by default. This skill ensures security patterns are applied during code generation, not discovered during review.

## When to Use This Skill

- Building React/TypeScript components
- Handling user input in forms
- Rendering dynamic content
- Implementing authentication flows
- Working with sensitive data (PII, tokens, secrets)
- Building admin interfaces

## When NOT to Use This Skill

- Static sites with no user input
- Server-side only code (use `api-security` instead)
- Next.js App Router (use `nextjs-security` for RSC-specific patterns)

## Core Principles

1. **Never trust user input** — Validate and sanitize everything
2. **Defense in depth** — Multiple layers of protection (validation + CSP + sanitization)
3. **Fail secure** — Errors should deny access, not grant it
4. **Least privilege** — Components only access what they need

---

## XSS Prevention

### Never Use `dangerouslySetInnerHTML` Without Sanitization

```tsx
// ❌ BAD: Direct HTML injection
function Comment({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

// ✅ GOOD: Sanitize with DOMPurify
import DOMPurify from 'dompurify';

function Comment({ html }: { html: string }) {
  // DOMPurify v3.x - configure allowed tags and attributes
  const sanitized = DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'ol', 'li'],
    ALLOWED_ATTR: ['href', 'target', 'rel'],
    ALLOW_DATA_ATTR: false,  // Block data-* attributes
    ADD_ATTR: ['target'],     // Allow target but we'll force it
    FORBID_TAGS: ['style', 'script', 'iframe', 'form', 'input'],
    FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover'],
  });
  
  return <div dangerouslySetInnerHTML={{ __html: sanitized }} />;
}

// ✅ BETTER: Create a reusable sanitizer with hooks
import DOMPurify from 'dompurify';
import { useMemo } from 'react';

// Configure DOMPurify once
const purify = DOMPurify();

// Force all links to open safely
purify.addHook('afterSanitizeAttributes', (node) => {
  if (node.tagName === 'A') {
    node.setAttribute('target', '_blank');
    node.setAttribute('rel', 'noopener noreferrer');
  }
});

export function useSanitizedHtml(dirty: string): string {
  return useMemo(() => {
    return purify.sanitize(dirty, {
      ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'ol', 'li', 'code', 'pre'],
      ALLOWED_ATTR: ['href'],
    });
  }, [dirty]);
}

// Usage
function SafeComment({ html }: { html: string }) {
  const cleanHtml = useSanitizedHtml(html);
  return <div dangerouslySetInnerHTML={{ __html: cleanHtml }} />;
}
```

### URL Validation

Both `javascript:` and `data:` URLs can execute code. Always allowlist protocols.

```tsx
// ❌ BAD: Arbitrary URLs can execute JavaScript
<a href={userProvidedUrl}>Click here</a>
<img src={userProvidedUrl} />

// ✅ GOOD: Validate URL protocol with allowlist
function SafeLink({ href, children }: { href: string; children: React.ReactNode }) {
  const isValidUrl = (url: string): boolean => {
    // Block protocol-relative URLs (//evil.com) — they redirect to another host
    if (url.startsWith('//')) return false;

    try {
      const parsed = new URL(url, window.location.origin);
      // Only allow safe protocols
      // Blocks: javascript:, data:, vbscript:, file:, etc.
      return ['http:', 'https:', 'mailto:', 'tel:'].includes(parsed.protocol);
    } catch {
      // Invalid URL format
      return false;
    }
  };

  if (!isValidUrl(href)) {
    // ⚠️ Don't log the URL itself — user input in logs can enable log injection
    console.warn('SafeLink: blocked a URL with a disallowed protocol');
    return <span>{children}</span>;
  }

  // External links get security attributes
  const isExternal = href.startsWith('http') && !href.includes(window.location.hostname);
  
  return (
    <a 
      href={href} 
      {...(isExternal && { 
        target: '_blank', 
        rel: 'noopener noreferrer' 
      })}
    >
      {children}
    </a>
  );
}

// ✅ For images, also validate
function SafeImage({ src, alt }: { src: string; alt: string }) {
  const isValidImageUrl = (url: string): boolean => {
    try {
      const parsed = new URL(url, window.location.origin);
      return ['http:', 'https:'].includes(parsed.protocol);
    } catch {
      return false;
    }
  };

  if (!isValidImageUrl(src)) {
    return <div className="image-placeholder">{alt}</div>;
  }

  return <img src={src} alt={alt} loading="lazy" />;
}
```

---

## Content Security Policy (CSP)

CSP is your last line of defense. Even if XSS gets through, CSP can block it from executing.

### Setting CSP via Meta Tag (Client-Side)

```tsx
// In your index.html or root component
// Note: Meta tag CSP CANNOT use report-uri or frame-ancestors.
// Use the Content-Security-Policy HTTP header for those directives.
// To prevent clickjacking, set frame-ancestors via server headers.
<meta
  httpEquiv="Content-Security-Policy"
  content="
    default-src 'self';
    script-src 'self';
    style-src 'self' 'unsafe-inline';
    img-src 'self' data: https:;
    font-src 'self';
    connect-src 'self' https://api.yoursite.com;
    base-uri 'self';
    form-action 'self';
  "
/>
```

> For ready-to-use CSP configurations for Google Analytics, Stripe, Intercom,
> Sentry, Cloudflare, YouTube, and combined stacks, see
> [references/csp-examples.md](references/csp-examples.md).

### CSP with Nonces (Most Secure)

```tsx
// Server generates a unique nonce per request
// This is the MOST secure approach - no 'unsafe-inline' needed

// Server-side (Next.js middleware example)
import { NextResponse } from 'next/server';
import crypto from 'crypto';

export function middleware(request) {
  const nonce = crypto.randomBytes(16).toString('base64');

  const csp = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}'`,
    `style-src 'self' 'nonce-${nonce}'`,
    "img-src 'self' data: https:",
    "font-src 'self'",
    "connect-src 'self'",
    "frame-ancestors 'none'",
  ].join('; ');

  const response = NextResponse.next();
  response.headers.set('Content-Security-Policy', csp);

  // ⚠️ NEVER expose the nonce via a response header like x-nonce.
  // An attacker with XSS could read headers via fetch() and extract it.
  // Instead, inject the nonce into the HTML during server-side rendering.
  // Next.js passes it via the request context:
  request.headers.set('x-nonce', nonce);

  return response;
}

// Server Component: read nonce from request headers and inject into HTML
// The nonce is ONLY available server-side — never sent to the client as a header.
import { headers } from 'next/headers';

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const nonce = (await headers()).get('x-nonce') ?? '';

  return (
    <html>
      <body>
        {/* Inline scripts must include the nonce */}
        <script nonce={nonce}>
          {`console.log('This script is allowed by CSP');`}
        </script>
        {children}
      </body>
    </html>
  );
}
```

### CSP Violation Reporting

```tsx
// Add reporting to catch violations in production
const cspWithReporting = [
  // ... your directives ...
  "report-uri https://your-domain.report-uri.com/r/d/csp/enforce",
  // Or use the newer report-to directive
  "report-to csp-endpoint",
].join('; ');

// Set up Report-To header as well
// Report-To: {"group":"csp-endpoint","max_age":10886400,"endpoints":[{"url":"https://your-domain.report-uri.com/a/d/g"}]}
```

---

## Input Validation with Zod

Always validate input at the boundary (forms, API responses).

> **Zod 4 Note:** Use top-level format types (`z.email()`, `z.url()`, `z.uuid()`) instead of
> the deprecated `z.string().email()` form. Use `{ error: '...' }` instead of the deprecated
> `message` parameter. See [Zod 4 Migration Guide](https://zod.dev/v4/changelog).

```tsx
import { z } from 'zod';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';

// Define schema with security constraints (Zod 4 API)
const userSchema = z.object({
  // Normalize BEFORE validation: trim + lowercase, then pipe into email format
  email: z
    .string()
    .trim()
    .toLowerCase()
    .pipe(z.email({ error: 'Invalid email address' }).max(254, { error: 'Email too long' })),
  password: z
    .string()
    .min(12, { error: 'Password must be at least 12 characters' })
    .max(128, { error: 'Password too long' })
    .regex(/[A-Z]/, { error: 'Must contain uppercase' })
    .regex(/[a-z]/, { error: 'Must contain lowercase' })
    .regex(/[0-9]/, { error: 'Must contain number' })
    .regex(/[^A-Za-z0-9]/, { error: 'Must contain special character' }),
  username: z
    .string()
    .min(3, { error: 'Username too short' })
    .max(30, { error: 'Username too long' })
    .regex(/^[a-zA-Z0-9_-]+$/, { error: 'Only alphanumeric, underscore, hyphen' })
    .toLowerCase()
    .trim(),
});

type UserForm = z.infer<typeof userSchema>;

function SignupForm() {
  const { 
    register, 
    handleSubmit, 
    formState: { errors, isSubmitting } 
  } = useForm<UserForm>({
    resolver: zodResolver(userSchema),
    mode: 'onBlur', // Validate on blur for better UX
  });

  const onSubmit = async (data: UserForm) => {
    // Data is validated and typed
    // Server MUST re-validate - client validation can be bypassed
    const res = await fetch('/api/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(data),
    });
    
    if (!res.ok) {
      const error = await res.json();
      // Handle server-side validation errors
    }
  };

  return (
    <form onSubmit={handleSubmit(onSubmit)} noValidate>
      <div>
        <input 
          {...register('email')} 
          type="email" 
          autoComplete="email"
          aria-invalid={!!errors.email}
        />
        {errors.email && (
          <span role="alert">{errors.email.message}</span>
        )}
      </div>
      
      <div>
        <input 
          {...register('password')} 
          type="password"
          autoComplete="new-password"
          aria-invalid={!!errors.password}
        />
        {errors.password && (
          <span role="alert">{errors.password.message}</span>
        )}
      </div>
      
      <button type="submit" disabled={isSubmitting}>
        {isSubmitting ? 'Signing up...' : 'Sign Up'}
      </button>
    </form>
  );
}
```

### Validating URL Input with Zod 4

```tsx
// Zod 4 has built-in protocol + hostname validation — no manual .refine() needed
const linkSchema = z.object({
  title: z.string().min(1, { error: 'Title is required' }).max(200).trim(),
  // z.url() with protocol restriction blocks javascript:, data:, etc.
  url: z.url({
    protocol: /^https?$/,
    hostname: z.regexes.domain,  // Validates real domain names
    error: 'Only valid http/https URLs are allowed',
  }),
});

// ❌ OLD (Zod 3): Manual refine for protocol check
// z.string().url().refine(url => { const p = new URL(url); return ['http:', 'https:'].includes(p.protocol); })
// ✅ NEW (Zod 4): Protocol option built into z.url()
```

### Validating API Responses

```tsx
// Never trust API responses - validate them too (Zod 4 top-level types)
const apiUserSchema = z.object({
  id: z.uuid(),                                // not z.string().uuid()
  email: z.email(),                            // not z.string().email()
  role: z.enum(['user', 'admin', 'moderator']),
  createdAt: z.iso.datetime(),                 // not z.string().datetime()
});

async function fetchUser(id: string) {
  const res = await fetch(`/api/users/${id}`, { credentials: 'include' });
  
  if (!res.ok) {
    throw new Error('Failed to fetch user');
  }
  
  const data = await res.json();
  
  // Validate response matches expected shape
  const result = apiUserSchema.safeParse(data);
  
  if (!result.success) {
    console.error('Invalid API response:', result.error);
    throw new Error('Invalid user data received');
  }
  
  return result.data; // Typed and validated
}
```

---

## Secure State Management

### Never Store Secrets in State

```tsx
// ❌ BAD: Token in React state (accessible via DevTools)
const [accessToken, setAccessToken] = useState(response.token);

// ❌ BAD: Token in localStorage (accessible via XSS)
localStorage.setItem('token', response.token);

// ✅ GOOD: Use httpOnly cookies (set by server)
// Token is never accessible to JavaScript
// Server sets: Set-Cookie: token=xxx; HttpOnly; Secure; SameSite=Strict
```

### Sanitize State from External Sources

```tsx
import { z } from 'zod';
import { useState, useEffect } from 'react';

const userSchema = z.object({
  id: z.uuid(),
  email: z.email(),
  role: z.enum(['user', 'admin']),
});

type User = z.infer<typeof userSchema>;

function useUser() {
  const [user, setUser] = useState<User | null>(null);
  const [error, setError] = useState<string | null>(null);
  
  useEffect(() => {
    fetch('/api/me', { credentials: 'include' })
      .then(res => res.json())
      .then(data => {
        // Validate before setting state
        const result = userSchema.safeParse(data);
        if (result.success) {
          setUser(result.data);
        } else {
          console.error('Invalid user data:', result.error);
          setError('Failed to load user');
        }
      })
      .catch(() => setError('Network error'));
  }, []);
  
  return { user, error };
}
```

---

## Authentication Patterns

### Secure Auth Context

```tsx
import { createContext, useContext, useEffect, useState, useCallback } from 'react';

interface User {
  id: string;
  email: string;
  role: 'user' | 'admin';
}

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  error: string | null;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshAuth: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refreshAuth = useCallback(async () => {
    try {
      const res = await fetch('/api/auth/me', { 
        credentials: 'include',
        headers: { 'Cache-Control': 'no-cache' },
      });
      
      if (res.ok) {
        const data = await res.json();
        setUser(data.user);
        setError(null);
      } else {
        setUser(null);
      }
    } catch {
      setUser(null);
      setError('Failed to check authentication');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshAuth();
  }, [refreshAuth]);

  const login = async (email: string, password: string) => {
    setError(null);
    
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || 'Login failed');
    }

    const data = await res.json();
    setUser(data.user);
  };

  const logout = async () => {
    await fetch('/api/auth/logout', {
      method: 'POST',
      credentials: 'include',
    });
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, isLoading, error, login, logout, refreshAuth }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
}
```

### Protected Routes

```tsx
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from './auth-context';

// Define a role hierarchy — higher index = more privilege
const ROLE_HIERARCHY: Record<string, number> = {
  user: 1,
  moderator: 2,
  admin: 3,
};

function hasRequiredRole(userRole: string, requiredRole: string): boolean {
  const userLevel = ROLE_HIERARCHY[userRole] ?? 0;
  const requiredLevel = ROLE_HIERARCHY[requiredRole] ?? Infinity;
  return userLevel >= requiredLevel;
}

interface ProtectedRouteProps {
  children: React.ReactNode;
  requiredRole?: string;
  fallback?: React.ReactNode;
}

export function ProtectedRoute({
  children,
  requiredRole,
  fallback = <div>Loading...</div>,
}: ProtectedRouteProps) {
  const { user, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return <>{fallback}</>;
  }

  if (!user) {
    // Redirect to login, preserve intended destination
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (requiredRole && !hasRequiredRole(user.role, requiredRole)) {
    // User doesn't have sufficient privilege
    return <Navigate to="/unauthorized" replace />;
  }

  return <>{children}</>;
}

// Usage
<Route 
  path="/admin" 
  element={
    <ProtectedRoute requiredRole="admin">
      <AdminDashboard />
    </ProtectedRoute>
  } 
/>
```

---

## CSRF Protection

For cookie-based auth, implement CSRF tokens:

```tsx
// Get CSRF token from meta tag (set by server on page load)
function getCsrfToken(): string {
  return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') ?? '';
}

// Create a wrapper for secure fetch requests
async function secureFetch(
  url: string, 
  options: RequestInit = {}
): Promise<Response> {
  const method = options.method?.toUpperCase() ?? 'GET';
  
  // Only add CSRF token for state-changing methods
  const needsCsrf = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);
  
  return fetch(url, {
    ...options,
    credentials: 'include',
    headers: {
      ...options.headers,
      ...(needsCsrf && { 'X-CSRF-Token': getCsrfToken() }),
    },
  });
}

// Usage
const res = await secureFetch('/api/posts', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ title, content }),
});
```

---

## Sensitive Data Handling

### Mask Sensitive Display

```tsx
import { useState } from 'react';

interface MaskedValueProps {
  value: string;
  maskChar?: string;
  visibleChars?: number;
}

function MaskedValue({ 
  value, 
  maskChar = '•',
  visibleChars = 0,
}: MaskedValueProps) {
  const [visible, setVisible] = useState(false);

  if (visible) {
    return (
      <span>
        {value}
        <button 
          type="button"
          onClick={() => setVisible(false)}
          aria-label="Hide value"
        >
          Hide
        </button>
      </span>
    );
  }

  const masked = visibleChars > 0
    ? maskChar.repeat(value.length - visibleChars) + value.slice(-visibleChars)
    : maskChar.repeat(value.length);

  return (
    <span>
      {masked}
      <button 
        type="button"
        onClick={() => setVisible(true)}
        aria-label="Show value"
      >
        Show
      </button>
    </span>
  );
}

// Usage
<MaskedValue value={user.ssn} visibleChars={4} /> // ••••••1234
<MaskedValue value={user.apiKey} /> // ••••••••••••••••
```

### Clear Sensitive Data on Unmount

```tsx
import { useState, useEffect, useRef } from 'react';

function SensitiveForm() {
  const [cardNumber, setCardNumber] = useState('');
  const [cvv, setCvv] = useState('');
  const cardRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    // Clear sensitive data when component unmounts
    return () => {
      setCardNumber('');
      setCvv('');
      // Also clear the actual input values
      if (cardRef.current) {
        cardRef.current.value = '';
      }
    };
  }, []);

  // Clear data after successful submission
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await processPayment({ cardNumber, cvv });
      // Clear immediately after use
      setCardNumber('');
      setCvv('');
    } catch (error) {
      // Handle error, but still consider clearing sensitive data
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        ref={cardRef}
        type="text"
        inputMode="numeric"
        autoComplete="cc-number"
        value={cardNumber}
        onChange={(e) => setCardNumber(e.target.value)}
      />
      {/* ... */}
    </form>
  );
}
```

---

## Link Security & Referrer Policy

### Secure Link Defaults

Every link rendering user-controlled URLs should enforce safe defaults:

```tsx
// ❌ BAD: Bare link leaks referrer and opens in same context
<a href={url}>{label}</a>

// ✅ GOOD: External links get full security attributes
<a
  href={url}
  target="_blank"
  rel="noopener noreferrer"
>
  {label}
</a>
```

### Referrer Policy

Control what information is sent in the `Referer` header when navigating away:

```tsx
// Set globally via meta tag or HTTP header
<meta name="referrer" content="strict-origin-when-cross-origin" />

// Or per-link for extra-sensitive pages (e.g. password reset)
<a href={url} rel="noreferrer">Link</a>
// noreferrer = no Referer header sent at all
```

| Policy | What Leaks | Use When |
|--------|-----------|----------|
| `no-referrer` | Nothing | Sensitive pages (auth, admin) |
| `strict-origin-when-cross-origin` | Origin only cross-site, full path same-site | Default for most apps |
| `same-origin` | Full URL same-origin, nothing cross-origin | Internal apps |

### Rel Attribute Reference

| Value | Purpose |
|-------|---------|
| `noopener` | Prevents `window.opener` access (tab-napping) |
| `noreferrer` | Strips Referer header (implies noopener) |
| `nofollow` | Tells search engines not to follow (UGC links) |
| `ugc` | Marks user-generated content links |
| `sponsored` | Marks paid/sponsored links |

For user-generated content, use `rel="noopener noreferrer ugc nofollow"`.

---

## Open Redirect Prevention

Open redirects let attackers craft URLs on your domain that redirect to malicious sites (`yourapp.com/redirect?url=evil.com`). Victims trust the link because it starts with your domain.

```tsx
// ❌ BAD: Redirect anywhere
function LoginRedirect() {
  const params = new URLSearchParams(window.location.search);
  const returnUrl = params.get('returnTo') ?? '/';

  // Attacker: /login?returnTo=https://evil.com/phishing
  window.location.href = returnUrl; // Open redirect!
}

// ✅ GOOD: Only allow relative paths on the same origin
function safeRedirect(url: string, fallback = '/'): string {
  // Must start with / and not // (protocol-relative URL)
  if (url.startsWith('/') && !url.startsWith('//')) {
    try {
      // Parse against current origin to block javascript: or data:
      const parsed = new URL(url, window.location.origin);
      if (parsed.origin === window.location.origin) {
        return parsed.pathname + parsed.search;
      }
    } catch {
      // Invalid URL
    }
  }
  return fallback;
}

// Usage after login
const returnTo = safeRedirect(params.get('returnTo') ?? '/');
navigate(returnTo);
```

```tsx
// ✅ EVEN BETTER: Use an allowlist for known redirect targets
const ALLOWED_REDIRECT_PATHS = ['/dashboard', '/settings', '/profile'];

function safeRedirectStrict(url: string): string {
  const path = safeRedirect(url);
  // Only allow specific known paths
  if (ALLOWED_REDIRECT_PATHS.some(p => path.startsWith(p))) {
    return path;
  }
  return '/dashboard'; // Safe default
}
```

---

## Subresource Integrity (SRI)

When loading scripts or stylesheets from CDNs, use SRI to ensure the file hasn't been tampered with. If the CDN is compromised, the browser will refuse to load the altered file.

```html
<!-- ❌ BAD: CDN compromise = your site is compromised -->
<script src="https://cdn.example.com/library.js"></script>

<!-- ✅ GOOD: SRI hash ensures integrity -->
<script
  src="https://cdn.example.com/library.js"
  integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8w"
  crossorigin="anonymous"
></script>
```

### Generate SRI Hashes

```bash
# Generate hash for a remote file
curl -s https://cdn.example.com/library.js | openssl dgst -sha384 -binary | openssl base64 -A

# Or use srihash.org for a web UI
```

### SRI in React (Vite / Webpack)

```tsx
// vite.config.ts — enable SRI for production builds
import { defineConfig } from 'vite';
import { sriPlugin } from 'vite-plugin-sri';

export default defineConfig({
  plugins: [sriPlugin()],
});

// Webpack — use the html-webpack-plugin with SRI
// npm install webpack-subresource-integrity
```

> **When to use SRI:** Any time you load resources from a third-party CDN.
> You do NOT need SRI for resources served from your own domain.

---

## Environment Variables in Client Bundles

Variables prefixed with `VITE_` (Vite) or `REACT_APP_` (CRA) are **bundled into the client JavaScript** and visible to anyone who inspects your source.

```tsx
// ❌ BAD: Secret in client bundle — visible in browser DevTools
const API_SECRET = import.meta.env.VITE_API_SECRET;

// ❌ BAD: Database URL in client
const DB_URL = import.meta.env.VITE_DATABASE_URL;

// ✅ GOOD: Only public, non-secret values get the VITE_ prefix
const API_BASE = import.meta.env.VITE_API_BASE_URL; // e.g. "https://api.myapp.com"
const APP_ENV = import.meta.env.VITE_APP_ENV;       // e.g. "production"
```

### Rules

| Prefix | Bundled? | Use For |
|--------|----------|---------|
| `VITE_` | **Yes** — in browser | Public API URLs, feature flags, app name |
| No prefix | **No** — server only | API keys, DB creds, JWT secrets, webhook secrets |
| `REACT_APP_` (CRA) | **Yes** — in browser | Same as `VITE_` |

```bash
# .env — safe
DATABASE_URL=postgres://...
STRIPE_SECRET_KEY=sk_live_...
JWT_SECRET=supersecret

# .env — public (ok to expose)
VITE_API_BASE_URL=https://api.myapp.com
VITE_SENTRY_DSN=https://public@sentry.io/123
```

### Validate Environment Variables at Build Time

```tsx
// src/env.ts — fail the build if variables are missing or malformed
import { z } from 'zod';

const envSchema = z.object({
  VITE_API_BASE_URL: z.url({ protocol: /^https?$/ }),
  VITE_APP_ENV: z.enum(['development', 'staging', 'production']),
});

export const env = envSchema.parse(import.meta.env);
```

---

## Prop Spreading Security

Spreading user-controlled objects as JSX props is dangerous — it can inject
event handlers, `ref` overrides, or arbitrary attributes.

```tsx
// ❌ BAD: Spreads ANY prop, including dangerous ones
function Card({ ...userProps }) {
  return <div {...userProps} />;
}
// Attacker can pass dangerous props like event handlers or ref overrides

// ✅ GOOD: Allowlist safe props explicitly
interface CardProps {
  className?: string;
  id?: string;
  children?: React.ReactNode;
}

function Card({ className, id, children }: CardProps) {
  return <div className={className} id={id}>{children}</div>;
}

// ✅ ALSO GOOD: Strip dangerous keys if you must accept arbitrary props
function SafeDiv(props: Record<string, unknown>) {
  const BLOCKED_PROPS = new Set([
    'ref',
    // Block all event handlers
    ...Object.keys(props).filter(k => k.startsWith('on')),
  ]);

  const safeProps = Object.fromEntries(
    Object.entries(props).filter(([key]) => !BLOCKED_PROPS.has(key))
  );

  return <div {...safeProps} />;
}
```

---

## React Error Boundaries & Information Leaks

Error boundaries catch rendering errors. In production, **never expose stack traces or internal details to users** — they reveal file paths, library versions, and internal logic.

```tsx
import { Component, type ReactNode, type ErrorInfo } from 'react';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
}

class SecureErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false };

  static getDerivedStateFromError(): State {
    return { hasError: true };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // ✅ Log full details to your error tracking service (server-side)
    reportToErrorService({
      message: error.message,
      stack: error.stack,
      componentStack: info.componentStack,
    });

    // ❌ NEVER: console.error(error) in production — DevTools expose it
    // ❌ NEVER: Show error.message to users — may contain secrets or SQL
    // ❌ NEVER: Render info.componentStack — reveals file paths
  }

  render() {
    if (this.state.hasError) {
      return this.props.fallback ?? (
        <div role="alert">
          <h2>Something went wrong</h2>
          {/* Generic message — no technical details */}
          <p>Please try refreshing the page.</p>
        </div>
      );
    }
    return this.props.children;
  }
}

// Usage
<SecureErrorBoundary fallback={<ErrorPage />}>
  <App />
</SecureErrorBoundary>
```

### Error Messages

| Context | Show to User | Log to Server |
|---------|-------------|---------------|
| Render error | "Something went wrong" | Full stack + componentStack |
| API error (4xx) | Validation message from API | Request details, status |
| API error (5xx) | "Server error, try again" | Full response + request |
| Network error | "Connection problem" | Error object + URL |

---

## Honeypot & Bot Prevention

Protect forms from automated abuse without degrading UX.

### Honeypot Fields

Hidden fields that humans don't see but bots fill out:

```tsx
import { useRef, useState } from 'react';

function SecureContactForm() {
  const [honeypot, setHoneypot] = useState('');
  const formStartTime = useRef(Date.now());

  const handleSubmit = async (data: FormData) => {
    // Bot detection #1: Honeypot field filled
    if (honeypot) {
      // Silently reject — don't tell bots they were caught
      console.warn('Bot submission detected (honeypot)');
      return;
    }

    // Bot detection #2: Form submitted too fast (< 2 seconds)
    const elapsed = Date.now() - formStartTime.current;
    if (elapsed < 2000) {
      console.warn('Bot submission detected (too fast)');
      return;
    }

    await submitForm(data);
  };

  return (
    <form onSubmit={handleSubmit}>
      {/* Honeypot — hidden from humans via CSS, NOT via type="hidden" */}
      {/* Bots often ignore type="hidden" but fill visible-looking fields */}
      <div aria-hidden="true" style={{
        position: 'absolute',
        left: '-9999px',
        tabIndex: -1,
      }}>
        <label htmlFor="website">Website</label>
        <input
          id="website"
          name="website"
          type="text"
          value={honeypot}
          onChange={e => setHoneypot(e.target.value)}
          tabIndex={-1}
          autoComplete="off"
        />
      </div>

      {/* Real form fields */}
      {/* ... */}
    </form>
  );
}
```

### Additional Bot Defenses

| Technique | How | Notes |
|-----------|-----|-------|
| **Honeypot field** | Hidden field bots fill out | Zero UX impact |
| **Time-based check** | Reject sub-2s submissions | Simple, effective |
| **Server rate limiting** | Max N submissions per IP/session | Essential for all forms |
| **CAPTCHA** | Google reCAPTCHA / Cloudflare Turnstile | Use after N failed attempts |
| **Proof-of-work** | Client computes hash challenge | Invisible to users, expensive for bots |

> **Important:** Honeypots and timing checks are client-side heuristics.
> **Server-side rate limiting is still required** — client-side checks can be bypassed.

---

## Recommended Libraries

> ⚠️ **Always check for the latest version before installing.**
> Run `pnpm info <package> version` or check the npm page.
> Libraries evolve — APIs get deprecated, security patches ship, and major versions
> introduce breaking changes. **Do not blindly use the versions listed here.**
> When a major version changes, check the migration guide for breaking changes
> before upgrading existing code.
>
> **Use `pnpm` as the package manager** — not npm or yarn.
> pnpm uses a content-addressable store with strict dependency isolation,
> preventing phantom dependencies and supply-chain attacks from hoisted packages.
> See [pnpm.io](https://pnpm.io) for details.

| Purpose | Library | Docs | npm | Why |
|---------|---------|------|-----|-----|
| HTML Sanitization | `dompurify` | [GitHub](https://github.com/cure53/DOMPurify) · [Changelog](https://github.com/cure53/DOMPurify/releases) | [npm](https://www.npmjs.com/package/dompurify) | Industry standard XSS sanitization |
| Schema Validation | `zod` | [Docs](https://zod.dev) · [Migration Guide](https://zod.dev/v4/changelog) | [npm](https://www.npmjs.com/package/zod) | TypeScript-first runtime validation |
| Form Handling | `react-hook-form` | [Docs](https://react-hook-form.com) · [Migration](https://react-hook-form.com/migrate-v6-to-v7) | [npm](https://www.npmjs.com/package/react-hook-form) | Performant, minimal re-renders |
| Form + Zod | `@hookform/resolvers` | [GitHub](https://github.com/react-hook-form/resolvers) | [npm](https://www.npmjs.com/package/@hookform/resolvers) | Bridges RHF and Zod |
| HTTP Client | Native `fetch` | [MDN](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API) | — | Built-in, no extra dependencies |

### Version-Sensitive Notes

These are current as of the skill's last update. **Verify before using.**

- **Zod 4** introduced top-level format types: `z.email()`, `z.url()`, `z.uuid()`, `z.iso.datetime()`.
  The old `z.string().email()` form still works but is **deprecated**.
  The `message` parameter is deprecated in favor of `error`.
  `z.url()` now has built-in `protocol` and `hostname` options — no more manual `.refine()`.
  See [Zod 4 Migration Guide](https://zod.dev/v4/changelog).

- **DOMPurify 3.x** changed initialization. Use `DOMPurify(window)` or `DOMPurify()`.
  Check the [releases page](https://github.com/cure53/DOMPurify/releases) for security patches.

- **@hookform/resolvers** must match your Zod major version. Check compatibility in their
  [README](https://github.com/react-hook-form/resolvers#zod).

---

## Anti-Patterns to Avoid

| Anti-Pattern | Risk | Do This Instead |
|--------------|------|-----------------|
| Storing JWTs in localStorage | XSS can steal tokens | httpOnly cookies |
| Client-side only auth checks | Bypass via DevTools | Always verify on server |
| Trusting URL parameters | Injection, open redirect | Validate all params with Zod |
| Unsanitized HTML injection | XSS | Always use DOMPurify |
| Inline event handlers with user data | XSS | Use React event handlers |
| Disabling React's escaping | XSS | Keep it enabled |
| No CSP headers | XSS has no safety net | Implement CSP |
| Dynamic code execution from strings | Code injection | Find alternatives |
| Using `npm` / `yarn` | Phantom deps, hoisting attacks | Use `pnpm` — strict isolation |
| Spreading `{...userProps}` onto elements | XSS, event injection | Allowlist specific props |
| `VITE_SECRET_KEY` in env | Secret in client bundle | Remove `VITE_` prefix, use server |
| `window.location = userInput` | Open redirect | Validate with `safeRedirect()` |
| Showing `error.message` to users | Info leak (paths, SQL) | Generic message + server log |
| Links without `rel="noopener"` | Tab-napping | Always add `noopener noreferrer` |
| Logging user input to console | Log injection | Log generic descriptions only |
| CDN scripts without SRI | Supply chain attack | Add `integrity` hash |
| No honeypot on public forms | Bot abuse | Add honeypot + rate limiting |

---

## React Server Components Note

If using React 18+ with Server Components (Next.js App Router):

- **Server Components** can safely fetch data and access secrets
- **Never pass secrets** from Server to Client Components via props
- Use the `nextjs-security` skill for RSC-specific patterns
- Client Components still need all the patterns in this skill

---

## External Resources

### Libraries
- [DOMPurify](https://github.com/cure53/DOMPurify) — XSS sanitization ([npm](https://www.npmjs.com/package/dompurify) · [releases](https://github.com/cure53/DOMPurify/releases))
- [Zod](https://zod.dev) — Schema validation ([npm](https://www.npmjs.com/package/zod) · [v4 migration](https://zod.dev/v4/changelog))
- [React Hook Form](https://react-hook-form.com) — Form handling ([npm](https://www.npmjs.com/package/react-hook-form) · [docs](https://react-hook-form.com/get-started))
- [@hookform/resolvers](https://github.com/react-hook-form/resolvers) — Validation resolvers ([npm](https://www.npmjs.com/package/@hookform/resolvers))

### Security References
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP DOM XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)

### CSP Tools
- [MDN Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy) — Full directive reference
- [CSP Evaluator (Google)](https://csp-evaluator.withgoogle.com/) — Test your CSP policy
- [Report URI](https://report-uri.com/) — CSP violation reporting service

---

## References

- [references/xss-patterns.md](references/xss-patterns.md) — XSS attack patterns and defenses
- [references/auth-checklist.md](references/auth-checklist.md) — Authentication security checklist
- [references/form-security.md](references/form-security.md) — Secure form patterns
- [references/csp-examples.md](references/csp-examples.md) — CSP configurations for common scenarios

---

*This skill is maintained by [TamperTantrum Labs](https://tampertantrum.com) — making application security accessible, human, and empowering.*
