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

## Core Principles

1. **Never trust user input** - Validate and sanitize everything
2. **Defense in depth** - Multiple layers of protection
3. **Fail secure** - Errors should deny access, not grant it
4. **Least privilege** - Components only access what they need

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
  const sanitized = DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p'],
    ALLOWED_ATTR: ['href'],
  });
  return <div dangerouslySetInnerHTML={{ __html: sanitized }} />;
}
```

### URL Validation

```tsx
// ❌ BAD: Arbitrary URLs (javascript: XSS)
<a href={userProvidedUrl}>Click here</a>

// ✅ GOOD: Validate URL protocol
function SafeLink({ href, children }: { href: string; children: React.ReactNode }) {
  const isValidUrl = (url: string): boolean => {
    try {
      const parsed = new URL(url);
      return ['http:', 'https:', 'mailto:'].includes(parsed.protocol);
    } catch {
      return false;
    }
  };

  if (!isValidUrl(href)) {
    console.warn('Blocked potentially malicious URL:', href);
    return <span>{children}</span>;
  }

  return <a href={href} rel="noopener noreferrer">{children}</a>;
}
```

---

## Input Validation with Zod

Always validate input at the boundary (forms, API responses).

```tsx
import { z } from 'zod';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';

// Define schema with security constraints
const userSchema = z.object({
  email: z.string().email().max(254),
  password: z
    .string()
    .min(12, 'Password must be at least 12 characters')
    .regex(/[A-Z]/, 'Must contain uppercase')
    .regex(/[a-z]/, 'Must contain lowercase')
    .regex(/[0-9]/, 'Must contain number')
    .regex(/[^A-Za-z0-9]/, 'Must contain special character'),
  username: z
    .string()
    .min(3)
    .max(30)
    .regex(/^[a-zA-Z0-9_-]+$/, 'Only alphanumeric, underscore, hyphen'),
});

type UserForm = z.infer<typeof userSchema>;

function SignupForm() {
  const { register, handleSubmit, formState: { errors } } = useForm<UserForm>({
    resolver: zodResolver(userSchema),
  });

  const onSubmit = (data: UserForm) => {
    // Data is validated and typed
  };

  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      {/* Form fields */}
    </form>
  );
}
```

---

## Secure State Management

### Never Store Secrets in State

```tsx
// ❌ BAD: Token in React state (accessible via DevTools)
const [accessToken, setAccessToken] = useState(response.token);

// ✅ GOOD: Use httpOnly cookies (set by server)
// Token is never accessible to JavaScript
```

### Sanitize State from External Sources

```tsx
// ❌ BAD: Trust API response directly
const [user, setUser] = useState(apiResponse.user);

// ✅ GOOD: Validate API response
const userSchema = z.object({
  id: z.string().uuid(),
  email: z.string().email(),
  role: z.enum(['user', 'admin']),
});

const [user, setUser] = useState(() => {
  const parsed = userSchema.safeParse(apiResponse.user);
  if (!parsed.success) {
    console.error('Invalid user data:', parsed.error);
    return null;
  }
  return parsed.data;
});
```

---

## Authentication Patterns

### Secure Auth Context

```tsx
import { createContext, useContext, useEffect, useState } from 'react';

interface User {
  id: string;
  email: string;
  role: 'user' | 'admin';
}

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Check session on mount (server validates httpOnly cookie)
    fetch('/api/auth/me', { credentials: 'include' })
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => setUser(data?.user ?? null))
      .finally(() => setIsLoading(false));
  }, []);

  const login = async (email: string, password: string) => {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      credentials: 'include', // Important: send cookies
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    if (!res.ok) throw new Error('Login failed');

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
    <AuthContext.Provider value={{ user, isLoading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within AuthProvider');
  return context;
}
```

### Protected Routes

```tsx
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from './auth-context';

interface ProtectedRouteProps {
  children: React.ReactNode;
  requiredRole?: 'user' | 'admin';
}

export function ProtectedRoute({ children, requiredRole }: ProtectedRouteProps) {
  const { user, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return <div>Loading...</div>;
  }

  if (!user) {
    // Redirect to login, preserve intended destination
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (requiredRole && user.role !== requiredRole) {
    // User doesn't have required role
    return <Navigate to="/unauthorized" replace />;
  }

  return <>{children}</>;
}
```

---

## CSRF Protection

For cookie-based auth, implement CSRF tokens:

```tsx
// Get CSRF token from meta tag (set by server)
function getCsrfToken(): string {
  return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') ?? '';
}

// Include in all state-changing requests
async function secureFetch(url: string, options: RequestInit = {}) {
  return fetch(url, {
    ...options,
    credentials: 'include',
    headers: {
      ...options.headers,
      'X-CSRF-Token': getCsrfToken(),
    },
  });
}
```

---

## Sensitive Data Handling

### Mask Sensitive Display

```tsx
function MaskedValue({ value, visible }: { value: string; visible: boolean }) {
  if (!visible) {
    return <span>{'•'.repeat(value.length)}</span>;
  }
  return <span>{value}</span>;
}

// Usage
<MaskedValue value={user.ssn} visible={showSsn} />
```

### Clear Sensitive Data on Unmount

```tsx
function SensitiveForm() {
  const [cardNumber, setCardNumber] = useState('');

  useEffect(() => {
    // Clear sensitive data when component unmounts
    return () => {
      setCardNumber('');
    };
  }, []);

  return <input type="text" value={cardNumber} onChange={(e) => setCardNumber(e.target.value)} />;
}
```

---

## Recommended Libraries

| Purpose | Library | Why |
|---------|---------|-----|
| HTML Sanitization | `dompurify` | Industry standard, actively maintained |
| Schema Validation | `zod` | TypeScript-first, runtime validation |
| Form Handling | `react-hook-form` + `@hookform/resolvers` | Performance, Zod integration |
| HTTP Client | `ky` or native `fetch` | Avoid axios footguns |

---

## Anti-Patterns to Avoid

1. **Storing JWTs in localStorage** - Use httpOnly cookies instead
2. **Client-side only auth checks** - Always verify on server
3. **Trusting URL parameters** - Validate all query/path params
4. **Inline event handlers with user data** - Potential XSS vector
5. **Disabling React's built-in escaping** - Don't unless absolutely necessary

---

## References

- [references/xss-patterns.md](references/xss-patterns.md) - Detailed XSS prevention
- [references/auth-checklist.md](references/auth-checklist.md) - Authentication checklist
- [references/form-security.md](references/form-security.md) - Secure form patterns
