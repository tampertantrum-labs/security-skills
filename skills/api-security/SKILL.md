---
name: api-security
description: Secure REST and GraphQL API patterns. Authentication, authorization, rate limiting, input validation.
---

# API Security

Build secure APIs that resist common attacks. Covers authentication, authorization, input validation, rate limiting, and secure error handling.

## When to Use This Skill

- Building REST or GraphQL APIs
- Implementing authentication endpoints
- Handling sensitive data operations
- Creating public-facing APIs
- Building admin/internal APIs

## When NOT to Use This Skill

- Frontend-only code (use `react-secure-coder`)
- Static file serving

---

## Authentication

### JWT Best Practices

```typescript
import jwt from 'jsonwebtoken';

// ✅ GOOD: Short-lived access tokens + refresh token rotation
const ACCESS_TOKEN_EXPIRY = '15m';
const REFRESH_TOKEN_EXPIRY = '7d';

interface TokenPayload {
  userId: string;
  role: 'user' | 'admin';
  // Never include sensitive data (email, PII) in JWT
}

function generateTokens(user: { id: string; role: string }) {
  const accessToken = jwt.sign(
    { userId: user.id, role: user.role } as TokenPayload,
    process.env.JWT_SECRET!,
    { expiresIn: ACCESS_TOKEN_EXPIRY, algorithm: 'HS256' }
  );

  const refreshToken = jwt.sign(
    { userId: user.id, tokenVersion: user.tokenVersion },
    process.env.REFRESH_SECRET!,
    { expiresIn: REFRESH_TOKEN_EXPIRY, algorithm: 'HS256' }
  );

  return { accessToken, refreshToken };
}

// ✅ GOOD: Verify with explicit algorithm
function verifyToken(token: string): TokenPayload {
  return jwt.verify(token, process.env.JWT_SECRET!, {
    algorithms: ['HS256'], // Prevent algorithm confusion attacks
  }) as TokenPayload;
}
```

### Secure Cookie Configuration

```typescript
// ✅ GOOD: httpOnly cookies for tokens
res.cookie('refreshToken', refreshToken, {
  httpOnly: true,        // Not accessible via JavaScript
  secure: true,          // HTTPS only
  sameSite: 'strict',    // CSRF protection
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  path: '/api/auth',     // Only sent to auth endpoints
});
```

---

## Authorization

### Middleware Pattern

```typescript
import { Request, Response, NextFunction } from 'express';

// ✅ GOOD: Role-based authorization middleware
function requireRole(...allowedRoles: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      // Log for security monitoring
      console.warn(`Unauthorized access attempt: ${req.user.id} -> ${req.path}`);
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    next();
  };
}

// Usage
app.delete('/api/users/:id', requireRole('admin'), deleteUser);
```

### Resource Ownership Check (Prevent IDOR)

```typescript
// ❌ BAD: No ownership check
app.get('/api/documents/:id', async (req, res) => {
  const doc = await db.documents.findById(req.params.id);
  res.json(doc); // Anyone can access any document!
});

// ✅ GOOD: Verify ownership
app.get('/api/documents/:id', async (req, res) => {
  const doc = await db.documents.findOne({
    where: {
      id: req.params.id,
      // User can only access their own documents
      // OR they're an admin
      ...(req.user.role !== 'admin' && { userId: req.user.id }),
    },
  });

  if (!doc) {
    return res.status(404).json({ error: 'Document not found' });
  }

  res.json(doc);
});
```

---

## Input Validation

### Zod Schema Validation

```typescript
import { z } from 'zod';
import { Request, Response, NextFunction } from 'express';

// Define strict schemas
const createUserSchema = z.object({
  email: z.string().email().max(254).toLowerCase(),
  password: z
    .string()
    .min(12)
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d]).+$/),
  name: z.string().min(1).max(100).trim(),
});

// Validation middleware factory
function validate<T extends z.ZodSchema>(schema: T) {
  return (req: Request, res: Response, next: NextFunction) => {
    const result = schema.safeParse(req.body);
    
    if (!result.success) {
      return res.status(400).json({
        error: 'Validation failed',
        details: result.error.issues.map((i) => ({
          field: i.path.join('.'),
          message: i.message,
        })),
      });
    }

    req.body = result.data; // Use validated/transformed data
    next();
  };
}

// Usage
app.post('/api/users', validate(createUserSchema), createUser);
```

### Path Parameter Validation

```typescript
// ❌ BAD: Trust path params
app.get('/api/users/:id', async (req, res) => {
  const user = await db.users.findById(req.params.id);
});

// ✅ GOOD: Validate path params
const uuidSchema = z.string().uuid();

app.get('/api/users/:id', async (req, res) => {
  const parseResult = uuidSchema.safeParse(req.params.id);
  if (!parseResult.success) {
    return res.status(400).json({ error: 'Invalid user ID format' });
  }
  
  const user = await db.users.findById(parseResult.data);
});
```

---

## Rate Limiting

```typescript
import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import Redis from 'ioredis';

const redis = new Redis(process.env.REDIS_URL);

// General API rate limit
const apiLimiter = rateLimit({
  store: new RedisStore({ sendCommand: (...args) => redis.call(...args) }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: { error: 'Too many requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Strict limit for auth endpoints (prevent brute force)
const authLimiter = rateLimit({
  store: new RedisStore({ sendCommand: (...args) => redis.call(...args) }),
  windowMs: 15 * 60 * 1000,
  max: 5, // 5 attempts per 15 minutes
  skipSuccessfulRequests: true, // Only count failures
  message: { error: 'Too many login attempts, please try again later' },
});

// Apply
app.use('/api/', apiLimiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);
```

---

## Secure Error Handling

```typescript
// ❌ BAD: Leak internal details
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack, // Never in production!
  });
});

// ✅ GOOD: Safe error responses
class AppError extends Error {
  constructor(
    public statusCode: number,
    public message: string,
    public isOperational = true
  ) {
    super(message);
  }
}

app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  // Log full error for debugging
  console.error('Error:', {
    message: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
    userId: req.user?.id,
  });

  // Return safe response
  if (err instanceof AppError && err.isOperational) {
    return res.status(err.statusCode).json({ error: err.message });
  }

  // Generic error for unexpected issues
  res.status(500).json({ error: 'An unexpected error occurred' });
});
```

---

## SQL Injection Prevention

```typescript
// ❌ BAD: String interpolation
const query = `SELECT * FROM users WHERE email = '${email}'`;

// ✅ GOOD: Parameterized queries (Prisma)
const user = await prisma.user.findUnique({ where: { email } });

// ✅ GOOD: Parameterized queries (raw SQL)
const user = await db.query('SELECT * FROM users WHERE email = $1', [email]);

// ✅ GOOD: Parameterized queries (Knex)
const user = await knex('users').where({ email }).first();
```

---

## Security Headers

```typescript
import helmet from 'helmet';

app.use(helmet());

// Custom CSP for APIs
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'none'"],
      frameAncestors: ["'none'"],
    },
  })
);

// Disable caching for sensitive endpoints
app.use('/api/auth', (req, res, next) => {
  res.set({
    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
    'Pragma': 'no-cache',
    'Expires': '0',
  });
  next();
});
```

---

## Recommended Libraries

| Purpose | Library | Why |
|---------|---------|-----|
| Validation | `zod` | TypeScript-first, runtime + compile time |
| Rate Limiting | `express-rate-limit` + `rate-limit-redis` | Distributed rate limiting |
| JWT | `jsonwebtoken` | Standard, well-maintained |
| Password Hashing | `bcrypt` or `argon2` | Argon2 preferred for new projects |
| Security Headers | `helmet` | Comprehensive defaults |

---

## Anti-Patterns

1. **Trusting client-side validation** - Always validate server-side
2. **Logging sensitive data** - Never log passwords, tokens, PII
3. **Returning full objects** - Only return needed fields
4. **Using sequential IDs** - Use UUIDs for public-facing resources
5. **Ignoring rate limiting** - Every endpoint needs limits

---

## References

- [references/auth-flows.md](references/auth-flows.md) - Authentication flow patterns
- [references/error-codes.md](references/error-codes.md) - Standardized error responses
- [references/logging.md](references/logging.md) - Secure logging practices

---

*This skill is maintained by [TamperTantrum Labs](https://tampertantrum.com)*
