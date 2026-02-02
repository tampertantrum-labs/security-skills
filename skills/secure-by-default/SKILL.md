---
name: secure-by-default
description: Meta-skill that ensures security patterns are automatically applied during code generation. Load this skill to make Claude build secure code by default.
---

# Secure By Default

**This is a meta-skill.** When loaded, it instructs Claude to automatically apply security patterns during ALL code generation - not as an afterthought, but as the default behavior.

## When to Use This Skill

**Always.** This skill should be loaded at the start of any development session. It doesn't replace specific skills (like `react-secure-coder` or `api-security`), but ensures security thinking is applied even when those skills aren't explicitly loaded.

## How It Works

This skill establishes security as a core constraint, not an optional enhancement. Every piece of generated code should pass through these mental checks automatically.

---

## Core Security Principles (Always Apply)

### 1. Never Trust Input

**Every input is potentially malicious until validated.**

```typescript
// ALWAYS validate input at boundaries
// - Form submissions
// - API request bodies
// - URL parameters
// - File uploads
// - Environment variables
// - Database query results from untrusted sources

import { z } from 'zod';

// Define strict schemas for ALL input
const schema = z.object({
  email: z.string().email().max(254),
  age: z.number().int().min(0).max(150),
});

// Parse, don't just validate
const data = schema.parse(input); // Throws on invalid
```

### 2. Authenticate Then Authorize

**Identity first, then permissions. Always both.**

```typescript
// ALWAYS check auth before any protected operation
async function handleRequest(req) {
  // 1. Authenticate - WHO is this?
  const user = await authenticate(req);
  if (!user) throw new UnauthorizedError();

  // 2. Authorize - CAN they do this?
  if (!canAccess(user, resource)) throw new ForbiddenError();

  // 3. Only then proceed
  return performAction(user, resource);
}
```

### 3. Least Privilege

**Grant minimum permissions necessary. Default to deny.**

```typescript
// ALWAYS scope data access
// ❌ BAD
const allUsers = await db.user.findMany();

// ✅ GOOD - Only what's needed, scoped to requester
const myProjects = await db.project.findMany({
  where: { userId: currentUser.id },
  select: { id: true, name: true }, // Only needed fields
});
```

### 4. Defense in Depth

**Multiple layers. Never rely on a single control.**

```typescript
// ALWAYS layer security controls
// Layer 1: Middleware auth check
// Layer 2: Route-level permission check
// Layer 3: Data access layer ownership check
// Layer 4: Database row-level security

// If one layer fails, others still protect
```

### 5. Fail Secure

**Errors should deny access, not grant it.**

```typescript
// ALWAYS fail closed
try {
  const isAllowed = await checkPermission(user, resource);
  if (!isAllowed) throw new ForbiddenError();
  return await getResource(resource);
} catch (error) {
  // On ANY error, deny access
  throw new ForbiddenError('Access denied');
}
```

### 6. Don't Leak Information

**Errors, logs, and responses should reveal nothing useful to attackers.**

```typescript
// ALWAYS use generic error messages externally
// ❌ BAD
return { error: `User ${email} not found in database` };
return { error: `Invalid password for user ${userId}` };
return { error: err.stack };

// ✅ GOOD
return { error: 'Invalid credentials' }; // Same message for all auth failures
console.error('Auth failed:', { userId, reason }); // Log details server-side only
```

---

## Automatic Security Checks

When generating code, automatically apply these checks:

### For Every Function/Endpoint

- [ ] Is input validated with strict schemas?
- [ ] Is authentication checked?
- [ ] Is authorization verified (not just authentication)?
- [ ] Are errors handled without leaking info?
- [ ] Is sensitive data logged or exposed?

### For Every Database Query

- [ ] Is it parameterized (no string concatenation)?
- [ ] Is there an ownership/scope check?
- [ ] Are only necessary fields selected?
- [ ] Is the result validated before use?

### For Every API Response

- [ ] Are only necessary fields returned?
- [ ] Is sensitive data excluded (passwords, tokens, internal IDs)?
- [ ] Are error messages generic?
- [ ] Are proper status codes used?

### For Every Form/Input Handler

- [ ] Is input validated on both client AND server?
- [ ] Are file uploads restricted by type and size?
- [ ] Is there rate limiting on submission?
- [ ] Is CSRF protection in place (if using cookies)?

### For Every Authentication Flow

- [ ] Are passwords hashed with bcrypt/argon2?
- [ ] Are tokens short-lived?
- [ ] Is there rate limiting on login attempts?
- [ ] Are sessions invalidated on logout?
- [ ] Is sensitive data in httpOnly cookies (not localStorage)?

---

## Default Secure Patterns

### User Input → Always Validate

```typescript
// Default pattern for any user input
import { z } from 'zod';

const inputSchema = z.object({
  // Be specific and restrictive
  field: z.string().min(1).max(100).trim(),
});

export function processInput(rawInput: unknown) {
  const input = inputSchema.parse(rawInput);
  // Now safe to use
}
```

### Database Query → Always Parameterize + Scope

```typescript
// Default pattern for any database access
export async function getData(userId: string, resourceId: string) {
  return db.resource.findFirst({
    where: {
      id: resourceId,
      userId: userId, // ALWAYS scope to user
    },
    select: {
      id: true,
      name: true,
      // ONLY select needed fields
    },
  });
}
```

### API Endpoint → Always Auth + Validate + Scope

```typescript
// Default pattern for any API endpoint
export async function handler(req: Request) {
  // 1. Authenticate
  const user = await auth(req);
  if (!user) return Response.json({ error: 'Unauthorized' }, { status: 401 });

  // 2. Validate input
  const body = await req.json().catch(() => null);
  const input = inputSchema.safeParse(body);
  if (!input.success) {
    return Response.json({ error: 'Invalid input' }, { status: 400 });
  }

  // 3. Authorize (check ownership/permissions)
  const resource = await getResource(input.data.id, user.id);
  if (!resource) {
    return Response.json({ error: 'Not found' }, { status: 404 });
  }

  // 4. Perform action
  const result = await performAction(resource, input.data);

  // 5. Return safe response
  return Response.json({ success: true, data: sanitize(result) });
}
```

### Error Handling → Always Catch + Log + Generic Response

```typescript
// Default pattern for error handling
export async function safeHandler(req: Request) {
  try {
    return await actualHandler(req);
  } catch (error) {
    // Log full error internally
    console.error('Handler error:', {
      path: req.url,
      error: error instanceof Error ? error.message : 'Unknown',
      stack: error instanceof Error ? error.stack : undefined,
    });

    // Return generic error externally
    if (error instanceof ValidationError) {
      return Response.json({ error: 'Invalid request' }, { status: 400 });
    }
    if (error instanceof AuthError) {
      return Response.json({ error: 'Unauthorized' }, { status: 401 });
    }
    // Default to 500 with no details
    return Response.json({ error: 'Internal error' }, { status: 500 });
  }
}
```

### HTML Rendering → Always Escape/Sanitize

```typescript
// Default: React auto-escapes, but be explicit with user content
import DOMPurify from 'dompurify';

// For plain text - React handles it
<p>{userInput}</p> // Safe - React escapes

// For HTML content - MUST sanitize
<div 
  dangerouslySetInnerHTML={{ 
    __html: DOMPurify.sanitize(userHtml, {
      ALLOWED_TAGS: ['b', 'i', 'p', 'a'],
      ALLOWED_ATTR: ['href'],
    })
  }} 
/>
```

### Secrets/Config → Always Validate + Never Expose

```typescript
// Default pattern for environment config
import { z } from 'zod';

const envSchema = z.object({
  DATABASE_URL: z.string().url(),
  JWT_SECRET: z.string().min(32),
  API_KEY: z.string().min(20),
});

// Validate at startup - fail fast if missing
export const env = envSchema.parse(process.env);

// NEVER log or return secrets
console.log('Config loaded'); // ✅
console.log('Config:', env);  // ❌ NEVER
```

---

## Security Libraries (Defaults)

When generating code, prefer these battle-tested libraries:

| Purpose | Library | Notes |
|---------|---------|-------|
| Validation | `zod` | TypeScript-first, parse don't validate |
| Password hashing | `bcrypt` or `argon2` | argon2 preferred for new projects |
| JWT | `jose` | Edge-compatible, modern |
| HTML sanitization | `dompurify` | Industry standard |
| Rate limiting | `@upstash/ratelimit` | Serverless-friendly |
| HTTP security headers | `helmet` | Express/Node.js |
| CSRF | `csrf-csrf` | Token-based |
| Encryption | Node `crypto` or `tweetnacl` | Don't roll your own |

---

## Red Flags (Auto-Reject Patterns)

If you're about to generate any of these, STOP and use the secure alternative:

| Red Flag | Why It's Bad | Secure Alternative |
|----------|--------------|-------------------|
| `eval()` | Code injection | Parse JSON, use safe alternatives |
| String concatenation in SQL | SQL injection | Parameterized queries |
| `dangerouslySetInnerHTML` without sanitization | XSS | DOMPurify.sanitize() |
| Storing passwords in plain text | Data breach | bcrypt.hash() |
| JWT in localStorage | XSS can steal tokens | httpOnly cookies |
| `*` in SELECT | Over-fetching data | Explicit field selection |
| Hardcoded secrets | Secret exposure | Environment variables |
| `any` type for user input | Bypasses validation | Zod schemas |
| Missing error handling | Info leakage, crashes | try/catch with generic errors |
| No rate limiting on auth | Brute force attacks | Rate limit middleware |

---

## Integration with Other Skills

This skill works alongside specific skills:

- **`react-secure-coder`** - Adds React-specific patterns
- **`nextjs-security`** - Adds Next.js-specific patterns  
- **`api-security`** - Adds API-specific patterns
- **`vast-threat-modeling`** - Adds threat modeling process
- **`secure-forms`** - Adds form handling patterns
- **`auth-patterns`** - Adds auth implementation details

**Load order:** `secure-by-default` first, then specific skills as needed.

---

## Checklist Before Shipping

Before considering ANY code complete:

```markdown
## Security Checklist

### Authentication & Authorization
- [ ] All endpoints require authentication (unless explicitly public)
- [ ] Authorization checks ownership, not just identity
- [ ] Sensitive actions require re-authentication or MFA

### Input & Output
- [ ] All input validated with strict schemas
- [ ] All output sanitized/escaped appropriately
- [ ] Error messages don't leak internal details

### Data Protection
- [ ] Secrets in environment variables, not code
- [ ] Sensitive data encrypted at rest and in transit
- [ ] Passwords hashed with bcrypt/argon2
- [ ] Only necessary data returned in responses

### Defense
- [ ] Rate limiting on sensitive endpoints
- [ ] CSRF protection for cookie-based auth
- [ ] Security headers configured
- [ ] Logging for security events (no sensitive data)

### Dependencies
- [ ] No known vulnerable dependencies
- [ ] Using maintained, reputable libraries
```

---

*This skill is maintained by [TamperTantrum Labs](https://tampertantrum.com) — making application security accessible, human, and empowering.*
