---
name: secure-forms
description: Secure form handling patterns. Input validation, file uploads, CSRF protection, and sanitization done right.
---

# Secure Forms

Build forms that are secure by default. Covers input validation, file uploads, CSRF protection, and sanitization across React, Next.js, and vanilla JS.

## When to Use This Skill

- Building any form that accepts user input
- Handling file uploads
- Processing form submissions
- Implementing search/filter functionality
- Building admin interfaces with data entry

## When NOT to Use This Skill

- Static content display
- Read-only dashboards

---

## Input Validation

### Client + Server Validation (Always Both)

```tsx
// schemas/user.ts - Shared schema
import { z } from 'zod';

export const signupSchema = z.object({
  email: z
    .string()
    .email('Invalid email address')
    .max(254, 'Email too long')
    .toLowerCase()
    .trim(),
  
  password: z
    .string()
    .min(12, 'Password must be at least 12 characters')
    .regex(/[A-Z]/, 'Must contain uppercase letter')
    .regex(/[a-z]/, 'Must contain lowercase letter')
    .regex(/[0-9]/, 'Must contain number')
    .regex(/[^A-Za-z0-9]/, 'Must contain special character'),
  
  username: z
    .string()
    .min(3, 'Username must be at least 3 characters')
    .max(30, 'Username too long')
    .regex(/^[a-zA-Z0-9_-]+$/, 'Only letters, numbers, underscore, hyphen')
    .toLowerCase()
    .trim(),
  
  age: z
    .number()
    .int('Age must be a whole number')
    .min(13, 'Must be at least 13 years old')
    .max(120, 'Invalid age'),
});

export type SignupData = z.infer<typeof signupSchema>;
```

```tsx
// Client-side: React Hook Form + Zod
'use client';

import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { signupSchema, SignupData } from '@/schemas/user';

export function SignupForm() {
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<SignupData>({
    resolver: zodResolver(signupSchema),
  });

  const onSubmit = async (data: SignupData) => {
    // Data is already validated by Zod
    const res = await fetch('/api/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    // Handle response...
  };

  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      <input {...register('email')} type="email" />
      {errors.email && <span>{errors.email.message}</span>}
      
      <input {...register('password')} type="password" />
      {errors.password && <span>{errors.password.message}</span>}
      
      <button type="submit" disabled={isSubmitting}>
        {isSubmitting ? 'Signing up...' : 'Sign Up'}
      </button>
    </form>
  );
}
```

```tsx
// Server-side: ALWAYS re-validate (never trust client)
// app/api/signup/route.ts
import { NextResponse } from 'next/server';
import { signupSchema } from '@/schemas/user';

export async function POST(request: Request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Invalid JSON' }, { status: 400 });
  }

  // Re-validate on server - client validation can be bypassed
  const result = signupSchema.safeParse(body);
  if (!result.success) {
    return NextResponse.json(
      { error: 'Validation failed', details: result.error.flatten() },
      { status: 400 }
    );
  }

  // Use validated data
  const { email, password, username, age } = result.data;
  
  // ... create user
}
```

---

## Common Input Patterns

### Text Fields

```typescript
const textSchema = z.object({
  // Basic text - trim and limit
  name: z.string().trim().min(1).max(100),
  
  // Multi-line text
  bio: z.string().trim().max(500).optional(),
  
  // Slug/URL-safe
  slug: z.string().regex(/^[a-z0-9-]+$/).min(3).max(50),
  
  // No HTML allowed (strip tags)
  comment: z.string().transform(s => s.replace(/<[^>]*>/g, '')).max(1000),
});
```

### Numbers

```typescript
const numberSchema = z.object({
  // Integer with range
  quantity: z.number().int().min(1).max(100),
  
  // Price (handle as cents/integers to avoid float issues)
  priceInCents: z.number().int().min(0).max(1000000),
  
  // From string input (forms submit strings)
  age: z.string().transform(Number).pipe(z.number().int().min(0).max(150)),
  
  // Optional with default
  page: z.coerce.number().int().min(1).default(1),
});
```

### Dates

```typescript
const dateSchema = z.object({
  // ISO date string
  birthDate: z.string().date(), // YYYY-MM-DD
  
  // Full datetime
  appointmentAt: z.string().datetime(), // ISO 8601
  
  // Date object
  createdAt: z.coerce.date(),
  
  // With constraints
  eventDate: z.coerce.date()
    .min(new Date(), 'Date must be in the future')
    .max(new Date('2030-12-31'), 'Date too far in future'),
});
```

### Enums & Selects

```typescript
const enumSchema = z.object({
  // Fixed options
  role: z.enum(['user', 'admin', 'moderator']),
  
  // With custom error
  status: z.enum(['active', 'inactive', 'pending'], {
    errorMap: () => ({ message: 'Invalid status selected' }),
  }),
  
  // Multi-select (array of enums)
  permissions: z.array(z.enum(['read', 'write', 'delete'])).min(1),
});
```

### URLs & Emails

```typescript
const urlSchema = z.object({
  // Email with normalization
  email: z.string().email().toLowerCase().trim(),
  
  // URL with protocol restriction
  website: z.string().url().refine(
    (url) => url.startsWith('https://'),
    'Must be HTTPS'
  ),
  
  // Optional URL
  linkedin: z.string().url().optional().or(z.literal('')),
  
  // URL safe from open redirect
  redirectUrl: z.string().url().refine(
    (url) => new URL(url).hostname === 'myapp.com',
    'Invalid redirect URL'
  ),
});
```

---

## File Uploads

### Secure File Upload Handler

```tsx
// schemas/file.ts
import { z } from 'zod';

const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
const ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
const ALLOWED_DOC_TYPES = ['application/pdf', 'text/plain'];

export const imageUploadSchema = z.object({
  file: z
    .instanceof(File)
    .refine((file) => file.size <= MAX_FILE_SIZE, 'File too large (max 5MB)')
    .refine(
      (file) => ALLOWED_IMAGE_TYPES.includes(file.type),
      'Invalid file type. Allowed: JPEG, PNG, WebP, GIF'
    ),
});

export const documentUploadSchema = z.object({
  file: z
    .instanceof(File)
    .refine((file) => file.size <= MAX_FILE_SIZE, 'File too large (max 5MB)')
    .refine(
      (file) => ALLOWED_DOC_TYPES.includes(file.type),
      'Invalid file type. Allowed: PDF, TXT'
    ),
});
```

```tsx
// Server-side upload handler
// app/api/upload/route.ts
import { NextResponse } from 'next/server';
import { writeFile } from 'fs/promises';
import path from 'path';
import crypto from 'crypto';

const MAX_FILE_SIZE = 5 * 1024 * 1024;
const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/webp'];

export async function POST(request: Request) {
  const formData = await request.formData();
  const file = formData.get('file') as File | null;

  if (!file) {
    return NextResponse.json({ error: 'No file provided' }, { status: 400 });
  }

  // 1. Validate file size
  if (file.size > MAX_FILE_SIZE) {
    return NextResponse.json({ error: 'File too large' }, { status: 400 });
  }

  // 2. Validate MIME type
  if (!ALLOWED_TYPES.includes(file.type)) {
    return NextResponse.json({ error: 'Invalid file type' }, { status: 400 });
  }

  // 3. Validate file extension matches MIME type
  const ext = path.extname(file.name).toLowerCase();
  const validExtensions: Record<string, string[]> = {
    'image/jpeg': ['.jpg', '.jpeg'],
    'image/png': ['.png'],
    'image/webp': ['.webp'],
  };
  
  if (!validExtensions[file.type]?.includes(ext)) {
    return NextResponse.json({ error: 'File extension mismatch' }, { status: 400 });
  }

  // 4. Generate safe filename (never use original filename)
  const safeFilename = `${crypto.randomUUID()}${ext}`;
  
  // 5. Read and validate content (magic bytes)
  const bytes = await file.arrayBuffer();
  const buffer = Buffer.from(bytes);
  
  // Check magic bytes for images
  const isValidImage = validateMagicBytes(buffer, file.type);
  if (!isValidImage) {
    return NextResponse.json({ error: 'Invalid file content' }, { status: 400 });
  }

  // 6. Save to safe location (outside web root ideally)
  const uploadDir = path.join(process.cwd(), 'uploads');
  await writeFile(path.join(uploadDir, safeFilename), buffer);

  return NextResponse.json({ 
    success: true, 
    filename: safeFilename,
    url: `/api/files/${safeFilename}`,
  });
}

function validateMagicBytes(buffer: Buffer, mimeType: string): boolean {
  const magicBytes: Record<string, number[]> = {
    'image/jpeg': [0xFF, 0xD8, 0xFF],
    'image/png': [0x89, 0x50, 0x4E, 0x47],
    'image/webp': [0x52, 0x49, 0x46, 0x46], // RIFF
  };

  const expected = magicBytes[mimeType];
  if (!expected) return false;

  for (let i = 0; i < expected.length; i++) {
    if (buffer[i] !== expected[i]) return false;
  }
  return true;
}
```

### Client-Side File Validation

```tsx
'use client';

import { useState } from 'react';

const MAX_SIZE = 5 * 1024 * 1024;
const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/webp'];

export function ImageUpload() {
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<string | null>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    setError(null);
    setPreview(null);

    if (!file) return;

    // Client-side validation (server will re-validate)
    if (file.size > MAX_SIZE) {
      setError('File too large (max 5MB)');
      e.target.value = '';
      return;
    }

    if (!ALLOWED_TYPES.includes(file.type)) {
      setError('Invalid file type');
      e.target.value = '';
      return;
    }

    // Show preview
    const reader = new FileReader();
    reader.onload = () => setPreview(reader.result as string);
    reader.readAsDataURL(file);
  };

  return (
    <div>
      <input
        type="file"
        accept="image/jpeg,image/png,image/webp"
        onChange={handleFileChange}
      />
      {error && <p className="error">{error}</p>}
      {preview && <img src={preview} alt="Preview" style={{ maxWidth: 200 }} />}
    </div>
  );
}
```

---

## CSRF Protection

### For Cookie-Based Authentication

```tsx
// lib/csrf.ts
import { randomBytes } from 'crypto';
import { cookies } from 'next/headers';

const CSRF_COOKIE = 'csrf_token';
const CSRF_HEADER = 'x-csrf-token';

export function generateCsrfToken(): string {
  return randomBytes(32).toString('hex');
}

export async function setCsrfCookie(): Promise<string> {
  const token = generateCsrfToken();
  
  cookies().set(CSRF_COOKIE, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
    maxAge: 60 * 60, // 1 hour
  });

  return token;
}

export async function validateCsrfToken(request: Request): Promise<boolean> {
  const cookieToken = cookies().get(CSRF_COOKIE)?.value;
  const headerToken = request.headers.get(CSRF_HEADER);

  if (!cookieToken || !headerToken) return false;
  
  // Constant-time comparison to prevent timing attacks
  if (cookieToken.length !== headerToken.length) return false;
  
  let result = 0;
  for (let i = 0; i < cookieToken.length; i++) {
    result |= cookieToken.charCodeAt(i) ^ headerToken.charCodeAt(i);
  }
  
  return result === 0;
}
```

```tsx
// app/api/protected/route.ts
import { validateCsrfToken } from '@/lib/csrf';

export async function POST(request: Request) {
  // Validate CSRF token for state-changing requests
  const validCsrf = await validateCsrfToken(request);
  if (!validCsrf) {
    return Response.json({ error: 'Invalid CSRF token' }, { status: 403 });
  }

  // ... handle request
}
```

```tsx
// Client: Include CSRF token in requests
'use client';

export async function submitForm(data: FormData) {
  const csrfToken = document.querySelector<HTMLMetaElement>(
    'meta[name="csrf-token"]'
  )?.content;

  const res = await fetch('/api/protected', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrfToken ?? '',
    },
    body: JSON.stringify(Object.fromEntries(data)),
    credentials: 'include',
  });

  return res.json();
}
```

### For Token-Based Auth (JWT in Headers)

CSRF protection is less critical when using Bearer tokens in headers (not cookies), but you should still:

1. Use `SameSite=Strict` on any cookies
2. Validate `Origin` header matches expected domains
3. Use short-lived tokens

---

## Output Sanitization

### Displaying User Content

```tsx
// For plain text - React auto-escapes
function Comment({ text }: { text: string }) {
  return <p>{text}</p>; // Safe - React escapes HTML entities
}

// For rich text/HTML - MUST sanitize
import DOMPurify from 'dompurify';

function RichComment({ html }: { html: string }) {
  const clean = DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'ol', 'li'],
    ALLOWED_ATTR: ['href'],
    ALLOW_DATA_ATTR: false,
  });

  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
```

### Search/Filter Display

```tsx
// Prevent XSS in search highlighting
function SearchResults({ query, results }: { query: string; results: string[] }) {
  // Escape the query for use in regex
  const escapedQuery = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const regex = new RegExp(`(${escapedQuery})`, 'gi');

  return (
    <ul>
      {results.map((result, i) => (
        <li key={i}>
          {result.split(regex).map((part, j) =>
            regex.test(part) ? <mark key={j}>{part}</mark> : part
          )}
        </li>
      ))}
    </ul>
  );
}
```

---

## Rate Limiting Forms

```tsx
// Prevent form spam
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';
import { headers } from 'next/headers';

const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(5, '1 m'), // 5 submissions per minute
});

export async function POST(request: Request) {
  // Rate limit by IP
  const ip = headers().get('x-forwarded-for') ?? 'unknown';
  const { success, remaining } = await ratelimit.limit(ip);

  if (!success) {
    return Response.json(
      { error: 'Too many submissions. Please wait.' },
      { 
        status: 429,
        headers: { 'Retry-After': '60' },
      }
    );
  }

  // Process form...
}
```

---

## Anti-Patterns

| Anti-Pattern | Risk | Solution |
|--------------|------|----------|
| Client-only validation | Bypass via dev tools | Always validate server-side |
| Using original filenames | Path traversal, overwrites | Generate random filenames |
| Trusting file extensions | Malicious file execution | Validate magic bytes |
| No file size limits | DoS via large uploads | Enforce size limits |
| Reflecting user input in HTML | XSS | Escape/sanitize output |
| No rate limiting | Spam, brute force | Rate limit by IP/user |
| Missing CSRF tokens | CSRF attacks | Implement CSRF protection |

---

## References

- [references/validation-patterns.md](references/validation-patterns.md) - More Zod patterns
- [references/upload-security.md](references/upload-security.md) - File upload deep dive
- [references/csrf-guide.md](references/csrf-guide.md) - CSRF implementation guide

---

*This skill is maintained by [TamperTantrum Labs](https://tampertantrum.com) — making application security accessible, human, and empowering.*
