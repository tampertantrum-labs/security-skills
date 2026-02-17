# Secure Form Patterns

Reference for building secure forms in React applications.

---

## Input Validation Schemas

> **Zod 4+**: Use top-level format types (`z.email()`, `z.url()`, `z.uuid()`) and
> `{ error: '...' }` instead of string messages. Always check [zod.dev](https://zod.dev)
> for the latest API before writing schemas.

### Common Zod Patterns

```tsx
import { z } from 'zod';

// Email - normalize BEFORE validation with .pipe()
const email = z.string()
  .trim()
  .toLowerCase()
  .pipe(z.email({ error: 'Invalid email' }).max(254, { error: 'Email too long' }));

// Password - strong
const password = z.string()
  .min(12, { error: 'Minimum 12 characters' })
  .max(128, { error: 'Maximum 128 characters' })
  .regex(/[A-Z]/, { error: 'Needs uppercase letter' })
  .regex(/[a-z]/, { error: 'Needs lowercase letter' })
  .regex(/[0-9]/, { error: 'Needs number' })
  .regex(/[^A-Za-z0-9]/, { error: 'Needs special character' });

// Username - safe characters only
const username = z.string()
  .min(3, { error: 'Minimum 3 characters' })
  .max(30, { error: 'Maximum 30 characters' })
  .regex(/^[a-zA-Z0-9_-]+$/, { error: 'Letters, numbers, underscore, hyphen only' })
  .toLowerCase()
  .trim();

// Phone - E.164 format
const phone = z.string()
  .regex(/^\+[1-9]\d{1,14}$/, { error: 'Invalid phone format' });

// URL - safe protocols only (Zod 4 built-in protocol + hostname validation)
const safeUrl = z.url({
  protocol: /^https?$/,          // Blocks javascript:, data:, vbscript:, etc.
  hostname: z.regexes.domain,    // Validates real domain names
  error: 'Only valid HTTP/HTTPS URLs allowed',
});

// Credit card (basic format)
const creditCard = z.string()
  .regex(/^\d{13,19}$/, { error: 'Invalid card number' })
  .refine((num) => luhnCheck(num), { error: 'Invalid card number' });

// Date in the past
const birthDate = z.coerce.date()
  .max(new Date(), { error: 'Date must be in the past' });

// Date in the future
const appointmentDate = z.coerce.date()
  .min(new Date(), { error: 'Date must be in the future' });

// Integer with range
const age = z.coerce.number()
  .int({ error: 'Must be whole number' })
  .min(0, { error: 'Must be positive' })
  .max(150, { error: 'Invalid age' });

// Price in cents (avoid float issues)
const priceInCents = z.coerce.number()
  .int()
  .min(0)
  .max(100000000); // $1M max

// Enum with custom error
const role = z.enum(['user', 'admin', 'moderator'], {
  error: 'Invalid role',
});

// Optional with default
const page = z.coerce.number().int().min(1).default(1);

// Array with constraints
const tags = z.array(z.string().max(50)).max(10);
```

---

## Form Component Template

```tsx
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';

const schema = z.object({
  email: z.string().trim().toLowerCase()
    .pipe(z.email({ error: 'Invalid email' }).max(254)),
  message: z.string().min(10, { error: 'Too short' }).max(1000).trim(),
});

type FormData = z.infer<typeof schema>;

export function ContactForm() {
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
    reset,
  } = useForm<FormData>({
    resolver: zodResolver(schema),
    mode: 'onBlur',
  });

  const onSubmit = async (data: FormData) => {
    try {
      const res = await fetch('/api/contact', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(data),
      });

      if (!res.ok) throw new Error('Failed to submit');
      
      reset(); // Clear form on success
    } catch (error) {
      // Handle error
    }
  };

  return (
    <form onSubmit={handleSubmit(onSubmit)} noValidate>
      <div>
        <label htmlFor="email">Email</label>
        <input
          {...register('email')}
          id="email"
          type="email"
          autoComplete="email"
          aria-invalid={!!errors.email}
          aria-describedby={errors.email ? 'email-error' : undefined}
        />
        {errors.email && (
          <span id="email-error" role="alert">
            {errors.email.message}
          </span>
        )}
      </div>

      <div>
        <label htmlFor="message">Message</label>
        <textarea
          {...register('message')}
          id="message"
          rows={5}
          aria-invalid={!!errors.message}
          aria-describedby={errors.message ? 'message-error' : undefined}
        />
        {errors.message && (
          <span id="message-error" role="alert">
            {errors.message.message}
          </span>
        )}
      </div>

      <button type="submit" disabled={isSubmitting}>
        {isSubmitting ? 'Sending...' : 'Send'}
      </button>
    </form>
  );
}
```

---

## File Upload Security

```tsx
const MAX_SIZE = 5 * 1024 * 1024; // 5MB
const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/webp'];

// Client-side validation (server MUST re-validate)
function validateFile(file: File): string | null {
  if (file.size > MAX_SIZE) {
    return 'File too large (max 5MB)';
  }
  
  if (!ALLOWED_TYPES.includes(file.type)) {
    return 'Invalid file type';
  }
  
  // Check extension matches MIME
  const ext = file.name.split('.').pop()?.toLowerCase();
  const validExts: Record<string, string[]> = {
    'image/jpeg': ['jpg', 'jpeg'],
    'image/png': ['png'],
    'image/webp': ['webp'],
  };
  
  if (!validExts[file.type]?.includes(ext || '')) {
    return 'File extension mismatch';
  }
  
  return null; // Valid
}

// Upload component
function FileUpload({ onUpload }: { onUpload: (file: File) => void }) {
  const [error, setError] = useState<string | null>(null);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const validationError = validateFile(file);
    if (validationError) {
      setError(validationError);
      e.target.value = ''; // Clear input
      return;
    }

    setError(null);
    onUpload(file);
  };

  return (
    <div>
      <input
        type="file"
        accept={ALLOWED_TYPES.join(',')}
        onChange={handleChange}
      />
      {error && <span role="alert">{error}</span>}
    </div>
  );
}
```

---

## CSRF Token Pattern

```tsx
// Hook to get CSRF token
function useCsrfToken(): string {
  const [token, setToken] = useState('');

  useEffect(() => {
    const meta = document.querySelector('meta[name="csrf-token"]');
    setToken(meta?.getAttribute('content') || '');
  }, []);

  return token;
}

// Use in forms
function SecureForm() {
  const csrfToken = useCsrfToken();

  return (
    <form method="POST" action="/api/submit">
      <input type="hidden" name="_csrf" value={csrfToken} />
      {/* ... form fields ... */}
    </form>
  );
}

// Or in fetch
async function secureSubmit(data: FormData) {
  const csrfToken = document.querySelector('meta[name="csrf-token"]')
    ?.getAttribute('content') || '';

  return fetch('/api/submit', {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrfToken,
    },
    body: JSON.stringify(Object.fromEntries(data)),
  });
}
```

---

## Preventing Double Submit

```tsx
function SubmitButton({ isSubmitting }: { isSubmitting: boolean }) {
  return (
    <button 
      type="submit" 
      disabled={isSubmitting}
      aria-busy={isSubmitting}
    >
      {isSubmitting ? (
        <>
          <span className="spinner" aria-hidden="true" />
          <span>Submitting...</span>
        </>
      ) : (
        'Submit'
      )}
    </button>
  );
}

// With react-hook-form, isSubmitting is automatic
const { formState: { isSubmitting } } = useForm();
```

---

## Autocomplete Security

Use correct `autocomplete` attributes:

| Field | Autocomplete Value |
|-------|-------------------|
| Email | `email` |
| Username | `username` |
| New password | `new-password` |
| Current password | `current-password` |
| Credit card number | `cc-number` |
| Credit card expiry | `cc-exp` |
| Credit card CVV | `cc-csc` |
| One-time code | `one-time-code` |
| Phone | `tel` |
| Address | `street-address` |

```tsx
// Disable autocomplete for sensitive one-time fields
<input autoComplete="off" />

// Or use a random value to prevent browser caching
<input autoComplete="new-password" /> // For password fields
```

---

## Server-Side Validation Reminder

**Client-side validation is for UX, not security.**

Server must ALWAYS re-validate:

```tsx
// Server (Next.js API route example)
import { z } from 'zod';

const schema = z.object({
  email: z.string().trim().toLowerCase().pipe(z.email().max(254)),
  message: z.string().min(10).max(1000),
});

export async function POST(req: Request) {
  const body = await req.json().catch(() => null);
  
  const result = schema.safeParse(body);
  if (!result.success) {
    return Response.json(
      { error: 'Validation failed', details: z.treeifyError(result.error) },
      { status: 400 }
    );
  }
  
  // Use result.data (validated)
}
```

---

## Checklist

- [ ] All inputs have Zod schemas
- [ ] Server re-validates all input
- [ ] File uploads validate type and size
- [ ] CSRF tokens on state-changing forms
- [ ] Double-submit prevented
- [ ] Correct autocomplete attributes
- [ ] Error messages don't leak sensitive info
- [ ] Forms clear sensitive data after submit
- [ ] Rate limiting on server
