# React Secure Coder - Test Suite

This test project validates the security patterns from the `react-secure-coder` skill.

## What's Tested

### 1. XSS Prevention (`SafeHtml.test.tsx`)
- Script tag removal
- Event handler stripping (`onerror`, `onclick`, `onload`, etc.)
- Iframe/style/form tag blocking
- `javascript:` and `data:` URL blocking in links
- Safe content preservation

### 2. URL Validation (`SafeLink.test.tsx`)
- `javascript:` URL blocking
- `data:` URL blocking
- `vbscript:`, `file:`, `about:` URL blocking
- Safe protocol allowlisting (http, https, mailto, tel)
- External link security attributes (`target="_blank"`, `rel="noopener noreferrer"`)
- Internal link handling

### 3. Form Validation (`SecureForm.test.tsx`)
- Email validation and normalization
- Password strength requirements (12+ chars, complexity)
- Username character restrictions (blocks injection attempts)
- SQL injection prevention in usernames
- XSS prevention in usernames
- Form accessibility (aria-invalid, aria-describedby)
- Submit state handling

## Running Tests

```bash
# Install dependencies (use pnpm for strict dependency isolation)
pnpm install

# Run tests once
pnpm test

# Run tests in watch mode
pnpm run test:watch

# Run tests with UI
pnpm run test:ui
```

## Test Results Expected

All tests should pass:

```
 ✓ SafeHtml Component
   ✓ XSS Prevention
     ✓ removes script tags
     ✓ removes onerror attributes from img tags
     ✓ removes onclick attributes
     ✓ removes onload attributes
     ✓ removes svg onload XSS
     ✓ removes iframe tags
     ✓ removes style tags
     ✓ removes form tags
     ✓ removes javascript: URLs from href
     ✓ removes data: URLs from href
   ✓ Safe Content Rendering
     ✓ allows basic formatting tags
     ✓ allows safe links
     ✓ adds security attributes to links
     ✓ allows lists
     ✓ allows code blocks

 ✓ SafeLink Component
   ✓ Dangerous URL handling
     ✓ renders span for javascript: URLs
     ✓ renders span for data: URLs
     ✓ logs warning for blocked URLs
   ✓ Safe URL handling
     ✓ renders link for https URLs
     ✓ renders link for mailto URLs
   ✓ External link handling
     ✓ adds target="_blank" for external links
     ✓ adds rel="noopener noreferrer" for external links
     ✓ does not add target for internal links

 ✓ SecureForm Component
   ✓ Validation errors
     ✓ shows error for invalid email
     ✓ shows error for weak password
     ✓ shows error for invalid username
   ✓ Form submission
     ✓ calls onSubmit with validated data
     ✓ does not submit with invalid data
```

## Security Payloads Tested

The tests include real-world XSS payloads:

| Payload | Should Be Blocked |
|---------|-------------------|
| `<script>alert('XSS')</script>` | ✅ |
| `<img src=x onerror=alert('XSS')>` | ✅ |
| `<svg onload=alert('XSS')>` | ✅ |
| `javascript:alert(1)` | ✅ |
| `data:text/html,<script>alert(1)</script>` | ✅ |
| `'; DROP TABLE users;--` (in username) | ✅ |
| `<script>alert(1)</script>` (in username) | ✅ |
| `JaVaScRiPt:alert(1)` (case variation) | ✅ |
| `//evil.com/path` (protocol-relative) | ✅ |
| `java\0script:alert(1)` (null byte) | ✅ |

## Using Components in Your App

```tsx
import { SafeHtml } from './components/SafeHtml';
import { SafeLink } from './components/SafeLink';
import { SecureForm } from './components/SecureForm';

// Render user-provided HTML safely
<SafeHtml html={userContent} />

// Safe external links
<SafeLink href={userProvidedUrl}>Click here</SafeLink>

// Form with built-in validation
<SecureForm onSubmit={(data) => api.signup(data)} />
```

## Adding More Tests

When adding new security features, follow this pattern:

```tsx
describe('NewSecurityFeature', () => {
  describe('Attack Prevention', () => {
    it('blocks [specific attack]', () => {
      // Test that malicious input is blocked
    });
  });
  
  describe('Safe Usage', () => {
    it('allows [legitimate use case]', () => {
      // Test that normal usage works
    });
  });
});
```
