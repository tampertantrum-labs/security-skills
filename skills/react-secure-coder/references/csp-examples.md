# CSP Configuration Examples

Real-world Content Security Policy configurations for common scenarios.

---

## CSP Directives Quick Reference

| Directive | Controls | Example |
|-----------|----------|---------|
| `default-src` | Fallback for all | `'self'` |
| `script-src` | JavaScript | `'self' https://cdn.example.com` |
| `style-src` | CSS | `'self' 'unsafe-inline'` |
| `img-src` | Images | `'self' data: https:` |
| `font-src` | Fonts | `'self' https://fonts.gstatic.com` |
| `connect-src` | Fetch, XHR, WebSocket | `'self' https://api.example.com` |
| `frame-src` | iframes | `'self' https://youtube.com` |
| `frame-ancestors` | Who can embed us | `'none'` |
| `object-src` | Plugins (Flash, etc.) | `'none'` |
| `base-uri` | `<base>` tag | `'self'` |
| `form-action` | Form submissions | `'self'` |
| `upgrade-insecure-requests` | HTTP → HTTPS | (no value) |
| `report-uri` | Violation reports | `https://report.example.com` |

---

## Source Values

| Value | Meaning |
|-------|---------|
| `'self'` | Same origin |
| `'none'` | Block everything |
| `'unsafe-inline'` | Allow inline scripts/styles (avoid!) |
| `'unsafe-eval'` | Allow eval() (avoid!) |
| `'nonce-{random}'` | Allow specific inline with nonce |
| `'strict-dynamic'` | Trust scripts loaded by trusted scripts |
| `https:` | Any HTTPS URL |
| `data:` | Data URIs |
| `blob:` | Blob URIs |
| `*.example.com` | Wildcard subdomain |

---

## Minimal Secure CSP

The most restrictive starting point:

```
Content-Security-Policy:
  default-src 'none';
  script-src 'self';
  style-src 'self';
  img-src 'self';
  font-src 'self';
  connect-src 'self';
  frame-ancestors 'none';
  base-uri 'none';
  form-action 'self';
```

---

## Standard SaaS Application

Typical configuration for a modern SaaS:

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'unsafe-inline';
  style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
  img-src 'self' data: https: blob:;
  font-src 'self' https://fonts.gstatic.com;
  connect-src 'self' https://api.yourapp.com wss://realtime.yourapp.com;
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self';
  upgrade-insecure-requests;
```

---

## With Google Analytics (GA4)

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'unsafe-inline'
    https://www.googletagmanager.com
    https://www.google-analytics.com
    https://ssl.google-analytics.com;
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:
    https://www.google-analytics.com
    https://www.googletagmanager.com;
  connect-src 'self'
    https://www.google-analytics.com
    https://analytics.google.com
    https://region1.google-analytics.com;
  frame-ancestors 'none';
```

---

## With Stripe Payments

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self' https://js.stripe.com;
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https://*.stripe.com;
  font-src 'self';
  connect-src 'self' https://api.stripe.com;
  frame-src https://js.stripe.com https://hooks.stripe.com;
  frame-ancestors 'none';
```

---

## With Intercom Support

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'unsafe-inline'
    https://widget.intercom.io
    https://js.intercomcdn.com;
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:
    https://static.intercomassets.com
    https://downloads.intercomcdn.com
    https://gifs.intercomcdn.com;
  font-src 'self'
    https://js.intercomcdn.com;
  connect-src 'self'
    https://api.intercom.io
    https://api-iam.intercom.io
    https://nexus-websocket-a.intercom.io
    wss://nexus-websocket-a.intercom.io;
  frame-src https://intercom-sheets.com;
  media-src https://js.intercomcdn.com;
```

---

## With YouTube Embeds

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https://i.ytimg.com https://img.youtube.com;
  frame-src https://www.youtube.com https://www.youtube-nocookie.com;
  frame-ancestors 'none';
```

---

## With Sentry Error Tracking

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self' https://browser.sentry-cdn.com;
  connect-src 'self'
    https://*.ingest.sentry.io
    https://*.ingest.us.sentry.io;
  frame-ancestors 'none';
```

---

## With Cloudflare (Turnstile, CDN)

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self'
    https://challenges.cloudflare.com
    https://static.cloudflareinsights.com;
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  connect-src 'self'
    https://cloudflareinsights.com;
  frame-src https://challenges.cloudflare.com;
  frame-ancestors 'none';
```

---

## Full Stack Example (Analytics + Payments + Support)

Combining Google Analytics, Stripe, and Intercom:

```
Content-Security-Policy:
  default-src 'self';
  
  script-src 'self' 'unsafe-inline'
    https://www.googletagmanager.com
    https://www.google-analytics.com
    https://js.stripe.com
    https://widget.intercom.io
    https://js.intercomcdn.com;
  
  style-src 'self' 'unsafe-inline'
    https://fonts.googleapis.com;
  
  img-src 'self' data: https: blob:;
  
  font-src 'self'
    https://fonts.gstatic.com
    https://js.intercomcdn.com;
  
  connect-src 'self'
    https://api.yourapp.com
    wss://realtime.yourapp.com
    https://www.google-analytics.com
    https://analytics.google.com
    https://api.stripe.com
    https://api.intercom.io
    https://api-iam.intercom.io
    wss://nexus-websocket-a.intercom.io;
  
  frame-src
    https://js.stripe.com
    https://hooks.stripe.com
    https://intercom-sheets.com;
  
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self';
  upgrade-insecure-requests;
```

---

## Using Nonces (Most Secure)

Eliminate `'unsafe-inline'` with nonces:

```tsx
// Middleware generates nonce
const nonce = crypto.randomBytes(16).toString('base64');

const csp = `
  default-src 'self';
  script-src 'self' 'nonce-${nonce}' 'strict-dynamic';
  style-src 'self' 'nonce-${nonce}';
`;

// Pass nonce to page
response.headers.set('Content-Security-Policy', csp);

// In HTML, add nonce to inline scripts/styles
<script nonce={nonce}>/* inline code */</script>
<style nonce={nonce}>/* inline styles */</style>
```

---

## Report-Only Mode (Testing)

Test CSP without breaking your site:

```
Content-Security-Policy-Report-Only:
  default-src 'self';
  script-src 'self';
  report-uri https://your-report-collector.com/csp;
```

This logs violations but doesn't block them.

---

## Violation Reporting

Set up reporting to catch issues:

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self';
  report-uri https://your-domain.report-uri.com/r/d/csp/enforce;
  report-to csp-endpoint;
```

Add Report-To header:

```
Report-To: {
  "group": "csp-endpoint",
  "max_age": 10886400,
  "endpoints": [{
    "url": "https://your-domain.report-uri.com/a/d/g"
  }]
}
```

Free reporting services:
- [Report URI](https://report-uri.com/)
- [Sentry CSP](https://docs.sentry.io/product/security-policy-reporting/)

---

## Development vs Production

```tsx
const isDev = process.env.NODE_ENV === 'development';

const csp = isDev
  ? `
    default-src 'self';
    script-src 'self' 'unsafe-inline' 'unsafe-eval';
    style-src 'self' 'unsafe-inline';
    connect-src 'self' ws://localhost:* http://localhost:*;
    img-src 'self' data: blob: https:;
  `
  : `
    default-src 'self';
    script-src 'self';
    style-src 'self';
    connect-src 'self' https://api.yourapp.com;
    img-src 'self' data: https:;
    frame-ancestors 'none';
    upgrade-insecure-requests;
  `;
```

---

## Testing Your CSP

1. **Browser DevTools** — Console shows CSP violations
2. **[CSP Evaluator](https://csp-evaluator.withgoogle.com/)** — Google's testing tool
3. **[Observatory](https://observatory.mozilla.org/)** — Mozilla's security scanner
4. **Report-Only mode** — Test in production safely

---

## Common Mistakes

| Mistake | Problem | Fix |
|---------|---------|-----|
| `'unsafe-inline'` everywhere | Defeats XSS protection | Use nonces |
| `'unsafe-eval'` | Allows code injection | Remove it |
| `*` wildcards | Too permissive | Specific domains |
| Missing `frame-ancestors` | Clickjacking possible | Add `'none'` or `'self'` |
| Missing `upgrade-insecure-requests` | Mixed content | Add it |
| No reporting | Can't see violations | Add report-uri |
