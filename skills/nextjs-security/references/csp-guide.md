# CSP Configuration Guide for Next.js

Comprehensive Content Security Policy setup for Next.js App Router applications.

---

## CSP Basics for Next.js

Content Security Policy controls which resources (scripts, styles, images, fonts, connections, etc.) are allowed to load on your pages. It is the primary defense against XSS attacks. Two approaches exist in Next.js:

| Approach | Best For | Nonce Support | Dynamic |
|----------|----------|---------------|---------|
| `next.config.ts` headers | Simple static policies, hash-based allowlisting | No | No |
| Middleware | Nonce-based policies, per-request dynamic policies | Yes | Yes |

For any application using third-party scripts (analytics, payments, chat widgets), use the middleware approach with nonces.

---

## Nonce-Based CSP via Middleware

The recommended approach for production Next.js applications.

### Step 1 -- Generate Nonce in Middleware

```typescript
// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest): NextResponse {
  const nonce = Buffer.from(crypto.randomUUID()).toString('base64');

  const cspHeader = [
    `default-src 'self'`,
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`,
    `style-src 'self' 'nonce-${nonce}'`,
    `img-src 'self' blob: data: https:`,
    `font-src 'self'`,
    `connect-src 'self'`,
    `media-src 'self'`,
    `object-src 'none'`,
    `frame-src 'none'`,
    `frame-ancestors 'none'`,
    `base-uri 'self'`,
    `form-action 'self'`,
    `upgrade-insecure-requests`,
  ].join('; ');

  // Set the nonce on REQUEST headers -- server-internal only.
  // Server Components read this via headers() but it never reaches the browser.
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);

  // Build the response, forwarding the modified request headers
  const response = NextResponse.next({
    request: { headers: requestHeaders },
  });

  // Set the CSP on RESPONSE headers -- this IS sent to the browser
  response.headers.set('Content-Security-Policy', cspHeader);

  return response;
}

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon\\.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)',
  ],
};
```

### Step 2 -- Read Nonce in Root Layout

```typescript
// app/layout.tsx
import { headers } from 'next/headers';
import Script from 'next/script';

export default async function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  // Next.js 16+: headers() is async
  const nonce = (await headers()).get('x-nonce') ?? '';

  return (
    <html lang="en">
      <head>
        <style nonce={nonce}>{`
          :root { color-scheme: light dark; }
        `}</style>
      </head>
      <body>
        {children}
        {/* Pass nonce to every Script component */}
        <Script
          src="https://example.com/analytics.js"
          strategy="afterInteractive"
          nonce={nonce}
        />
      </body>
    </html>
  );
}
```

### Critical Rule: Never Set Nonce on Response Headers

```typescript
// CORRECT -- nonce on request headers only (server-internal)
const requestHeaders = new Headers(request.headers);
requestHeaders.set('x-nonce', nonce);

const response = NextResponse.next({
  request: { headers: requestHeaders },
});
response.headers.set('Content-Security-Policy', cspHeader);

// WRONG -- never do this:
// response.headers.set('x-nonce', nonce); // Leaks nonce to network observers!
```

If the nonce appears on response headers, it travels over the network to the browser. Any network observer (proxy, CDN log, browser extension) can read it and use it to craft allowlisted script tags, defeating CSP entirely.

---

## CSP Directive Reference

### Core Directives

| Directive | Controls | Recommended Value |
|-----------|----------|-------------------|
| `default-src` | Fallback for any fetch directive not explicitly set | `'self'` |
| `script-src` | JavaScript sources allowed to execute | `'self' 'nonce-{nonce}' 'strict-dynamic'` |
| `style-src` | CSS sources allowed to apply | `'self' 'nonce-{nonce}'` |
| `img-src` | Image sources | `'self' blob: data: https:` |
| `font-src` | Font sources | `'self'` (add CDN if using Google Fonts) |
| `connect-src` | Fetch, XHR, WebSocket, EventSource destinations | `'self'` (add API endpoints as needed) |
| `media-src` | Audio and video sources | `'self'` |
| `object-src` | `<object>`, `<embed>`, `<applet>` sources | `'none'` -- always block |
| `frame-src` | Sources allowed in `<iframe>` | `'none'` or specific domains |
| `frame-ancestors` | Which pages can embed this page in an iframe | `'none'` or `'self'` |
| `base-uri` | Allowed values for `<base href>` | `'self'` -- prevents base tag hijacking |
| `form-action` | URLs forms can submit to | `'self'` |
| `upgrade-insecure-requests` | Upgrades HTTP sub-resources to HTTPS | Include in production |
| `report-uri` / `report-to` | Where to send violation reports | Your reporting endpoint |

### Key Directive Details

**`script-src` with `'strict-dynamic'`** -- Propagates trust from a nonce-allowlisted script to any scripts it dynamically loads. Essential for third-party scripts that inject additional scripts at runtime (analytics, tag managers, chat widgets).

**`object-src 'none'`** -- Flash and plugin content is a historical XSS vector. Always block. No legitimate reason for modern web apps to load plugin content.

**`frame-ancestors 'none'`** -- Prevents clickjacking. This directive must be set as an HTTP header -- it is ignored in `<meta>` CSP tags.

**`base-uri 'self'`** -- Prevents an attacker from injecting `<base href="https://evil.com">` to redirect all relative URLs.

### Source Expression Reference

| Source Expression | Meaning |
|-------------------|---------|
| `'self'` | Same origin (scheme + host + port) |
| `'none'` | No sources allowed |
| `'unsafe-inline'` | Inline scripts/styles (avoid -- defeats CSP) |
| `'unsafe-eval'` | Dynamic code evaluation APIs (never in production) |
| `'strict-dynamic'` | Propagates trust from nonce-allowlisted scripts |
| `'nonce-{value}'` | Script/style with matching nonce attribute |
| `'sha256-{hash}'` | Script/style with matching content hash |
| `https:` | Any HTTPS source |
| `https://example.com` | Specific origin |
| `https://*.example.com` | Wildcard subdomain |
| `data:` | Data URIs (only use for img-src) |
| `blob:` | Blob URIs |

---

## Third-Party Service Configurations

| Service | `script-src` | `connect-src` | `img-src` | `frame-src` | `style-src` | `font-src` |
|---------|-------------|---------------|-----------|-------------|-------------|------------|
| Google Analytics (GA4) | `https://www.googletagmanager.com` | `https://*.google-analytics.com https://*.analytics.google.com https://*.googletagmanager.com` | `https://*.google-analytics.com` | -- | -- | -- |
| Google Fonts | -- | -- | -- | -- | `https://fonts.googleapis.com` | `https://fonts.gstatic.com` |
| Stripe.js | `https://js.stripe.com` | `https://api.stripe.com` | -- | `https://js.stripe.com https://hooks.stripe.com` | -- | -- |
| Vercel Analytics | `https://va.vercel-scripts.com` | `https://va.vercel-scripts.com` | -- | -- | -- | -- |
| Vercel Speed Insights | `https://va.vercel-scripts.com` | `https://vitals.vercel-insights.com` | -- | -- | -- | -- |
| Sentry | -- | `https://*.sentry.io https://*.ingest.sentry.io` | -- | -- | -- | -- |
| Intercom | `https://widget.intercom.io https://js.intercomcdn.com` | `https://api.intercom.io https://*.intercom.io wss://*.intercom.io` | `https://*.intercomcdn.com https://*.intercom.io` | `https://intercom-sheets.com` | `https://rsms.me` | `https://rsms.me` |
| YouTube embeds | -- | -- | `https://i.ytimg.com` | `https://www.youtube-nocookie.com` | -- | -- |

### Full CSP Middleware with Common Third Parties

```typescript
// middleware.ts
export function middleware(request: NextRequest): NextResponse {
  const nonce = Buffer.from(crypto.randomUUID()).toString('base64');

  const cspHeader = [
    `default-src 'self'`,
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic' https://www.googletagmanager.com https://js.stripe.com https://va.vercel-scripts.com`,
    `style-src 'self' 'nonce-${nonce}' https://fonts.googleapis.com`,
    `img-src 'self' data: blob: https://*.google-analytics.com`,
    `font-src 'self' https://fonts.gstatic.com`,
    `connect-src 'self' https://*.google-analytics.com https://*.analytics.google.com https://*.googletagmanager.com https://api.stripe.com https://*.sentry.io https://*.ingest.sentry.io https://vitals.vercel-insights.com`,
    `media-src 'self'`,
    `object-src 'none'`,
    `frame-src https://js.stripe.com https://hooks.stripe.com https://www.youtube-nocookie.com`,
    `frame-ancestors 'none'`,
    `base-uri 'self'`,
    `form-action 'self'`,
    `upgrade-insecure-requests`,
  ].join('; ');

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);

  const response = NextResponse.next({
    request: { headers: requestHeaders },
  });
  response.headers.set('Content-Security-Policy', cspHeader);

  return response;
}
```

### Service Notes

- **GA4**: Uses `'strict-dynamic'` to handle dynamically injected scripts from `googletagmanager.com`
- **Stripe**: Requires `frame-src` for hosted payment fields (Stripe Elements / Payment Element)
- **Sentry**: SDK is bundled via npm (`pnpm add @sentry/nextjs`) -- only `connect-src` needed for error payloads
- **YouTube**: Always use `youtube-nocookie.com` instead of `youtube.com` to avoid tracking cookies

---

## Report-Only Mode

Test your CSP before enforcing it using `Content-Security-Policy-Report-Only`. Violations are logged but resources are not blocked.

```typescript
// Use Report-Only during testing
response.headers.set('Content-Security-Policy-Report-Only', cspHeader);

// Switch to enforcing once validated:
// response.headers.set('Content-Security-Policy', cspHeader);
```

### CSP Reporting Endpoint

```typescript
// app/api/csp-report/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';

const cspReportSchema = z.object({
  'csp-report': z.object({
    'document-uri': z.string(),
    'violated-directive': z.string(),
    'blocked-uri': z.string(),
    'source-file': z.string().optional(),
    'line-number': z.number().optional(),
    'column-number': z.number().optional(),
  }),
});

export async function POST(request: NextRequest): Promise<NextResponse> {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return new NextResponse(null, { status: 400 });
  }

  const result = cspReportSchema.safeParse(body);
  if (!result.success) {
    return new NextResponse(null, { status: 400 });
  }

  const report = result.data['csp-report'];

  // Log for analysis -- in production, send to your observability platform
  console.warn('CSP Violation:', {
    documentUri: report['document-uri'],
    violatedDirective: report['violated-directive'],
    blockedUri: report['blocked-uri'],
    sourceFile: report['source-file'],
  });

  return new NextResponse(null, { status: 204 });
}
```

### Rollout Strategy

1. Deploy with `Content-Security-Policy-Report-Only` and your reporting endpoint
2. Monitor violations for at least one week across all user flows
3. Add necessary allowlist entries for legitimate resources
4. Repeat until no violations from legitimate sources appear
5. Switch header to `Content-Security-Policy` to enforce
6. Keep `Report-Only` running in parallel during initial enforcement

---

## Common CSP Mistakes in Next.js

| Mistake | Why It's a Problem | Correct Approach |
|---------|--------------------|--------------------|
| Using `unsafe-inline` in `script-src` | Allows all inline scripts, defeating XSS protection | Use `'nonce-{value}'` and `'strict-dynamic'` |
| Using `unsafe-eval` in production | Allows dynamic code evaluation -- a code injection vector | Configure bundlers to avoid it. Next.js prod builds do not require it |
| Setting nonce on response headers | Leaks nonce to network observers, defeating CSP | Set nonce only on request headers |
| Omitting `'strict-dynamic'` | Third-party scripts that inject other scripts will be blocked | Include `'strict-dynamic'` alongside the nonce |
| `frame-ancestors` in `<meta>` tag | Ignored by browsers in meta tags -- only works as HTTP header | Set via middleware or `next.config.ts` |
| Overly broad `connect-src` (e.g., `*`) | Allows data exfiltration to any endpoint | List only specific origins your app communicates with |
| Static nonce (set at build time) | Becomes predictable -- defeats the whole purpose | Generate nonce in middleware, which runs per request |
| Missing `object-src 'none'` | Plugin content unrestricted, defaults to `default-src` | Always explicitly set `object-src 'none'` |
| Missing `base-uri 'self'` | Attacker can inject `<base>` tag to redirect all relative URLs | Always include `base-uri 'self'` |

---

## Using next/script with Nonce

```typescript
// app/layout.tsx
import { headers } from 'next/headers';
import Script from 'next/script';

export default async function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const nonce = (await headers()).get('x-nonce') ?? '';

  return (
    <html lang="en">
      <body>
        {children}
        <Script
          src="https://www.googletagmanager.com/gtag/js?id=G-XXXXXXXXXX"
          strategy="afterInteractive"
          nonce={nonce}
        />
      </body>
    </html>
  );
}
```

### Script Loading Strategies

| Strategy | When it Loads | CSP Nonce Required |
|----------|---------------|-------------------|
| `beforeInteractive` | Before page hydration, in `<head>` | Yes |
| `afterInteractive` (default) | After page becomes interactive | Yes |
| `lazyOnload` | During browser idle time | Yes |
| `worker` | Web Worker via Partytown | Different CSP considerations |

---

## Static CSP via next.config.ts

For simpler apps that do not need nonces (no inline scripts, no dynamically injected third-party scripts):

```typescript
// next.config.ts
import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          {
            key: 'Content-Security-Policy',
            value: [
              `default-src 'self'`,
              `script-src 'self'`,
              `style-src 'self'`,
              `img-src 'self' blob: data:`,
              `font-src 'self'`,
              `connect-src 'self'`,
              `object-src 'none'`,
              `frame-ancestors 'none'`,
              `base-uri 'self'`,
              `form-action 'self'`,
              `upgrade-insecure-requests`,
            ].join('; '),
          },
        ],
      },
    ];
  },
};

export default nextConfig;
```

### Hash-Based Script Allowlisting

For known static inline scripts, compute the SHA-256 hash and add it to `script-src`:

```bash
# Generate hash for an inline script
echo -n 'window.__APP_CONFIG__ = { env: "production" };' | openssl dgst -sha256 -binary | openssl base64
# Add the output as 'sha256-{hash}' to script-src
```

### Static CSP Limitations

| Limitation | Impact |
|------------|--------|
| No nonce support | Cannot use `'strict-dynamic'`; dynamically injected scripts blocked |
| Hash-based allowlisting is fragile | Any script change requires recomputing the hash |
| Cannot adapt per-request | Same policy for all requests |
| Third-party script loaders | Will break without nonces or `unsafe-inline` |

For apps using Google Analytics, Stripe, Intercom, or other script-injecting services, use the nonce-based middleware approach.

---

*This reference is maintained by [TamperTantrum Labs](https://tampertantrum.com) -- making application security accessible, human, and empowering.*
