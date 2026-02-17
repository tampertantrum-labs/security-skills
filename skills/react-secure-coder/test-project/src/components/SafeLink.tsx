/**
 * SafeLink - Validates URLs before rendering links
 * 
 * This component prevents javascript:, data:, and other dangerous
 * URL schemes from being used in links.
 */

import { ReactNode } from 'react';

interface SafeLinkProps {
  href: string;
  children: ReactNode;
  className?: string;
  allowedProtocols?: string[];
}

// Default safe protocols
const DEFAULT_ALLOWED_PROTOCOLS = ['http:', 'https:', 'mailto:', 'tel:'];

/**
 * Validates if a URL is safe to use
 */
export function isValidUrl(
  url: string, 
  allowedProtocols = DEFAULT_ALLOWED_PROTOCOLS
): boolean {
  // Reject empty or whitespace-only strings
  if (!url || !url.trim()) {
    return false;
  }
  
  try {
    // Try parsing as absolute URL first
    const parsed = new URL(url);
    return allowedProtocols.includes(parsed.protocol);
  } catch {
    // If not absolute, check if it looks like a relative URL (starts with / or ./)
    // This prevents random text from being treated as valid URLs
    // IMPORTANT: Block protocol-relative URLs (//evil.com) — they redirect to another host
    if (url.startsWith('//')) {
      return false; // Protocol-relative URL — not a safe relative path
    }
    if (url.startsWith('/') || url.startsWith('./') || url.startsWith('../')) {
      return true; // Relative paths are safe (same-origin)
    }
    // Invalid URL format
    return false;
  }
}

/**
 * Checks if a URL is external (different hostname)
 */
export function isExternalUrl(url: string): boolean {
  try {
    const parsed = new URL(url, window.location.origin);
    return parsed.hostname !== window.location.hostname;
  } catch {
    return false;
  }
}

export function SafeLink({
  href,
  children,
  className,
  allowedProtocols = DEFAULT_ALLOWED_PROTOCOLS,
}: SafeLinkProps) {
  // Validate URL
  if (!isValidUrl(href, allowedProtocols)) {
    // Don't log the URL itself — user input in logs can enable log injection
    console.warn('SafeLink: blocked a URL with a disallowed protocol');
    // Render as non-clickable span
    return <span className={className}>{children}</span>;
  }

  const isExternal = isExternalUrl(href);

  return (
    <a
      href={href}
      className={className}
      // External links get security attributes
      {...(isExternal && {
        target: '_blank',
        rel: 'noopener noreferrer',
      })}
    >
      {children}
    </a>
  );
}
