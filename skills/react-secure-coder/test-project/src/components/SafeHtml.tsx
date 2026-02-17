/**
 * SafeHtml - Sanitizes HTML using DOMPurify before rendering
 * 
 * This component demonstrates the CORRECT way to render user-provided HTML
 * in React applications, preventing XSS attacks.
 */

import DOMPurify from 'dompurify';
import { useMemo } from 'react';

interface SafeHtmlProps {
  html: string;
  allowedTags?: string[];
  allowedAttr?: string[];
  className?: string;
}

// Default safe tags for rich text content
const DEFAULT_ALLOWED_TAGS = [
  'b', 'i', 'em', 'strong', 'a', 'p', 'br', 
  'ul', 'ol', 'li', 'code', 'pre', 'blockquote'
];

const DEFAULT_ALLOWED_ATTR = ['href', 'target', 'rel'];

// Configure DOMPurify hooks
const purify = DOMPurify();

// Force safe link behavior
purify.addHook('afterSanitizeAttributes', (node) => {
  if (node.tagName === 'A') {
    node.setAttribute('target', '_blank');
    node.setAttribute('rel', 'noopener noreferrer');
  }
});

export function SafeHtml({
  html,
  allowedTags = DEFAULT_ALLOWED_TAGS,
  allowedAttr = DEFAULT_ALLOWED_ATTR,
  className,
}: SafeHtmlProps) {
  const sanitizedHtml = useMemo(() => {
    return purify.sanitize(html, {
      ALLOWED_TAGS: allowedTags,
      ALLOWED_ATTR: allowedAttr,
      ALLOW_DATA_ATTR: false,
      FORBID_TAGS: ['style', 'script', 'iframe', 'form', 'input', 'button'],
      FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover', 'style'],
    });
  }, [html, allowedTags, allowedAttr]);

  return (
    <div
      className={className}
      dangerouslySetInnerHTML={{ __html: sanitizedHtml }}
    />
  );
}

// Export the sanitize function for direct use
export function sanitizeHtml(
  html: string,
  options?: {
    allowedTags?: string[];
    allowedAttr?: string[];
  }
): string {
  return purify.sanitize(html, {
    ALLOWED_TAGS: options?.allowedTags ?? DEFAULT_ALLOWED_TAGS,
    ALLOWED_ATTR: options?.allowedAttr ?? DEFAULT_ALLOWED_ATTR,
    ALLOW_DATA_ATTR: false,
  });
}
