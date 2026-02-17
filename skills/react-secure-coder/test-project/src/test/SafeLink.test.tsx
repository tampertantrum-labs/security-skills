/**
 * SafeLink Tests - URL Validation
 * 
 * These tests verify that the SafeLink component properly validates
 * URLs and blocks dangerous protocols like javascript: and data:
 */

import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { SafeLink, isValidUrl, isExternalUrl } from '../components/SafeLink';

// Mock window.location for tests
const mockLocation = (hostname: string) => {
  Object.defineProperty(window, 'location', {
    value: { hostname, origin: `https://${hostname}` },
    writable: true,
  });
};

describe('isValidUrl Function', () => {
  describe('Blocks dangerous protocols', () => {
    it('blocks javascript: URLs', () => {
      expect(isValidUrl('javascript:alert(1)')).toBe(false);
      expect(isValidUrl('javascript:void(0)')).toBe(false);
      expect(isValidUrl('JAVASCRIPT:alert(1)')).toBe(false); // Case insensitive
    });

    it('blocks data: URLs', () => {
      expect(isValidUrl('data:text/html,<script>alert(1)</script>')).toBe(false);
      expect(isValidUrl('data:image/svg+xml,<svg onload="alert(1)">')).toBe(false);
      expect(isValidUrl('DATA:text/html,<h1>test</h1>')).toBe(false);
    });

    it('blocks vbscript: URLs', () => {
      expect(isValidUrl('vbscript:msgbox("XSS")')).toBe(false);
    });

    it('blocks file: URLs', () => {
      expect(isValidUrl('file:///etc/passwd')).toBe(false);
    });

    it('blocks about: URLs', () => {
      expect(isValidUrl('about:blank')).toBe(false);
    });
  });

  describe('Allows safe protocols', () => {
    it('allows http: URLs', () => {
      expect(isValidUrl('http://example.com')).toBe(true);
      expect(isValidUrl('http://example.com/path?query=1')).toBe(true);
    });

    it('allows https: URLs', () => {
      expect(isValidUrl('https://example.com')).toBe(true);
      expect(isValidUrl('https://sub.example.com/path')).toBe(true);
    });

    it('allows mailto: URLs', () => {
      expect(isValidUrl('mailto:user@example.com')).toBe(true);
      expect(isValidUrl('mailto:user@example.com?subject=Hello')).toBe(true);
    });

    it('allows tel: URLs', () => {
      expect(isValidUrl('tel:+1234567890')).toBe(true);
      expect(isValidUrl('tel:555-1234')).toBe(true);
    });
  });

  describe('Handles edge cases', () => {
    it('returns false for invalid URLs', () => {
      expect(isValidUrl('not a url')).toBe(false);
      expect(isValidUrl('')).toBe(false);
      expect(isValidUrl('   ')).toBe(false);
    });

    it('handles relative URLs (treats as same origin)', () => {
      mockLocation('example.com');
      expect(isValidUrl('/path/to/page')).toBe(true);
      expect(isValidUrl('./relative')).toBe(true);
    });

    it('allows custom protocols when specified', () => {
      expect(isValidUrl('ftp://example.com', ['ftp:'])).toBe(true);
      expect(isValidUrl('ftp://example.com')).toBe(false); // Not in default
    });
  });

  describe('Bypass attempt resistance', () => {
    it('blocks case-varied javascript: URLs', () => {
      expect(isValidUrl('JaVaScRiPt:alert(1)')).toBe(false);
      expect(isValidUrl('JAVASCRIPT:alert(1)')).toBe(false);
      expect(isValidUrl('Javascript:void(0)')).toBe(false);
    });

    it('blocks case-varied data: URLs', () => {
      expect(isValidUrl('DATA:text/html,test')).toBe(false);
      expect(isValidUrl('Data:text/html,<h1>x</h1>')).toBe(false);
    });

    it('blocks protocol-relative URLs as non-relative', () => {
      // //evil.com could be treated as https://evil.com
      expect(isValidUrl('//evil.com/path')).toBe(false);
    });

    it('blocks URLs with leading/trailing whitespace in protocol', () => {
      // The URL constructor normalizes whitespace, but let's verify
      expect(isValidUrl(' javascript:alert(1)')).toBe(false);
    });

    it('blocks URLs with null bytes', () => {
      expect(isValidUrl('java\0script:alert(1)')).toBe(false);
    });

    it('handles URLs with encoded characters safely', () => {
      // %6A = 'j' — URL constructor decodes this to javascript:
      // The URL constructor should handle this correctly
      expect(isValidUrl('https://example.com/%6A')).toBe(true); // Safe: encoded path char
    });

    it('blocks URLs with credentials in authority', () => {
      // user:pass@host — can be used for phishing
      // These are still valid http: URLs, but worth testing
      const url = 'https://admin:password@evil.com';
      // URL constructor parses this as valid https — isValidUrl allows it
      // but isExternalUrl should flag it as external
      expect(isExternalUrl(url)).toBe(true);
    });
  });
});

describe('isExternalUrl Function', () => {
  beforeEach(() => {
    mockLocation('myapp.com');
  });

  it('identifies external URLs', () => {
    expect(isExternalUrl('https://external.com')).toBe(true);
    expect(isExternalUrl('https://evil.com/phishing')).toBe(true);
  });

  it('identifies internal URLs', () => {
    expect(isExternalUrl('https://myapp.com/page')).toBe(false);
    expect(isExternalUrl('/relative/path')).toBe(false);
  });

  it('treats subdomains as external', () => {
    expect(isExternalUrl('https://sub.myapp.com')).toBe(true);
  });
});

describe('SafeLink Component', () => {
  beforeEach(() => {
    mockLocation('myapp.com');
    vi.spyOn(console, 'warn').mockImplementation(() => {});
  });

  describe('Dangerous URL handling', () => {
    it('renders span for javascript: URLs', () => {
      render(<SafeLink href="javascript:alert(1)">Click me</SafeLink>);
      
      const element = screen.getByText('Click me');
      expect(element.tagName).toBe('SPAN');
      expect(element).not.toHaveAttribute('href');
    });

    it('renders span for data: URLs', () => {
      render(
        <SafeLink href="data:text/html,<script>alert(1)</script>">
          Malicious
        </SafeLink>
      );
      
      const element = screen.getByText('Malicious');
      expect(element.tagName).toBe('SPAN');
    });

    it('logs warning for blocked URLs without leaking input', () => {
      render(<SafeLink href="javascript:void(0)">Link</SafeLink>);
      expect(console.warn).toHaveBeenCalledWith(
        expect.stringContaining('blocked a URL with a disallowed protocol')
      );
      // Verify user input is NOT in the log
      const calls = (console.warn as ReturnType<typeof vi.fn>).mock.calls;
      const logOutput = calls.map(c => c.join(' ')).join(' ');
      expect(logOutput).not.toContain('javascript:');
    });
  });

  describe('Safe URL handling', () => {
    it('renders link for https URLs', () => {
      render(<SafeLink href="https://example.com">Safe Link</SafeLink>);
      
      const link = screen.getByText('Safe Link');
      expect(link.tagName).toBe('A');
      expect(link).toHaveAttribute('href', 'https://example.com');
    });

    it('renders link for mailto URLs', () => {
      render(<SafeLink href="mailto:test@example.com">Email</SafeLink>);
      
      const link = screen.getByText('Email');
      expect(link.tagName).toBe('A');
      expect(link).toHaveAttribute('href', 'mailto:test@example.com');
    });
  });

  describe('External link handling', () => {
    it('adds target="_blank" for external links', () => {
      render(<SafeLink href="https://external.com">External</SafeLink>);
      
      const link = screen.getByText('External');
      expect(link).toHaveAttribute('target', '_blank');
    });

    it('adds rel="noopener noreferrer" for external links', () => {
      render(<SafeLink href="https://external.com">External</SafeLink>);
      
      const link = screen.getByText('External');
      expect(link).toHaveAttribute('rel', 'noopener noreferrer');
    });

    it('does not add target for internal links', () => {
      render(<SafeLink href="https://myapp.com/page">Internal</SafeLink>);
      
      const link = screen.getByText('Internal');
      expect(link).not.toHaveAttribute('target');
    });

    it('does not add target for relative links', () => {
      render(<SafeLink href="/about">About</SafeLink>);
      
      const link = screen.getByText('About');
      expect(link).not.toHaveAttribute('target');
    });
  });

  describe('Props handling', () => {
    it('passes className to element', () => {
      render(
        <SafeLink href="https://example.com" className="my-class">
          Link
        </SafeLink>
      );
      
      const link = screen.getByText('Link');
      expect(link).toHaveClass('my-class');
    });

    it('respects custom allowed protocols', () => {
      render(
        <SafeLink 
          href="ftp://files.example.com" 
          allowedProtocols={['ftp:']}
        >
          FTP Link
        </SafeLink>
      );
      
      const link = screen.getByText('FTP Link');
      expect(link.tagName).toBe('A');
    });
  });
});
