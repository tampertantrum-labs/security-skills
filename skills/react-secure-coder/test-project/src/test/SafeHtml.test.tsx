/**
 * SafeHtml Tests - XSS Prevention
 * 
 * These tests verify that the SafeHtml component properly sanitizes
 * malicious HTML content and prevents XSS attacks.
 */

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { SafeHtml, sanitizeHtml } from '../components/SafeHtml';

describe('SafeHtml Component', () => {
  describe('XSS Prevention', () => {
    it('removes script tags', () => {
      const malicious = '<script>alert("XSS")</script><p>Safe content</p>';
      render(<SafeHtml html={malicious} />);
      
      expect(screen.getByText('Safe content')).toBeInTheDocument();
      expect(document.querySelector('script')).toBeNull();
    });

    it('removes onerror attributes from img tags', () => {
      const malicious = '<img src="x" onerror="alert(\'XSS\')"><p>Text</p>';
      render(<SafeHtml html={malicious} />);
      
      const img = document.querySelector('img');
      expect(img).toBeNull(); // img not in default allowed tags
      expect(screen.getByText('Text')).toBeInTheDocument();
    });

    it('removes onclick attributes', () => {
      const malicious = '<p onclick="alert(\'XSS\')">Click me</p>';
      render(<SafeHtml html={malicious} />);
      
      const p = screen.getByText('Click me');
      expect(p.getAttribute('onclick')).toBeNull();
    });

    it('removes onload attributes', () => {
      const malicious = '<body onload="alert(\'XSS\')"><p>Content</p></body>';
      render(<SafeHtml html={malicious} />);
      
      const body = document.querySelector('body[onload]');
      expect(body).toBeNull();
    });

    it('removes svg onload XSS', () => {
      const malicious = '<svg onload="alert(\'XSS\')"></svg><p>Safe</p>';
      render(<SafeHtml html={malicious} />);
      
      const svg = document.querySelector('svg');
      expect(svg).toBeNull(); // svg not in default allowed tags
    });

    it('removes iframe tags', () => {
      const malicious = '<iframe src="https://evil.com"></iframe><p>Content</p>';
      render(<SafeHtml html={malicious} />);
      
      expect(document.querySelector('iframe')).toBeNull();
      expect(screen.getByText('Content')).toBeInTheDocument();
    });

    it('removes style tags', () => {
      const malicious = '<style>body{display:none}</style><p>Content</p>';
      render(<SafeHtml html={malicious} />);
      
      expect(document.querySelector('style')).toBeNull();
    });

    it('removes form tags', () => {
      const malicious = '<form action="https://evil.com"><input></form><p>Safe</p>';
      render(<SafeHtml html={malicious} />);
      
      expect(document.querySelector('form')).toBeNull();
    });

    it('removes javascript: URLs from href', () => {
      const malicious = '<a href="javascript:alert(\'XSS\')">Click</a>';
      render(<SafeHtml html={malicious} />);
      
      const link = screen.getByText('Click');
      const href = link.getAttribute('href');
      // DOMPurify removes dangerous href entirely or sanitizes it
      expect(href === null || !href.includes('javascript:')).toBe(true);
    });

    it('removes data: URLs from href', () => {
      const malicious = '<a href="data:text/html,<script>alert(1)</script>">Click</a>';
      render(<SafeHtml html={malicious} />);
      
      const link = screen.getByText('Click');
      const href = link.getAttribute('href');
      // DOMPurify removes dangerous href entirely or sanitizes it
      expect(href === null || !href.includes('data:')).toBe(true);
    });
  });

  describe('Safe Content Rendering', () => {
    it('allows basic formatting tags', () => {
      const safe = '<p><b>Bold</b> and <i>italic</i> and <em>emphasis</em></p>';
      render(<SafeHtml html={safe} />);
      
      expect(screen.getByText('Bold')).toBeInTheDocument();
      expect(document.querySelector('b')).toBeInTheDocument();
      expect(document.querySelector('i')).toBeInTheDocument();
      expect(document.querySelector('em')).toBeInTheDocument();
    });

    it('allows safe links', () => {
      const safe = '<a href="https://example.com">Link</a>';
      render(<SafeHtml html={safe} />);
      
      const link = screen.getByText('Link');
      expect(link).toHaveAttribute('href', 'https://example.com');
    });

    it('adds security attributes to links', () => {
      const safe = '<a href="https://example.com">Link</a>';
      render(<SafeHtml html={safe} />);
      
      const link = screen.getByText('Link');
      expect(link).toHaveAttribute('target', '_blank');
      expect(link).toHaveAttribute('rel', 'noopener noreferrer');
    });

    it('allows lists', () => {
      const safe = '<ul><li>Item 1</li><li>Item 2</li></ul>';
      render(<SafeHtml html={safe} />);
      
      expect(screen.getByText('Item 1')).toBeInTheDocument();
      expect(screen.getByText('Item 2')).toBeInTheDocument();
    });

    it('allows code blocks', () => {
      const safe = '<pre><code>const x = 1;</code></pre>';
      render(<SafeHtml html={safe} />);
      
      expect(document.querySelector('pre')).toBeInTheDocument();
      expect(document.querySelector('code')).toBeInTheDocument();
    });
  });
});

describe('sanitizeHtml Function', () => {
  it('sanitizes script injection', () => {
    const result = sanitizeHtml('<script>alert(1)</script>');
    expect(result).not.toContain('<script>');
    expect(result).not.toContain('alert');
  });

  it('preserves safe HTML', () => {
    const result = sanitizeHtml('<p><strong>Hello</strong></p>');
    expect(result).toContain('<p>');
    expect(result).toContain('<strong>');
    expect(result).toContain('Hello');
  });

  it('respects custom allowed tags', () => {
    const result = sanitizeHtml(
      '<p><div>Content</div></p>',
      { allowedTags: ['p', 'div'] }
    );
    expect(result).toContain('<div>');
  });
});
