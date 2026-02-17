/**
 * SecureForm Tests - Input Validation
 * 
 * These tests verify that the form properly validates user input
 * using Zod schemas and prevents malicious/invalid data.
 */

import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SecureForm, userFormSchema } from '../components/SecureForm';

describe('userFormSchema Validation', () => {
  describe('Email validation', () => {
    it('accepts valid emails', () => {
      const result = userFormSchema.shape.email.safeParse('user@example.com');
      expect(result.success).toBe(true);
    });

    it('normalizes emails to lowercase', () => {
      const result = userFormSchema.shape.email.safeParse('USER@EXAMPLE.COM');
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data).toBe('user@example.com');
      }
    });

    it('trims whitespace', () => {
      const result = userFormSchema.shape.email.safeParse('  user@example.com  ');
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data).toBe('user@example.com');
      }
    });

    it('rejects invalid emails', () => {
      expect(userFormSchema.shape.email.safeParse('notanemail').success).toBe(false);
      expect(userFormSchema.shape.email.safeParse('missing@domain').success).toBe(false);
      expect(userFormSchema.shape.email.safeParse('@nodomain.com').success).toBe(false);
    });

    it('rejects emails over 254 characters', () => {
      const longEmail = 'a'.repeat(250) + '@example.com';
      expect(userFormSchema.shape.email.safeParse(longEmail).success).toBe(false);
    });

    it('rejects empty email', () => {
      expect(userFormSchema.shape.email.safeParse('').success).toBe(false);
    });
  });

  describe('Password validation', () => {
    it('accepts strong passwords', () => {
      const result = userFormSchema.shape.password.safeParse('SecurePass123!');
      expect(result.success).toBe(true);
    });

    it('requires minimum 12 characters', () => {
      expect(userFormSchema.shape.password.safeParse('Short1!').success).toBe(false);
      expect(userFormSchema.shape.password.safeParse('Exactly12Ch!').success).toBe(true);
    });

    it('requires uppercase letter', () => {
      expect(userFormSchema.shape.password.safeParse('alllowercase123!').success).toBe(false);
    });

    it('requires lowercase letter', () => {
      expect(userFormSchema.shape.password.safeParse('ALLUPPERCASE123!').success).toBe(false);
    });

    it('requires number', () => {
      expect(userFormSchema.shape.password.safeParse('NoNumbersHere!!').success).toBe(false);
    });

    it('requires special character', () => {
      expect(userFormSchema.shape.password.safeParse('NoSpecialChar123').success).toBe(false);
    });

    it('rejects passwords over 128 characters', () => {
      const longPassword = 'Aa1!' + 'a'.repeat(130);
      expect(userFormSchema.shape.password.safeParse(longPassword).success).toBe(false);
    });
  });

  describe('Username validation', () => {
    it('accepts valid usernames', () => {
      expect(userFormSchema.shape.username.safeParse('john_doe').success).toBe(true);
      expect(userFormSchema.shape.username.safeParse('user-123').success).toBe(true);
      expect(userFormSchema.shape.username.safeParse('JohnDoe').success).toBe(true);
    });

    it('normalizes usernames to lowercase', () => {
      const result = userFormSchema.shape.username.safeParse('JohnDoe');
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data).toBe('johndoe');
      }
    });

    it('rejects usernames with special characters', () => {
      expect(userFormSchema.shape.username.safeParse('user@name').success).toBe(false);
      expect(userFormSchema.shape.username.safeParse('user name').success).toBe(false);
      expect(userFormSchema.shape.username.safeParse('user.name').success).toBe(false);
      expect(userFormSchema.shape.username.safeParse('<script>').success).toBe(false);
    });

    it('rejects usernames under 3 characters', () => {
      expect(userFormSchema.shape.username.safeParse('ab').success).toBe(false);
    });

    it('rejects usernames over 30 characters', () => {
      expect(userFormSchema.shape.username.safeParse('a'.repeat(31)).success).toBe(false);
    });

    it('rejects SQL injection attempts', () => {
      expect(userFormSchema.shape.username.safeParse("'; DROP TABLE users;--").success).toBe(false);
    });

    it('rejects XSS attempts', () => {
      expect(userFormSchema.shape.username.safeParse('<script>alert(1)</script>').success).toBe(false);
    });
  });
});

describe('SecureForm Component', () => {
  const user = userEvent.setup();

  describe('Form rendering', () => {
    it('renders all form fields', () => {
      render(<SecureForm onSubmit={() => {}} />);
      
      expect(screen.getByLabelText('Email')).toBeInTheDocument();
      expect(screen.getByLabelText('Username')).toBeInTheDocument();
      expect(screen.getByLabelText('Password')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Submit' })).toBeInTheDocument();
    });

    it('has proper accessibility attributes', () => {
      render(<SecureForm onSubmit={() => {}} />);
      
      const emailInput = screen.getByLabelText('Email');
      expect(emailInput).toHaveAttribute('type', 'email');
      expect(emailInput).toHaveAttribute('autoComplete', 'email');
      
      const passwordInput = screen.getByLabelText('Password');
      expect(passwordInput).toHaveAttribute('type', 'password');
      expect(passwordInput).toHaveAttribute('autoComplete', 'new-password');
    });
  });

  describe('Validation errors', () => {
    it('shows error for invalid email', async () => {
      render(<SecureForm onSubmit={() => {}} />);
      
      const emailInput = screen.getByLabelText('Email');
      await user.type(emailInput, 'invalid-email');
      await user.tab(); // Trigger blur validation
      
      await waitFor(() => {
        expect(screen.getByRole('alert')).toHaveTextContent('Invalid email');
      });
    });

    it('shows error for weak password', async () => {
      render(<SecureForm onSubmit={() => {}} />);
      
      const passwordInput = screen.getByLabelText('Password');
      await user.type(passwordInput, 'weak');
      await user.tab();
      
      await waitFor(() => {
        expect(screen.getByRole('alert')).toHaveTextContent('at least 12 characters');
      });
    });

    it('shows error for invalid username', async () => {
      render(<SecureForm onSubmit={() => {}} />);
      
      const usernameInput = screen.getByLabelText('Username');
      await user.type(usernameInput, 'u@');
      await user.tab();
      
      await waitFor(() => {
        expect(screen.getByRole('alert')).toBeInTheDocument();
      });
    });

    it('sets aria-invalid on invalid fields', async () => {
      render(<SecureForm onSubmit={() => {}} />);
      
      const emailInput = screen.getByLabelText('Email');
      await user.type(emailInput, 'invalid');
      await user.tab();
      
      await waitFor(() => {
        expect(emailInput).toHaveAttribute('aria-invalid', 'true');
      });
    });
  });

  describe('Form submission', () => {
    it('calls onSubmit with validated data', async () => {
      const handleSubmit = vi.fn();
      render(<SecureForm onSubmit={handleSubmit} />);
      
      await user.type(screen.getByLabelText('Email'), 'USER@example.com');
      await user.type(screen.getByLabelText('Username'), 'TestUser123');
      await user.type(screen.getByLabelText('Password'), 'SecurePassword123!');
      await user.click(screen.getByRole('button', { name: 'Submit' }));
      
      await waitFor(() => {
        expect(handleSubmit).toHaveBeenCalled();
        // react-hook-form passes (data, event) - check first argument
        expect(handleSubmit.mock.calls[0][0]).toEqual({
          email: 'user@example.com', // normalized
          username: 'testuser123', // normalized
          password: 'SecurePassword123!',
        });
      });
    });

    it('does not submit with invalid data', async () => {
      const handleSubmit = vi.fn();
      render(<SecureForm onSubmit={handleSubmit} />);
      
      await user.type(screen.getByLabelText('Email'), 'invalid');
      await user.click(screen.getByRole('button', { name: 'Submit' }));
      
      await waitFor(() => {
        expect(handleSubmit).not.toHaveBeenCalled();
      });
    });

    it('disables submit button while submitting', async () => {
      const handleSubmit = vi.fn(() => new Promise(r => setTimeout(r, 100)));
      render(<SecureForm onSubmit={handleSubmit} />);
      
      await user.type(screen.getByLabelText('Email'), 'user@example.com');
      await user.type(screen.getByLabelText('Username'), 'testuser');
      await user.type(screen.getByLabelText('Password'), 'SecurePassword123!');
      
      const submitButton = screen.getByRole('button');
      await user.click(submitButton);
      
      expect(submitButton).toBeDisabled();
      expect(submitButton).toHaveTextContent('Submitting...');
    });
  });
});
