/**
 * SecureForm - Form with Zod 4 validation
 * 
 * Demonstrates secure form handling with:
 * - Zod 4 top-level format types (z.email() instead of z.string().email())
 * - `error` parameter instead of deprecated `message`
 * - .pipe() for normalization before validation
 * - react-hook-form integration
 * - Proper error handling
 * - Accessibility
 */

import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';

// Schema with security constraints (Zod 4 API)
export const userFormSchema = z.object({
  // Normalize FIRST with trim/toLowerCase, then pipe into z.email()
  email: z
    .string()
    .trim()
    .toLowerCase()
    .pipe(
      z.email({ error: 'Invalid email address' })
        .max(254, { error: 'Email too long' })
    ),
  
  password: z
    .string()
    .min(12, { error: 'Password must be at least 12 characters' })
    .max(128, { error: 'Password too long' })
    .regex(/[A-Z]/, { error: 'Must contain at least one uppercase letter' })
    .regex(/[a-z]/, { error: 'Must contain at least one lowercase letter' })
    .regex(/[0-9]/, { error: 'Must contain at least one number' })
    .regex(/[^A-Za-z0-9]/, { error: 'Must contain at least one special character' }),
  
  // Normalize FIRST, then validate format
  username: z
    .string()
    .trim()
    .toLowerCase()
    .pipe(
      z.string()
        .min(3, { error: 'Username must be at least 3 characters' })
        .max(30, { error: 'Username too long' })
        .regex(
          /^[a-zA-Z0-9_-]+$/, 
          { error: 'Username can only contain letters, numbers, underscore, and hyphen' }
        )
    ),
});

export type UserFormData = z.infer<typeof userFormSchema>;

interface SecureFormProps {
  onSubmit: (data: UserFormData) => void | Promise<void>;
}

export function SecureForm({ onSubmit }: SecureFormProps) {
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<UserFormData>({
    resolver: zodResolver(userFormSchema),
    mode: 'onBlur',
  });

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
        <label htmlFor="username">Username</label>
        <input
          {...register('username')}
          id="username"
          type="text"
          autoComplete="username"
          aria-invalid={!!errors.username}
          aria-describedby={errors.username ? 'username-error' : undefined}
        />
        {errors.username && (
          <span id="username-error" role="alert">
            {errors.username.message}
          </span>
        )}
      </div>

      <div>
        <label htmlFor="password">Password</label>
        <input
          {...register('password')}
          id="password"
          type="password"
          autoComplete="new-password"
          aria-invalid={!!errors.password}
          aria-describedby={errors.password ? 'password-error' : undefined}
        />
        {errors.password && (
          <span id="password-error" role="alert">
            {errors.password.message}
          </span>
        )}
      </div>

      <button type="submit" disabled={isSubmitting}>
        {isSubmitting ? 'Submitting...' : 'Submit'}
      </button>
    </form>
  );
}
