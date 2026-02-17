# Security Skills — Review & Improvement Tracker

Tracking the review, fix, and enhancement work for each skill.
Each skill needs the same treatment `react-secure-coder` received.

## Per-Skill Checklist

For each skill:

- [ ] **Review for accuracy** — API correctness, contradictions, outdated patterns
- [ ] **Fix bugs** — anything incorrect or misleading
- [ ] **Add missing coverage** — topics the skill should cover but doesn't
- [ ] **Add reference docs** — supporting checklists, quick-reference material
- [ ] **Add test project** — executable validation with bypass-resistance tests (where applicable)
- [ ] **Update anti-patterns table** — ensure new topics are reflected

---

## Completed

### react-secure-coder
- [x] Review for accuracy
- [x] Fix bugs (CSP meta tag, nonce leak, ProtectedRoute role check, console.warn log injection, protocol-relative URL bypass)
- [x] Add missing coverage (Open Redirect, SRI, Env Vars, Prop Spreading, Error Boundaries, Honeypot, Link Security)
- [x] Add reference docs (xss-patterns, auth-checklist, csp-examples, form-security)
- [x] Add test project (80 tests — SafeHtml, SafeLink, SecureForm + bypass edge cases)
- [x] Update anti-patterns table (9 → 17 entries)
- **Branch:** `feature/react-secure-coder-improvements`
- **PR:** https://github.com/tampertantrum-labs/security-skills/pull/1

---

## In Progress

### nextjs-security (691 → 1034 lines)
- [x] Review for accuracy (async APIs, CSP nonce pattern, library renames, Zod API)
- [x] Fix bugs (6 critical: async cookies/headers/params, nonce response header leak, CSP middleware structure; 4 moderate: Auth.js rename, lucia deprecated, next.config.ts, Zod flatten)
- [x] Add missing coverage (Open Redirect, Taint API, Error Handling, CORS, File Uploads, Cache Security, next/script nonce, Server Action public endpoint warning)
- [x] Add reference docs (auth-patterns, middleware-examples, csp-guide)
- [ ] Add test project
- [x] Update anti-patterns table (7 → 17 entries)
- **Notes:** No test project yet — Next.js skill is primarily patterns/guidance, may not need an executable test project like react-secure-coder

---

## Pending

### 2. api-security (362 lines)
- [ ] Review for accuracy (JWT library APIs, rate limiting patterns)
- [ ] Fix bugs
- [ ] Add missing coverage
- [ ] Add reference docs
- [ ] Add test project
- **Notes:** Smallest skill, high-impact. Check JWT/jose API accuracy.

### 3. secure-forms (615 lines)
- [ ] Review for accuracy (Zod 4 patterns, file upload validation)
- [ ] Fix bugs
- [ ] Add missing coverage
- [ ] Add reference docs
- [ ] Add test project
- **Notes:** Overlaps with react-secure-coder form section — ensure consistency, not duplication.

### 4. auth-patterns (797 lines)
- [ ] Review for accuracy (JWT, OAuth PKCE, MFA/TOTP, argon2/bcrypt APIs)
- [ ] Fix bugs
- [ ] Add missing coverage
- [ ] Add reference docs
- [ ] Add test project
- **Notes:** Largest skill. Covers many sensitive patterns — accuracy is critical.

### 5. secure-by-default (398 lines)
- [ ] Review for accuracy
- [ ] Fix bugs
- [ ] Add missing coverage
- [ ] Add reference docs
- [ ] Add test project (partial — meta-skill, mostly guidance)
- **Notes:** Meta-skill that sets baseline for all others. May not need a full test project but should have reference checklists.

### 6. vast-threat-modeling (434 lines)
- [ ] Review for accuracy
- [ ] Fix bugs
- [ ] Add missing coverage
- [ ] Add reference docs
- [ ] Add test project (unlikely — process/methodology, no code patterns)
- **Notes:** VAST methodology guidance. Review for completeness, add templates/checklists if missing.
