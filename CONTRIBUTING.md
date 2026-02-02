# Contributing to TamperTantrum Security Skills

Thanks for your interest in contributing! Here's how to help.

## Adding a New Skill

1. Create a folder in `skills/` with your skill name (kebab-case)
2. Add a `SKILL.md` file following the template below
3. Add any reference files in a `references/` subfolder
4. Submit a PR with a clear description

## Skill Structure

```
skills/your-skill-name/
├── SKILL.md           # Main skill file (required)
├── references/        # Supporting documentation
│   ├── patterns.md
│   └── examples.md
└── README.md          # Optional: detailed docs
```

## SKILL.md Template

```markdown
---
name: your-skill-name
description: One-line description of what the skill does
---

# Skill Name

## When to Use This Skill
- Bullet points of when this skill applies

## When NOT to Use This Skill  
- Bullet points of when to skip this skill

## Core Principles
Key security principles this skill enforces

## Patterns
Code patterns and examples

## Anti-Patterns
What to avoid (with examples)

## Recommended Libraries
Specific libraries for specific frameworks

## References
Links to supporting docs in references/ folder
```

## Code Standards

- All code examples should be TypeScript unless framework-specific
- Include both "bad" (❌) and "good" (✅) examples
- Reference specific library versions when relevant
- Test examples before submitting

## Review Process

1. PRs are reviewed by TamperTantrum Labs maintainers
2. Security accuracy is the top priority
3. We may ask for additional examples or clarification

## Questions?

Open an issue or reach out to us at [tampertantrum.com](https://tampertantrum.com).
