---
name: vast-threat-modeling
description: VAST threat modeling methodology for practical, scalable application security analysis. Visual, Agile, Simple - designed for DevSecOps.
---

# VAST Threat Modeling

Build security into your development process with Visual, Agile, and Simple Threat modeling.

## When to Use This Skill

- Starting a new application or feature
- Reviewing architecture decisions
- Before major releases
- After security incidents
- During compliance audits
- Adding third-party integrations
- CI/CD pipeline security gates

## When NOT to Use This Skill

- Quick bug fixes with no architectural changes
- UI-only changes with no data flow changes
- Copy/text changes

---

## What is VAST?

**VAST (Visual, Agile, and Simple Threat modeling)** is an enterprise-focused methodology designed for scalability and DevOps integration.

### VAST vs STRIDE

| Aspect | VAST | STRIDE |
|--------|------|--------|
| **Approach** | Visual, automated, continuous | Manual, mnemonic-based |
| **Scale** | Hundreds of applications | Single application/component |
| **Focus** | DevSecOps integration | Trust boundaries, architectural flaws |
| **Speed** | Minutes to hours | Hours to days |
| **Who** | Developers + Security | Security specialists |
| **When** | Every sprint/release | Major design phases |

### The Three Pillars

**1. Visual** - Diagrams over documents
- Process-flow diagrams for application threats
- Data-flow diagrams for operational threats
- Attack path visualization
- Easy to update, easy to share

**2. Agile** - Continuous, not one-time
- Iterative updates throughout SDLC
- Integrated into CI/CD pipelines
- Quick threat assessments per feature
- Living documentation

**3. Simple** - Everyone participates
- Developers can contribute (not just security)
- Clear, actionable outputs
- Minimal jargon
- Templates over blank pages

### Dual-View Structure

VAST uses two complementary perspectives:

| View | Created By | Uses | Analyzes |
|------|-----------|------|----------|
| **Application Threat Model** | Developers & Architects | Process-flow diagrams | Architectural flaws, design weaknesses |
| **Operational Threat Model** | Security & Ops teams | Data-flow diagrams | Attacker perspective, runtime threats |

---

## VAST Process

### Step 1: Identify and Define Assets

Determine what needs protection before identifying threats.

**Asset Categories:**
- **Data**: PII, credentials, API keys, business data
- **Systems**: Databases, APIs, services, infrastructure
- **Functions**: Authentication, payment processing, admin features

**Example Asset Inventory:**
```markdown
| Asset | Type | Sensitivity | Owner |
|-------|------|-------------|-------|
| User passwords | Data | Critical | Auth Service |
| Payment tokens | Data | Critical | Payment Service |
| User profiles | Data | High | User Service |
| Admin dashboard | Function | Critical | Admin Service |
| Public API | System | Medium | API Gateway |
```

### Step 2: Apply Threat Intelligence

Integrate current threat data relevant to your stack and domain.

**Sources to consider:**
- OWASP Top 10 (web apps)
- OWASP API Security Top 10 (APIs)
- CWE Top 25 (code vulnerabilities)
- Industry-specific threats (healthcare, fintech, etc.)
- Recent CVEs in your dependencies

**Questions to ask:**
- What attacks are common for this technology stack?
- What have similar applications been hit with?
- What's in the news for our industry?

### Step 3: Create System Diagrams

Visual representation is core to VAST. Create diagrams that show:

**Data Flow Diagram Elements:**
```
┌─────────────┐     HTTPS      ┌─────────────┐
│   Browser   │ ───────────────▶│   API GW    │
│  (External) │                 │  (DMZ)      │
└─────────────┘                 └──────┬──────┘
                                       │
                    ═══════════════════╪═══════════ Trust Boundary
                                       │
                                       ▼
                               ┌───────────────┐
                               │  Auth Service │
                               │  (Internal)   │
                               └───────┬───────┘
                                       │
                                       ▼
                               ┌───────────────┐
                               │   Database    │
                               │  (Internal)   │
                               └───────────────┘
```

**Key elements to include:**
- External entities (users, third parties)
- Processes (services, functions)
- Data stores (databases, caches, files)
- Data flows (arrows with protocols)
- Trust boundaries (dashed lines)

### Step 4: Identify Mitigation Capabilities

Map existing security controls before identifying gaps.

**Control Categories:**
```markdown
| Category | Control | Implemented | Verified |
|----------|---------|-------------|----------|
| Authentication | MFA | ✅ | ✅ |
| Authentication | Rate limiting | ✅ | ❌ |
| Authorization | RBAC | ✅ | ✅ |
| Authorization | Row-level security | ❌ | - |
| Data Protection | Encryption at rest | ✅ | ✅ |
| Data Protection | Encryption in transit | ✅ | ✅ |
| Logging | Auth events | ✅ | ❌ |
| Logging | Data access | ❌ | - |
```

### Step 5: Perform Threat Mapping/Assessment

Map threats to assets and assess risk.

**Threat Mapping Template:**
```markdown
| Threat | Asset | Likelihood | Impact | Risk | Mitigation | Status |
|--------|-------|------------|--------|------|------------|--------|
| SQL Injection | Database | Medium | Critical | High | Parameterized queries | ✅ Done |
| Credential stuffing | Auth | High | High | Critical | Rate limiting + MFA | 🔄 In Progress |
| IDOR | User data | High | High | Critical | Ownership checks | ❌ Todo |
| XSS | Frontend | Medium | Medium | Medium | CSP + sanitization | ✅ Done |
```

**Risk Calculation:**
```
Risk = Likelihood × Impact

Likelihood: Low (1), Medium (2), High (3)
Impact: Low (1), Medium (2), High (3), Critical (4)

Risk Score:
- 1-2: Low (accept or monitor)
- 3-4: Medium (mitigate when possible)
- 6-8: High (mitigate soon)
- 9-12: Critical (mitigate immediately)
```

---

## Templates

### Application Threat Model Template

```markdown
# Application Threat Model: [Name]

## Overview
- **Date**: YYYY-MM-DD
- **Version**: 1.0
- **Author**: [Name]
- **Reviewers**: [Names]
- **Status**: Draft | Review | Approved

## System Description

[2-3 sentences describing what this system does and why it exists]

## Architecture Diagram

[Insert or link to diagram]

## Assets

| Asset | Sensitivity | Description |
|-------|-------------|-------------|
| | | |

## Trust Boundaries

| Boundary | From | To | Controls |
|----------|------|-----|----------|
| | | | |

## Threats Identified

| ID | Threat | Asset | Risk | Mitigation | Owner | Status |
|----|--------|-------|------|------------|-------|--------|
| T1 | | | | | | |

## Action Items

- [ ] [Action] - @owner - Due: YYYY-MM-DD
- [ ] [Action] - @owner - Due: YYYY-MM-DD

## Sign-off

- [ ] Development reviewed - @name - Date
- [ ] Security reviewed - @name - Date
- [ ] Mitigations verified - @name - Date
```

### Operational Threat Model Template

```markdown
# Operational Threat Model: [System/Environment]

## Overview
- **Date**: YYYY-MM-DD
- **Scope**: [Production | Staging | All]
- **Author**: [Name]

## Infrastructure Diagram

[Data flow diagram from attacker perspective]

## Attack Surface

| Entry Point | Protocol | Authentication | Exposure |
|-------------|----------|----------------|----------|
| Public API | HTTPS | JWT | Internet |
| Admin Panel | HTTPS | MFA | VPN Only |
| Database | TCP/5432 | mTLS | Internal |

## Threat Scenarios

### Scenario 1: [Name]
- **Attacker**: [External | Internal | Privileged]
- **Goal**: [What they want]
- **Path**: [How they'd get it]
- **Mitigations**: [What stops them]
- **Gaps**: [What's missing]

## Monitoring & Detection

| Threat | Detection Method | Alert | Response |
|--------|------------------|-------|----------|
| Brute force | Failed login rate | PagerDuty | Auto-block IP |
| Data exfil | Unusual query volume | Slack | Investigate |

## Incident Response

- Runbook: [Link]
- On-call: [Team/rotation]
- Escalation: [Path]
```

### Quick Threat Assessment (15 min)

For single features or API endpoints:

```markdown
## Quick Threat Assessment: [Feature Name]

**Date**: YYYY-MM-DD | **Author**: [Name]

### What does it do?
[1-2 sentences]

### What data does it touch?
- [ ] PII
- [ ] Credentials
- [ ] Financial
- [ ] Other sensitive: ___

### Who can access it?
- [ ] Unauthenticated
- [ ] Any authenticated user
- [ ] Specific roles: ___
- [ ] Internal only

### Quick threat check:
- [ ] Input validation on all parameters?
- [ ] Authorization check (not just authentication)?
- [ ] Rate limiting needed?
- [ ] Audit logging needed?
- [ ] Data encrypted in transit and at rest?

### Threats identified:
1. [Threat] → [Mitigation]
2. [Threat] → [Mitigation]

### Sign-off: @reviewer
```

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Threat Model Check

on:
  pull_request:
    paths:
      - 'src/**'
      - 'api/**'

jobs:
  threat-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Check for threat model
        run: |
          # Require threat model for new services
          if git diff --name-only origin/main | grep -q "src/services/"; then
            if ! test -f "docs/threat-models/$(basename $service).md"; then
              echo "❌ New service requires threat model"
              exit 1
            fi
          fi
          
      - name: Validate threat model format
        run: |
          for tm in docs/threat-models/*.md; do
            # Check required sections exist
            grep -q "## Assets" "$tm" || exit 1
            grep -q "## Threats Identified" "$tm" || exit 1
            grep -q "## Sign-off" "$tm" || exit 1
          done
```

### PR Template Addition

```markdown
## Security Checklist

- [ ] No new sensitive data handling (skip threat assessment)
- [ ] Quick threat assessment completed (link: ___)
- [ ] Full threat model updated (link: ___)
- [ ] Security review requested (@security-team)
```

---

## Lightweight vs Full Models

| Scope | Time | Trigger | Output |
|-------|------|---------|--------|
| **Quick** (15 min) | New endpoint, minor feature | Quick Assessment template |
| **Standard** (1 hr) | New feature, integration | Application Threat Model |
| **Full** (half day) | New application, major refactor | App + Operational models |

**Rule of thumb:** If it touches auth, payments, or PII → at least Standard. New service or infrastructure → Full.

---

## Common Threats by Component

### APIs
- Broken authentication
- Broken authorization (IDOR)
- Injection (SQL, NoSQL, Command)
- Mass assignment
- Rate limiting bypass

### Frontend
- XSS (stored, reflected, DOM)
- CSRF
- Open redirects
- Sensitive data in localStorage
- Clickjacking

### Databases
- SQL injection
- Insufficient access controls
- Unencrypted sensitive data
- Excessive privileges
- Missing audit logs

### Infrastructure
- Misconfigured cloud resources
- Exposed management interfaces
- Missing network segmentation
- Inadequate logging
- Secrets in code/config

---

## References

- [references/vast-checklist.md](references/vast-checklist.md) - Quick reference checklist
- [references/threat-catalog.md](references/threat-catalog.md) - Common threats and mitigations
- [references/templates.md](references/templates.md) - Copy-paste templates

---

*This skill is maintained by [TamperTantrum Labs](https://tampertantrum.com) — making application security accessible, human, and empowering.*
