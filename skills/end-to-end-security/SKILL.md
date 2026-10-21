---
name: end-to-end-security
description: Layered security strategy applied from the front end through the API, services, storage and data, including identity proofing for onboarding flows that capture a selfie or ID photo. Use when designing or reviewing a feature that handles personal data, onboarding, verification documents or images, or when asked for a security strategy rather than a code checklist.
origin: ECC
---

# End-to-End Security Strategy

A security strategy you apply to every layer of a feature, from the browser to the
row in the database and the backup it ends up in. `security-review` covers
code-level checks; this skill covers the **design**: what each layer must
guarantee, what it must not trust, and how to verify a person is who they say
they are during onboarding.

## When to Use

- Designing a new feature that collects personal data, photos or documents
- Onboarding flows where a person proves identity (selfie, ID scan, clearance
  certificate such as a PCC, background-check consent)
- Someone asks "is an email confirmation enough?" or "how do we know it's really them?"
- Reviewing an existing app for gaps between layers (front end validates, API trusts)
- Writing a threat model, security section of a design doc, or a security PR checklist

## Core Principles

1. **Never trust the client.** Everything the browser sends (including "verified: true",
   file type, image metadata, timestamps) is attacker-controlled. Re-check on the server.
2. **Bind every step to one identity.** Each onboarding step must be tied to the same
   authenticated session that was created from a channel you already trust.
3. **Least privilege, everywhere.** Users, services, database roles, storage buckets
   and staff accounts get only what the task needs.
4. **Minimise data.** The safest PII is the PII you never stored. Keep raw images and
   documents only as long as the verification needs them.
5. **Assume breach.** Encrypt at rest, separate keys from data, log access, and make
   sure one compromised component can't read everything.
6. **Make it auditable.** Every verification decision has who, when, what evidence,
   and which reviewer, in an append-only log.

## Identity Proofing for Onboarding

### Is an email confirmation enough?

No, on its own. A confirmation email proves **control of an inbox**, not identity.
Anyone who knows or owns that address can click it, and if the person types their own
address during sign-up, the email proves nothing about who they are.

Email (or SMS) is still valuable as **the anchor of the session**, provided:

- The address comes from a trusted source (the organisation that invited them, an
  HR/admin record, an existing account), **not** typed in by the person being verified.
- The link is single-use, short-lived (15–30 min), and opens an authenticated session.
- The photo capture can only happen inside that session.

Then add proof that the person in front of the camera is real and matches a document.

### Assurance levels (pick per risk)

| Level | What it proves | Steps | Use for |
|-------|---------------|-------|---------|
| L1 | Controls a known contact channel | Invite link / OTP to email or phone on record | Low-risk accounts |
| L2 | A live human, matching a photo ID | L1 + live camera capture + liveness + face match to ID document | Staff, volunteers, anyone working with children |
| L3 | Verified by an accountable person | L2 + document authenticity check + human reviewer sign-off (or in-person check) | Clearance certificates, safeguarding roles, payouts |

Anything involving clearance certificates or safeguarding should be **L3**.

### Recommended L3 onboarding flow

```
Admin creates invite (email/phone from HR record)
  └─▶ Server issues single-use token (hashed in DB, 30 min TTL)
        └─▶ Person opens link ─▶ OTP to second channel (SMS) ─▶ authenticated session
              ├─▶ Consent screen (what is collected, why, retention period)
              ├─▶ ID document capture (live camera, front/back)
              ├─▶ Selfie capture with active liveness (turn head / random prompt)
              ├─▶ Server: liveness score, face match selfie ↔ ID, document checks
              ├─▶ Upload clearance certificate (PDF/image) ─▶ server validation
              └─▶ Status = PENDING_REVIEW ─▶ human reviewer approves/rejects
                    └─▶ Raw images deleted or archived per retention policy
```

Key rules for the flow:

- **Live capture only** for selfie and ID: use `getUserMedia`, not a file picker, so
  people can't upload a photo of someone else from the gallery. Treat this as friction,
  not proof: the server still runs liveness, because a client can be scripted.
- **Server-side liveness and face match.** Use a vendor (e.g. AWS Rekognition Face
  Liveness, Onfido, Veriff, Smile ID for African IDs, iProov) or an equivalent
  in-house service. Never accept a client-computed score.
- **Random challenge** per session (nonce shown on screen or a prompted action),
  so a replayed video from an earlier session fails.
- **Cross-check names.** Name and ID number on the ID document must match the
  invite record and the clearance certificate. Mismatch means manual review.
- **Verify the certificate at source** where possible (issuing authority's portal,
  reference number, QR code), not just by looking at the image.
- **Human-in-the-loop** for final approval at L3; the reviewer sees the evidence and
  records the decision, and cannot approve their own onboarding.
- **Re-verification** on sensitive changes: new email, new bank details, or
  certificate expiry triggers the flow again.

### Token and session handling

```typescript
import crypto from 'node:crypto'

// Issue: store only the hash, send the raw token in the link
export async function createInvite(db, personId: string) {
  const token = crypto.randomBytes(32).toString('base64url')
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex')
  await db.invites.insert({
    personId,
    tokenHash,
    expiresAt: new Date(Date.now() + 30 * 60 * 1000),
    usedAt: null,
  })
  return `https://app.example.com/onboard?t=${token}`
}

// Redeem: single use, constant-time lookup by hash, then start a session
export async function redeemInvite(db, token: string) {
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex')
  const invite = await db.invites.claim({ tokenHash, now: new Date() })
  // claim() = UPDATE ... SET used_at = now()
  //           WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
  //           RETURNING *  (atomic, so the link can't be used twice)
  if (!invite) throw new Error('Invalid or expired link')
  return startSession(invite.personId, { assurance: 'L1', needsOtp: true })
}
```

- Session cookie: `HttpOnly`, `Secure`, `SameSite=Lax` (or `Strict`), short idle timeout.
- Every capture/upload endpoint checks the session **and** that the session's
  `personId` owns the onboarding record being written.
- Rate-limit invite redemption, OTP verification and uploads per person and per IP.

## Layer-by-Layer Strategy

### 1. Front end (browser / mobile)

- [ ] Strict Content Security Policy; no inline scripts; `frame-ancestors 'none'`
- [ ] No secrets, API keys with write access, or vendor private keys in the bundle
- [ ] Camera permission requested only on the capture step, with clear purpose text
- [ ] Don't keep captured images in `localStorage`/IndexedDB; hold in memory, upload, discard
- [ ] Client validation for UX only; the server repeats every check
- [ ] Don't render user-supplied text as HTML; sanitise if you must
- [ ] Show the person what's collected and the retention period before capture (consent)

### 2. Transport and edge

- [ ] HTTPS only, HSTS with `includeSubDomains`; TLS 1.2+
- [ ] WAF / bot protection on onboarding and login endpoints
- [ ] Rate limits and lockouts on OTP, invite, password and upload endpoints
- [ ] Upload size limits enforced at the edge and in the app

### 3. API and application

- [ ] Authenticate every request; authorise every object (check ownership, not just login)
- [ ] Validate all input with a schema (e.g. zod); reject unknown fields
- [ ] File uploads: check magic bytes not extension, re-encode images server-side
      (strips EXIF/GPS and embedded payloads), scan PDFs, cap dimensions and size
- [ ] Use pre-signed, short-lived, single-object upload URLs; never public buckets
- [ ] State machine for onboarding (`INVITED → OTP_VERIFIED → CAPTURED → PENDING_REVIEW
      → APPROVED/REJECTED`); reject out-of-order transitions on the server
- [ ] Errors don't reveal whether an email, ID number or person exists
- [ ] Admin/reviewer actions require MFA and are role-checked server-side

```typescript
const allowed: Record<Status, Status[]> = {
  INVITED: ['OTP_VERIFIED'],
  OTP_VERIFIED: ['CAPTURED'],
  CAPTURED: ['PENDING_REVIEW'],
  PENDING_REVIEW: ['APPROVED', 'REJECTED'],
  APPROVED: [],
  REJECTED: ['INVITED'], // only via a new admin invite
}

export function transition(current: Status, next: Status) {
  if (!allowed[current].includes(next)) {
    throw new Error(`Illegal transition ${current} -> ${next}`)
  }
  return next
}
```

### 4. Services and third parties

- [ ] Verification vendor called from the server, with its own scoped credentials
- [ ] Verify webhook signatures and timestamps from vendors; idempotent handlers
- [ ] Data processing agreement in place; know which region the vendor stores data in
- [ ] Send the vendor only what it needs; prefer vendors that delete after processing

### 5. Data and storage

- [ ] Classify fields: **restricted** (ID numbers, biometrics, certificates, health,
      children's data), **confidential** (contact details), **internal**
- [ ] Restricted data encrypted at rest with a managed KMS key; consider
      field-level encryption for ID numbers
- [ ] Images/documents in a private bucket, separate from app assets, served only via
      short-lived signed URLs after an authorisation check
- [ ] Database roles: app role can't `DROP`/`ALTER`; reporting role can't read restricted columns
- [ ] Row-level security (or equivalent) so one tenant/person can't query another's records
- [ ] Retention: delete raw selfies/ID images after the decision (e.g. 30 days) and
      keep only the outcome, reviewer, timestamp and a reference; certificates per legal need
- [ ] Backups encrypted, access-controlled, and covered by the same retention rules
- [ ] Never log images, ID numbers, tokens or OTPs; mask in logs and error trackers

### 6. Operations and people

- [ ] Staff with access to restricted data use MFA and named accounts; access reviewed quarterly
- [ ] Append-only audit log for: invite created, link redeemed, captures, vendor result,
      reviewer decision, each view/download of restricted files
- [ ] Alerts on anomalies: many failed OTPs, repeated face-match failures, bulk downloads
- [ ] Incident plan includes notifying the regulator and affected people within the
      required window (POPIA in South Africa, GDPR in the EU/UK)
- [ ] Secrets in a secret manager; rotated; dependency and secret scanning in CI

## Threat Model Quick Pass

For each new feature, answer these before building:

| Threat | Example | Control |
|--------|---------|---------|
| Impersonation | Someone onboards with another person's email | Invite from trusted record + OTP + liveness + face match + reviewer |
| Replay / spoof | Photo of a photo, deepfake video | Active liveness, random challenge, vendor presentation-attack detection |
| Document forgery | Edited certificate PDF | Verify at issuer, cross-check names/IDs, reviewer |
| Broken access control | `GET /files/123` returns someone else's ID | Ownership check per object, signed URLs, RLS |
| Data leak | Bucket made public, logs contain ID numbers | Private buckets, policy guardrails, log masking |
| Insider misuse | Staff browsing selfies | Least privilege, view logging, access reviews |
| Over-retention | Biometrics kept forever | Retention job + tests that it runs |

## Best Practices

- Decide the assurance level first; it drives every other control.
- Put the security-critical decisions (status transitions, approvals, match results)
  only on the server and only in one place.
- Write tests for the abuse paths: reused invite, expired token, out-of-order step,
  accessing another person's file, oversized/invalid upload, reviewer self-approval.
- Run `security-review` on the code and the `security-reviewer` agent on the PR
  once the design here is settled.

## Related

- `security-review` skill: code-level checklist (secrets, injection, XSS, CSRF)
- `security-review/cloud-infrastructure-security.md`: cloud and IAM hardening
- `security-reviewer` agent: automated review of changes
