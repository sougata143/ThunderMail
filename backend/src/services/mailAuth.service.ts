/**
 * mailAuth.service.ts
 *
 * Sender authenticity verification for inbound external email.
 * Supports two paths:
 *   1. Webhook mode  – parse SPF/DKIM/DMARC from provider HTTP headers
 *   2. Raw SMTP mode – run `mailauth` against the raw RFC 5322 message buffer
 *
 * Neither path rejects unauthenticated mail; both produce an AuthResult
 * that is stored alongside the encrypted message and surfaced in the UI.
 */

import type { IncomingHttpHeaders } from 'node:http';

// ─── Public Types ─────────────────────────────────────────────────────────────

export type SpfResult   = 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'unknown';
export type DkimResult  = 'pass' | 'fail' | 'none' | 'unknown';
export type DmarcResult = 'pass' | 'fail' | 'none' | 'unknown';
export type AuthStatus  = 'PASS' | 'PARTIAL' | 'FAIL' | 'NONE';

/**
 * Named type alias for alignment result (SonarQube S4323: replace repeated union literals).
 * Previous: inline 'strict' | 'relaxed' | 'none' repeated at every usage site.
 */
export type AlignmentResult = 'strict' | 'relaxed' | 'none';

export interface AuthResult {
  /** Roll-up status stored in the DB and shown in the UI */
  status: AuthStatus;
  spf:    SpfResult;
  dkim:   DkimResult;
  dmarc:  DmarcResult;
  /** DMARC alignment: was Return-Path / DKIM d= aligned with From domain? */
  alignment:        AlignmentResult;
  fromDomain:       string;
  returnPathDomain: string;
}

// ─── Pre-compiled RegExp constants ────────────────────────────────────────────
//
// Using RegExp.exec() with module-level compiled patterns rather than
// String.prototype.match() for two reasons:
//   1. Avoids re-compiling the regex on every call (performance).
//   2. Makes linear-time guarantees explicit to static analysis tools (SonarQube S5852).
//
// Duplicate-character analysis for each character class:
//   WORD_VALUE_RE: [a-z0-9_-]  — no duplicates; all four ranges are disjoint.
//     With the /i flag removed, `a-z` is unambiguous lowercase-only.
//     The captured result is always `.toLowerCase()`'d immediately anyway.
//   DOMAIN_RE:     [@>\\s]     — three distinct metaclasses; no overlap.
//   SMTP_MFROM_RE: [\\s;]      — whitespace and semicolon; disjoint.
//   HEADER_D_RE:   [\\s;]      — same; disjoint.

/** Matches "spf=<word>" in an Authentication-Results header */
const SPF_RESULT_RE   = /\bspf=([a-z0-9_-]+)/;

/** Matches "dkim=<word>" in an Authentication-Results header */
const DKIM_RESULT_RE  = /\bdkim=([a-z0-9_-]+)/;

/** Matches "dmarc=<word>" in an Authentication-Results header */
const DMARC_RESULT_RE = /\bdmarc=([a-z0-9_-]+)/;

/** Matches "smtp.mailfrom=<value>" — stops at whitespace or semicolon */
const SMTP_MFROM_RE   = /smtp\.mailfrom=([^\s;]+)/;

/** Matches "header.d=<value>" — stops at whitespace or semicolon */
const HEADER_D_RE     = /header\.d=([^\s;]+)/;

/** Extracts domain from angle-addr or bare "user@domain" (>@\s are distinct metaclasses) */
const DOMAIN_OF_RE    = /@([^>@\s]+)/;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Extract the domain portion from an email address or RFC-5321 angle-addr. */
function domainOf(value: string): string {
  const m = DOMAIN_OF_RE.exec(value);
  return m ? m[1].toLowerCase() : '';
}

/**
 * Derive org-domain from a FQDN for relaxed alignment.
 * Strips all sub-labels except the last two (e.g. mail.example.com → example.com).
 */
function orgDomain(fqdn: string): string {
  const parts = fqdn.split('.');
  return parts.length > 2 ? parts.slice(-2).join('.') : fqdn;
}

function alignmentOf(fromDomain: string, otherDomain: string): AlignmentResult {
  if (!fromDomain || !otherDomain) return 'none';
  if (fromDomain === otherDomain) return 'strict';
  if (orgDomain(fromDomain) === orgDomain(otherDomain)) return 'relaxed';
  return 'none';
}

/**
 * Roll up individual check results into a single AuthStatus.
 *
 * PASS    – SPF AND DKIM both pass, AND DMARC passes, AND at least relaxed alignment
 * PARTIAL – some checks pass but DMARC is absent/none OR alignment is missing
 * FAIL    – DMARC explicitly failed
 * NONE    – no verifiable data at all
 */
function rollUp(
  spf: SpfResult,
  dkim: DkimResult,
  dmarc: DmarcResult,
  alignment: AlignmentResult,
): AuthStatus {
  if (dmarc === 'fail') return 'FAIL';

  const spfPass   = spf === 'pass';
  const dkimPass  = dkim === 'pass';
  const dmarcPass = dmarc === 'pass';
  const aligned   = alignment === 'strict' || alignment === 'relaxed';

  if (dmarcPass && (spfPass || dkimPass) && aligned) return 'PASS';
  if (spfPass || dkimPass) return 'PARTIAL';
  return 'NONE';
}

// ─── Path 1: Webhook Provider Header Parsing ─────────────────────────────────

/** Lowercase header map — accepts Node.js IncomingHttpHeaders or a plain Record */
type HeaderMap = IncomingHttpHeaders | Record<string, string | string[] | undefined>;

function headerStr(headers: HeaderMap, key: string): string {
  const val = headers[key.toLowerCase()];
  return Array.isArray(val) ? val[0] : (val ?? '');
}

/**
 * Parse Authentication-Results header (RFC 7601).
 * Returns a partial object with spf / dkim / dmarc string values.
 * Example header value:
 *   "mx.example.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass"
 *
 * All .match() calls replaced with RegExp.exec() against pre-compiled constants.
 * Character class duplicate analysis is documented at the constant declarations above.
 */
function parseAuthResultsHeader(raw: string): {
  spf?: string; dkim?: string; dmarc?: string; dkimDomain?: string; returnPath?: string;
} {
  const out: { spf?: string; dkim?: string; dmarc?: string; dkimDomain?: string; returnPath?: string } = {};

  // spf=<result> — match only word characters to avoid capturing trailing ;
  const spfM = SPF_RESULT_RE.exec(raw);
  if (spfM) out.spf = spfM[1].toLowerCase();

  // dkim=<result>
  const dkimM = DKIM_RESULT_RE.exec(raw);
  if (dkimM) out.dkim = dkimM[1].toLowerCase();

  // dmarc=<result>
  const dmarcM = DMARC_RESULT_RE.exec(raw);
  if (dmarcM) out.dmarc = dmarcM[1].toLowerCase();

  // smtp.mailfrom= for Return-Path domain
  const rpM = SMTP_MFROM_RE.exec(raw);
  if (rpM) out.returnPath = domainOf(rpM[1]) || rpM[1].toLowerCase();

  // header.d= for DKIM signing domain
  const hdM = HEADER_D_RE.exec(raw);
  if (hdM) out.dkimDomain = hdM[1].toLowerCase();

  return out;
}

/**
 * Extract FromDomain and ReturnPathDomain from standard email headers.
 */
function domainsFromHeaders(headers: HeaderMap): { fromDomain: string; returnPathDomain: string } {
  const fromHeader = headerStr(headers, 'from') || headerStr(headers, 'x-original-from');
  const rpHeader   = headerStr(headers, 'return-path') || headerStr(headers, 'x-original-return-path');
  return {
    fromDomain:       domainOf(fromHeader),
    returnPathDomain: domainOf(rpHeader) || domainOf(fromHeader), // fallback
  };
}

/**
 * Map a raw result string from any provider into our typed enum.
 */
function normalizeSpf(raw: string | undefined): SpfResult {
  const v = (raw ?? '').toLowerCase().trim();
  if (v === 'pass') return 'pass';
  if (v === 'fail') return 'fail';
  if (v === 'softfail' || v === 'soft_fail' || v === 'soft-fail') return 'softfail';
  if (v === 'neutral') return 'neutral';
  if (v === 'none') return 'none';
  return 'unknown';
}

function normalizeDkim(raw: string | undefined): DkimResult {
  const v = (raw ?? '').toLowerCase().trim();
  if (v === 'pass') return 'pass';
  if (v === 'fail') return 'fail';
  if (v === 'none') return 'none';
  return 'unknown';
}

function normalizeDmarc(raw: string | undefined): DmarcResult {
  const v = (raw ?? '').toLowerCase().trim();
  if (v === 'pass') return 'pass';
  if (v === 'fail') return 'fail';
  if (v === 'none' || v === '') return 'none';
  return 'unknown';
}

export const mailAuthService = {
  /**
   * Path 1 — Webhook Provider Header Parsing.
   *
   * Supports:
   *   • SendGrid Inbound Parse:   X-SG-Spf, Authentication-Results
   *   • Mailgun:                  X-Mailgun-Dkim-Check-Result, X-Mailgun-Spf, Authentication-Results
   *   • Postmark:                 Authentication-Results only
   *   • Generic fallback:        Authentication-Results (RFC 7601)
   *
   * Preference order for each check:
   *   1. Provider-specific header (most reliable — provider already ran it)
   *   2. Standard Authentication-Results header
   *   3. Unknown
   */
  verifyWebhookHeaders(headers: HeaderMap): AuthResult {
    // ── Extract provider-specific SPF ──────────────────────────────────────
    const sgSpf  = headerStr(headers, 'x-sg-spf');           // SendGrid
    const mgSpf  = headerStr(headers, 'x-mailgun-spf');      // Mailgun
    const pmSpf  = headerStr(headers, 'x-pm-spf');           // Postmark (unofficial)

    // ── Extract provider-specific DKIM ─────────────────────────────────────
    const mgDkim = headerStr(headers, 'x-mailgun-dkim-check-result'); // Mailgun
    // SendGrid and Postmark use Authentication-Results for DKIM

    // ── Parse Authentication-Results for anything not in a vendor header ───
    const authResults = headerStr(headers, 'authentication-results');
    const parsed = parseAuthResultsHeader(authResults);

    // ── Resolve final values (provider header wins over generic) ───────────
    const spfRaw   = sgSpf || mgSpf || pmSpf || parsed.spf;
    const dkimRaw  = mgDkim || parsed.dkim;
    const dmarcRaw = parsed.dmarc;

    const spf   = normalizeSpf(spfRaw);
    const dkim  = normalizeDkim(dkimRaw);
    const dmarc = normalizeDmarc(dmarcRaw);

    // ── Domain alignment ───────────────────────────────────────────────────
    const { fromDomain, returnPathDomain } = domainsFromHeaders(headers);

    // For DKIM alignment use header.d= from Authentication-Results if present
    const dkimDomain = parsed.dkimDomain || returnPathDomain;

    // SPF alignment: Return-Path domain vs From domain
    const spfAlign  = alignmentOf(fromDomain, returnPathDomain);
    // DKIM alignment: DKIM d= vs From domain
    const dkimAlign = alignmentOf(fromDomain, dkimDomain);

    // Combined alignment (best of the two that passed)
    let alignment: AlignmentResult = 'none';
    if (spf === 'pass' && spfAlign !== 'none') alignment = spfAlign;
    if (dkim === 'pass' && dkimAlign !== 'none') {
      // Upgrade alignment if DKIM gives stricter result
      if (dkimAlign === 'strict') alignment = 'strict';
      else if (alignment === 'none') alignment = 'relaxed';
    }

    const status = rollUp(spf, dkim, dmarc, alignment);

    return { status, spf, dkim, dmarc, alignment, fromDomain, returnPathDomain };
  },

  /**
   * Path 2 — Raw SMTP Message Verification via `mailauth`.
   *
   * Used when ThunderMail owns the SMTP listener (self-hosted MX).
   * The `mailauth` package verifies SPF, DKIM, DMARC, and ARC
   * directly against DNS. Requires the sender IP for SPF.
   *
   * @param rawEml  - Complete RFC 5322 message as a Buffer
   * @param clientIp - The SMTP client's IP address (for SPF)
   */
  async verifyRawMessage(rawEml: Buffer, clientIp: string): Promise<AuthResult> {
    // Dynamic import so the dependency is optional — only needed for INBOUND_PROVIDER=smtp
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const mailauthModule = (await import('mailauth')) as any;
    const authenticate = mailauthModule.authenticate || mailauthModule.default?.authenticate;

    // eslint-disable-next-line @typescript-eslint/no-unsafe-call
    const result = await authenticate(rawEml, {
      ip: clientIp,
      helo: clientIp,   // Fallback EHLO domain
      sender: '',        // Auto-extracted from Return-Path header
    });

    // Extract typed results from mailauth output safely
    const spfRaw  = (result?.spf && typeof result.spf === 'object' && result.spf.status?.result) as string | undefined;
    const dkimRaw = (result?.dkim && typeof result.dkim === 'object' && result.dkim.results?.[0]?.status?.result) as string | undefined;
    const dmarcRaw = (result?.dmarc && typeof result.dmarc === 'object' && result.dmarc.status?.result) as string | undefined;

    const spf   = normalizeSpf(spfRaw);
    const dkim  = normalizeDkim(dkimRaw);
    const dmarc = normalizeDmarc(dmarcRaw);

    // Domain alignment from mailauth DMARC result
    const fromHeader = (result?.dmarc && typeof result.dmarc === 'object' && result.dmarc.status?.header?.from) as string | undefined;
    const fromDomain = domainOf(fromHeader ?? '');

    const returnPathHeader = (result?.spf && typeof result.spf === 'object' && result.spf.status?.smtp?.mailfrom) as string | undefined;
    const returnPathDomain = domainOf(returnPathHeader ?? '');

    // Derive alignment from the DMARC result details if available
    const dmarcPolicy = (result?.dmarc && typeof result.dmarc === 'object' && result.dmarc.policy) as string | undefined ?? '';
    let alignment: AlignmentResult = 'none';
    if (dmarc === 'pass') {
      alignment = alignmentOf(fromDomain, returnPathDomain);
      if (alignment === 'none') alignment = 'relaxed'; // if DMARC passed, at least relaxed
    } else if (dmarcPolicy) {
      alignment = alignmentOf(fromDomain, returnPathDomain);
    }

    const status = rollUp(spf, dkim, dmarc, alignment);

    return { status, spf, dkim, dmarc, alignment, fromDomain, returnPathDomain };
  },

  /**
   * Serialize an AuthResult to a JSON string for storage in `authDetails`.
   */
  serialize(result: AuthResult): string {
    return JSON.stringify({
      spf:              result.spf,
      dkim:             result.dkim,
      dmarc:            result.dmarc,
      alignment:        result.alignment,
      fromDomain:       result.fromDomain,
      returnPathDomain: result.returnPathDomain,
    });
  },
};
