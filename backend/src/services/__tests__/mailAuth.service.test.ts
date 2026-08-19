/**
 * mailAuth.service.test.ts
 *
 * Unit tests for the mailAuth service.
 * Tests both the webhook-header parsing path and the alignment/roll-up logic.
 * The `verifyRawMessage` path (mailauth lib) is not tested here because it
 * requires live DNS — integration-test that separately.
 */

import { describe, it, expect } from 'vitest';
import { mailAuthService } from '../mailAuth.service.js';

// ─── Webhook header parsing ───────────────────────────────────────────────────

describe('mailAuthService.verifyWebhookHeaders', () => {
  it('returns PASS for full SendGrid pass headers with aligned domains', () => {
    const headers = {
      'x-sg-spf': 'pass',
      'authentication-results': [
        'mx.sendgrid.net;',
        'dkim=pass header.d=example.com;',
        'dmarc=pass;',
        'smtp.mailfrom=example.com',
      ].join(' '),
      from:          'Alice <alice@example.com>',
      'return-path': '<alice@example.com>',
    };

    const result = mailAuthService.verifyWebhookHeaders(headers);

    expect(result.spf).toBe('pass');
    expect(result.dkim).toBe('pass');
    expect(result.dmarc).toBe('pass');
    expect(result.alignment).toBe('strict');
    expect(result.status).toBe('PASS');
  });

  it('returns PASS for Mailgun-specific headers with aligned domains', () => {
    const headers = {
      'x-mailgun-spf':              'pass',
      'x-mailgun-dkim-check-result': 'Pass',
      'authentication-results':     'mxa.mailgun.org; dmarc=pass; smtp.mailfrom=mg.example.com',
      from:          '"Bob" <bob@mg.example.com>',
      'return-path': '<bob@mg.example.com>',
    };

    const result = mailAuthService.verifyWebhookHeaders(headers);

    expect(result.spf).toBe('pass');
    expect(result.dkim).toBe('pass');
    expect(result.dmarc).toBe('pass');
    expect(result.status).toBe('PASS');
  });

  it('returns FAIL when DMARC explicitly fails', () => {
    const headers = {
      'authentication-results': 'mx.example.com; spf=fail; dkim=fail; dmarc=fail',
      from:          'spoofed@legit.com',
      'return-path': '<spammer@evil.com>',
    };

    const result = mailAuthService.verifyWebhookHeaders(headers);

    expect(result.dmarc).toBe('fail');
    expect(result.status).toBe('FAIL');
  });

  it('returns PARTIAL when SPF passes but DMARC is absent', () => {
    const headers = {
      'x-sg-spf':               'pass',
      'authentication-results': 'mx.example.com; dkim=pass header.d=example.com',
      // No dmarc= in auth-results
      from:          'user@example.com',
      'return-path': '<user@example.com>',
    };

    const result = mailAuthService.verifyWebhookHeaders(headers);

    expect(result.spf).toBe('pass');
    expect(result.dmarc).toBe('none');
    expect(result.status).toBe('PARTIAL');
  });

  it('returns PARTIAL when domains are misaligned (SPF passes but different org)', () => {
    const headers = {
      'x-sg-spf': 'pass',
      'authentication-results': 'mx.example.com; smtp.mailfrom=evil.com',
      from:          'ceo@legit.com',
      'return-path': '<bounce@evil.com>',
    };

    const result = mailAuthService.verifyWebhookHeaders(headers);

    expect(result.spf).toBe('pass');
    // fromDomain is legit.com, returnPathDomain is evil.com → no alignment
    expect(result.alignment).toBe('none');
    expect(result.status).toBe('PARTIAL');
  });

  it('returns NONE when no auth headers are present', () => {
    const headers = {
      from: 'unknown@mystery.com',
    };

    const result = mailAuthService.verifyWebhookHeaders(headers);

    expect(result.spf).toBe('unknown');
    expect(result.dkim).toBe('unknown');
    expect(result.status).toBe('NONE');
  });

  it('handles SPF softfail correctly — does not treat as pass', () => {
    const headers = {
      'authentication-results': 'mx.example.com; spf=softfail; dkim=none; dmarc=none',
      from:          'sender@example.com',
      'return-path': '<sender@example.com>',
    };

    const result = mailAuthService.verifyWebhookHeaders(headers);

    expect(result.spf).toBe('softfail');
    expect(result.status).toBe('NONE');
  });

  it('handles relaxed org-domain alignment (sub-domain case)', () => {
    const headers = {
      'x-sg-spf': 'pass',
      'authentication-results': [
        'mx.example.com;',
        'dkim=pass header.d=mail.example.com;',
        'dmarc=pass;',
        'smtp.mailfrom=mail.example.com',
      ].join(' '),
      from:          'alice@example.com',      // org domain: example.com
      'return-path': '<alice@mail.example.com>', // org domain: example.com → relaxed match
    };

    const result = mailAuthService.verifyWebhookHeaders(headers);

    expect(result.alignment).toBe('relaxed');
    expect(result.status).toBe('PASS');
  });
});

// ─── Serialization ────────────────────────────────────────────────────────────

describe('mailAuthService.serialize', () => {
  it('produces valid JSON with all expected fields', () => {
    const result = mailAuthService.verifyWebhookHeaders({
      'x-sg-spf': 'pass',
      'authentication-results': 'mx.example.com; dkim=pass header.d=example.com; dmarc=pass',
      from:          'user@example.com',
      'return-path': '<user@example.com>',
    });

    const json = mailAuthService.serialize(result);
    const parsed = JSON.parse(json) as Record<string, string>;

    expect(parsed).toHaveProperty('spf');
    expect(parsed).toHaveProperty('dkim');
    expect(parsed).toHaveProperty('dmarc');
    expect(parsed).toHaveProperty('alignment');
    expect(parsed).toHaveProperty('fromDomain');
    expect(parsed).toHaveProperty('returnPathDomain');
  });
});
