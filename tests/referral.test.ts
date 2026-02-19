/**
 * Referral System Tests
 * Run with: npx vitest run tests/referral.test.ts
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';

const BASE_URL = process.env.LICENSE_SERVER_URL || 'https://license.vibetravel.club';
const ADMIN_KEY = process.env.ADMIN_API_KEY || '0f6f182611dae66687629f5cfe67240cbf549316ab5a79f30280ca0ae00f4968';

describe('Referral System', () => {
  let testReferralCode: string;
  const testEmail = `test-${Date.now()}@example.com`;

  describe('POST /api/v1/referrals/register', () => {
    it('should register a new referrer', async () => {
      const res = await fetch(`${BASE_URL}/api/v1/referrals/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: testEmail,
          name: 'Test User',
          payout_email: testEmail,
          payout_method: 'paypal'
        })
      });

      expect(res.status).toBe(200);
      const data = await res.json();
      
      expect(data.success).toBe(true);
      expect(data.referral_code).toBeDefined();
      expect(data.referral_code).toMatch(/^[A-Z]{3}-[A-Z0-9]{6}$/);
      expect(data.referral_link).toContain(data.referral_code);
      expect(data.commission_rate).toBe('10%');

      testReferralCode = data.referral_code;
    });

    it('should return existing code for duplicate email', async () => {
      const res = await fetch(`${BASE_URL}/api/v1/referrals/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: testEmail,
          name: 'Test User 2'
        })
      });

      expect(res.status).toBe(200);
      const data = await res.json();
      
      expect(data.success).toBe(true);
      expect(data.referral_code).toBe(testReferralCode);
      expect(data.message).toBe('Already registered');
    });

    it('should reject registration without email', async () => {
      const res = await fetch(`${BASE_URL}/api/v1/referrals/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'No Email' })
      });

      expect(res.status).toBe(400);
      const data = await res.json();
      expect(data.error).toContain('Email');
    });
  });

  describe('GET /api/v1/referrals/stats', () => {
    it('should return stats by referral code', async () => {
      const res = await fetch(`${BASE_URL}/api/v1/referrals/stats?code=${testReferralCode}`);
      
      expect(res.status).toBe(200);
      const data = await res.json();
      
      expect(data.referral_code).toBe(testReferralCode);
      expect(data.referral_link).toBeDefined();
      expect(data.total_referrals).toBeDefined();
      expect(data.total_earned).toBeDefined();
      expect(data.unpaid_amount).toBeDefined();
      expect(Array.isArray(data.recent_referrals)).toBe(true);
    });

    it('should return stats by email', async () => {
      const res = await fetch(`${BASE_URL}/api/v1/referrals/stats?email=${encodeURIComponent(testEmail)}`);
      
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.referral_code).toBe(testReferralCode);
    });

    it('should return 404 for unknown code', async () => {
      const res = await fetch(`${BASE_URL}/api/v1/referrals/stats?code=XXX-NOTREAL`);
      expect(res.status).toBe(404);
    });

    it('should require code or email', async () => {
      const res = await fetch(`${BASE_URL}/api/v1/referrals/stats`);
      expect(res.status).toBe(400);
    });
  });

  describe('GET /admin/referrals/pending', () => {
    it('should reject without auth', async () => {
      const res = await fetch(`${BASE_URL}/admin/referrals/pending`);
      expect(res.status).toBe(401);
    });

    it('should return pending payouts with valid auth', async () => {
      const res = await fetch(`${BASE_URL}/admin/referrals/pending`, {
        headers: { 'Authorization': `Bearer ${ADMIN_KEY}` }
      });
      
      expect(res.status).toBe(200);
      const data = await res.json();
      
      expect(Array.isArray(data.pending_payouts)).toBe(true);
      expect(data.total_pending).toBeDefined();
    });
  });

  describe('POST /admin/referrals/mark-paid', () => {
    it('should reject without auth', async () => {
      const res = await fetch(`${BASE_URL}/admin/referrals/mark-paid`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ referral_code: testReferralCode })
      });
      expect(res.status).toBe(401);
    });

    it('should return 404 for unknown referrer', async () => {
      const res = await fetch(`${BASE_URL}/admin/referrals/mark-paid`, {
        method: 'POST',
        headers: { 
          'Authorization': `Bearer ${ADMIN_KEY}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ referral_code: 'XXX-NOTREAL' })
      });
      expect(res.status).toBe(404);
    });
  });
});

describe('License System', () => {
  const testLicenseKey = 'CX-TEST-' + Math.random().toString(36).substring(2, 6).toUpperCase();

  describe('POST /admin/create-license', () => {
    it('should reject without auth', async () => {
      const res = await fetch(`${BASE_URL}/admin/create-license`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ customer_email: 'test@example.com' })
      });
      expect(res.status).toBe(401);
    });

    it('should create license with valid auth', async () => {
      const res = await fetch(`${BASE_URL}/admin/create-license`, {
        method: 'POST',
        headers: { 
          'Authorization': `Bearer ${ADMIN_KEY}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          customer_email: `license-test-${Date.now()}@example.com`,
          tier: 'pro',
          systems_allowed: 5,
          days_valid: 30
        })
      });
      
      expect(res.status).toBe(200);
      const data = await res.json();
      
      expect(data.success).toBe(true);
      expect(data.license_key).toMatch(/^CX-PRO-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/);
      expect(data.tier).toBe('pro');
      expect(data.systems_allowed).toBe(5);
    });
  });

  describe('Health Check', () => {
    it('should return healthy status', async () => {
      const res = await fetch(`${BASE_URL}/health`);
      
      expect(res.status).toBe(200);
      const data = await res.json();
      
      expect(data.status).toBe('ok');
      expect(data.service).toBe('CX Linux License Server');
      expect(data.features).toContain('referrals');
    });
  });
});

describe('CORS', () => {
  it('should handle OPTIONS preflight', async () => {
    const res = await fetch(`${BASE_URL}/api/v1/referrals/register`, {
      method: 'OPTIONS'
    });
    
    expect(res.status).toBe(200);
    expect(res.headers.get('Access-Control-Allow-Origin')).toBe('*');
    expect(res.headers.get('Access-Control-Allow-Methods')).toContain('POST');
  });
});
