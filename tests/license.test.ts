/**
 * License Validation Tests
 * Run with: npx vitest run tests/license.test.ts
 */

import { describe, it, expect, beforeAll } from 'vitest';

const BASE_URL = process.env.LICENSE_SERVER_URL || 'https://license.vibetravel.club';
const ADMIN_KEY = process.env.ADMIN_API_KEY || '0f6f182611dae66687629f5cfe67240cbf549316ab5a79f30280ca0ae00f4968';

describe('License Validation Flow', () => {
  let testLicenseKey: string;
  const testEmail = `license-test-${Date.now()}@example.com`;
  const testHardwareId = `test-hw-${Date.now()}`;

  beforeAll(async () => {
    // Create a test license
    const res = await fetch(`${BASE_URL}/admin/create-license`, {
      method: 'POST',
      headers: { 
        'Authorization': `Bearer ${ADMIN_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        customer_email: testEmail,
        tier: 'core',
        systems_allowed: 2,
        days_valid: 30
      })
    });
    
    const data = await res.json();
    testLicenseKey = data.license_key;
    console.log(`Created test license: ${testLicenseKey}`);
  });

  describe('POST /api/v1/licenses/validate', () => {
    it('should validate a valid license', async () => {
      const res = await fetch(`${BASE_URL}/api/v1/licenses/validate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          license_key: testLicenseKey,
          hardware_id: testHardwareId
        })
      });

      expect(res.status).toBe(200);
      const data = await res.json();
      
      expect(data.valid).toBe(true);
      expect(data.license_key).toBe(testLicenseKey);
      expect(data.tier).toBe('core');
      expect(data.customer_email).toBe(testEmail);
      expect(data.days_remaining).toBeGreaterThan(0);
      expect(data.systems_allowed).toBe(2);
      expect(data.features).toContain('cx-ask');
    });

    it('should reject invalid license key', async () => {
      const res = await fetch(`${BASE_URL}/api/v1/licenses/validate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          license_key: 'CX-FAKE-1234-5678-ABCD-EFGH'
        })
      });

      expect(res.status).toBe(404);
      const data = await res.json();
      expect(data.valid).toBe(false);
    });

    it('should require license_key', async () => {
      const res = await fetch(`${BASE_URL}/api/v1/licenses/validate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });

      expect(res.status).toBe(400);
    });
  });

  describe('POST /api/v1/licenses/activate', () => {
    it('should activate a device', async () => {
      const res = await fetch(`${BASE_URL}/api/v1/licenses/activate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          license_key: testLicenseKey,
          hardware_id: testHardwareId,
          device_name: 'Test Device',
          platform: 'linux',
          hostname: 'test-host'
        })
      });

      expect(res.status).toBe(200);
      const data = await res.json();
      
      expect(data.valid).toBe(true);
      expect(data.systems_used).toBe(1);
      expect(data.systems_allowed).toBe(2);
    });

    it('should reactivate same device', async () => {
      const res = await fetch(`${BASE_URL}/api/v1/licenses/activate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          license_key: testLicenseKey,
          hardware_id: testHardwareId,
          device_name: 'Test Device Updated'
        })
      });

      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.message).toContain('reactivated');
    });

    it('should enforce device limit', async () => {
      // Activate device 2
      await fetch(`${BASE_URL}/api/v1/licenses/activate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          license_key: testLicenseKey,
          hardware_id: `${testHardwareId}-2`
        })
      });

      // Try to activate device 3 (should fail)
      const res = await fetch(`${BASE_URL}/api/v1/licenses/activate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          license_key: testLicenseKey,
          hardware_id: `${testHardwareId}-3`
        })
      });

      expect(res.status).toBe(403);
      const data = await res.json();
      expect(data.error).toContain('Device limit');
    });
  });

  describe('GET /api/v1/licenses/status', () => {
    it('should return license status', async () => {
      const res = await fetch(`${BASE_URL}/api/v1/licenses/status?license_key=${testLicenseKey}`);

      expect(res.status).toBe(200);
      const data = await res.json();
      
      expect(data.license_key).toBe(testLicenseKey);
      expect(data.tier).toBe('core');
      expect(data.systems_used).toBe(2);
      expect(data.systems_allowed).toBe(2);
      expect(Array.isArray(data.devices)).toBe(true);
      expect(data.devices.length).toBe(2);
    });

    it('should require license_key', async () => {
      const res = await fetch(`${BASE_URL}/api/v1/licenses/status`);
      expect(res.status).toBe(400);
    });
  });

  describe('POST /api/v1/licenses/deactivate', () => {
    it('should deactivate a device', async () => {
      const res = await fetch(`${BASE_URL}/api/v1/licenses/deactivate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          license_key: testLicenseKey,
          hardware_id: `${testHardwareId}-2`
        })
      });

      expect(res.status).toBe(200);
      const data = await res.json();
      
      expect(data.success).toBe(true);
      expect(data.systems_used).toBe(1);
    });

    it('should allow new device after deactivation', async () => {
      const res = await fetch(`${BASE_URL}/api/v1/licenses/activate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          license_key: testLicenseKey,
          hardware_id: `${testHardwareId}-new`
        })
      });

      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.valid).toBe(true);
    });
  });
});

describe('Tier Features', () => {
  const tiers = ['community', 'core', 'pro', 'enterprise'];
  
  it('should return different features per tier', async () => {
    for (const tier of ['core', 'pro', 'enterprise']) {
      const res = await fetch(`${BASE_URL}/admin/create-license`, {
        method: 'POST',
        headers: { 
          'Authorization': `Bearer ${ADMIN_KEY}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          customer_email: `tier-test-${tier}-${Date.now()}@example.com`,
          tier,
          days_valid: 1
        })
      });
      
      const license = await res.json();
      
      const validateRes = await fetch(`${BASE_URL}/api/v1/licenses/validate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ license_key: license.license_key })
      });
      
      const data = await validateRes.json();
      expect(data.tier).toBe(tier);
      expect(Array.isArray(data.features)).toBe(true);
      expect(data.features.length).toBeGreaterThan(0);
      
      // Enterprise should have more features
      if (tier === 'enterprise') {
        expect(data.features).toContain('sso');
        expect(data.features).toContain('audit-log');
      }
    }
  });
});
