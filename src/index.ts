// CX Linux License Server with Referral System
// Version 1.2.0

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization"
};

interface Env {
  DB: D1Database;
  STRIPE_WEBHOOK_SECRET: string;
  ADMIN_API_KEY: string;
}

// ============================================
// REFERRAL CONSTANTS
// ============================================
const PRICE_AMOUNTS: Record<string, number> = {
  'price_1SqYQjJ4X1wkC4EsLDB6ZbOk': 20,    // Core+ monthly
  'price_1SqYQjJ4X1wkC4EslIkZEJFZ': 200,   // Core+ annual
  'price_1SqYQkJ4X1wkC4Es8OMt79pZ': 99,    // Pro+ monthly
  'price_1SqYQkJ4X1wkC4EsWYwUgceu': 990,   // Pro+ annual
  'price_1SqYQkJ4X1wkC4EsCFVBHYnT': 299,   // Enterprise+ monthly
  'price_1SqYQlJ4X1wkC4EsJcPW7Of2': 2990,  // Enterprise+ annual
};

const COMMISSION_RATE = 0.10; // 10%

// ============================================
// HELPERS
// ============================================
function jsonResponse(data: any, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders
    }
  });
}

function errorResponse(message: string, status = 400) {
  return jsonResponse({ error: message, valid: false }, status);
}

function generateRandomString(length: number): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let result = "";
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

function generateReferralCode(name?: string): string {
  const prefix = name ? name.substring(0, 3).toUpperCase().replace(/[^A-Z]/g, 'X') : 'REF';
  const random = generateRandomString(6);
  return `${prefix}-${random}`;
}

async function logValidation(db: D1Database, licenseKey: string, hardwareId: string | null, action: string, success: boolean, errorMessage: string | null, request: Request) {
  try {
    await db.prepare(`
      INSERT INTO validation_log (license_key, hardware_id, action, success, error_message, ip_address, user_agent)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(
      licenseKey,
      hardwareId,
      action,
      success ? 1 : 0,
      errorMessage,
      request.headers.get("CF-Connecting-IP") || "unknown",
      request.headers.get("User-Agent") || "unknown"
    ).run();
  } catch (e) {
    console.error("Failed to log validation:", e);
  }
}

async function getActiveDeviceCount(db: D1Database, licenseId: number): Promise<number> {
  const result = await db.prepare(
    "SELECT COUNT(*) as count FROM activations WHERE license_id = ? AND active = 1"
  ).bind(licenseId).first<{ count: number }>();
  return result?.count || 0;
}

function getTierFeatures(tier: string): string[] {
  const features: Record<string, string[]> = {
    community: ["cx-ask", "cx-status", "local-llm"],
    core: ["cx-ask", "cx-status", "cx-demo", "cloud-llm", "email-support"],
    pro: ["cx-ask", "cx-status", "cx-demo", "cloud-llm", "priority-support", "api-access"],
    enterprise: ["cx-ask", "cx-status", "cx-demo", "cloud-llm", "sso", "audit-log", "compliance", "dedicated-support"],
    managed: ["cx-ask", "cx-status", "cx-demo", "cloud-llm", "sso", "audit-log", "compliance", "dedicated-support", "custom-features", "sla"]
  };
  return features[tier] || features.community;
}

// ============================================
// LICENSE HANDLERS
// ============================================
async function handleValidate(request: Request, env: Env) {
  const body = await request.json() as any;
  const { license_key, hardware_id } = body;

  if (!license_key) {
    return errorResponse("License key is required");
  }

  const license = await env.DB.prepare(
    "SELECT * FROM licenses WHERE license_key = ? AND active = 1"
  ).bind(license_key).first<any>();

  if (!license) {
    await logValidation(env.DB, license_key, hardware_id || null, "validate", false, "License not found", request);
    return errorResponse("Invalid license key", 404);
  }

  const now = new Date();
  const expiresAt = new Date(license.expires_at);

  if (now > expiresAt) {
    await logValidation(env.DB, license_key, hardware_id || null, "validate", false, "License expired", request);
    return errorResponse("License has expired", 403);
  }

  const systemsUsed = await getActiveDeviceCount(env.DB, license.id);

  let deviceActivated = false;
  if (hardware_id) {
    const activation = await env.DB.prepare(
      "SELECT * FROM activations WHERE license_id = ? AND hardware_id = ? AND active = 1"
    ).bind(license.id, hardware_id).first();
    deviceActivated = !!activation;

    if (activation) {
      await env.DB.prepare(
        "UPDATE activations SET last_seen = CURRENT_TIMESTAMP WHERE id = ?"
      ).bind((activation as any).id).run();
    }
  }

  const daysRemaining = Math.ceil((expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
  await logValidation(env.DB, license_key, hardware_id || null, "validate", true, null, request);

  return jsonResponse({
    valid: true,
    license_key: license.license_key,
    tier: license.tier,
    customer_id: license.customer_id,
    customer_email: license.customer_email,
    organization: license.organization,
    issued_at: license.issued_at,
    expires_at: license.expires_at,
    days_remaining: daysRemaining,
    systems_used: systemsUsed,
    systems_allowed: license.systems_allowed,
    device_activated: deviceActivated,
    features: getTierFeatures(license.tier)
  });
}

async function handleActivate(request: Request, env: Env) {
  const body = await request.json() as any;
  const { license_key, hardware_id, device_name, platform, hostname } = body;

  if (!license_key || !hardware_id) {
    return errorResponse("License key and hardware_id are required");
  }

  const license = await env.DB.prepare(
    "SELECT * FROM licenses WHERE license_key = ? AND active = 1"
  ).bind(license_key).first<any>();

  if (!license) {
    await logValidation(env.DB, license_key, hardware_id, "activate", false, "License not found", request);
    return errorResponse("Invalid license key", 404);
  }

  const now = new Date();
  const expiresAt = new Date(license.expires_at);
  if (now > expiresAt) {
    await logValidation(env.DB, license_key, hardware_id, "activate", false, "License expired", request);
    return errorResponse("License has expired", 403);
  }

  const existingActivation = await env.DB.prepare(
    "SELECT * FROM activations WHERE license_id = ? AND hardware_id = ?"
  ).bind(license.id, hardware_id).first<any>();

  if (existingActivation) {
    await env.DB.prepare(
      "UPDATE activations SET active = 1, last_seen = CURRENT_TIMESTAMP, device_name = ?, platform = ?, hostname = ? WHERE id = ?"
    ).bind(device_name || existingActivation.device_name, platform || existingActivation.platform, hostname || existingActivation.hostname, existingActivation.id).run();

    await logValidation(env.DB, license_key, hardware_id, "activate", true, "Reactivated existing device", request);
    const systemsUsed = await getActiveDeviceCount(env.DB, license.id);
    return jsonResponse({
      valid: true,
      message: "Device reactivated",
      systems_used: systemsUsed,
      systems_allowed: license.systems_allowed
    });
  }

  const systemsUsed = await getActiveDeviceCount(env.DB, license.id);
  if (systemsUsed >= license.systems_allowed) {
    await logValidation(env.DB, license_key, hardware_id, "activate", false, `Device limit reached (${systemsUsed}/${license.systems_allowed})`, request);
    return errorResponse(`Device limit reached. You have ${systemsUsed}/${license.systems_allowed} devices activated. Please deactivate a device first.`, 403);
  }

  await env.DB.prepare(`
    INSERT INTO activations (license_id, hardware_id, device_name, platform, hostname)
    VALUES (?, ?, ?, ?, ?)
  `).bind(license.id, hardware_id, device_name || null, platform || null, hostname || null).run();

  await logValidation(env.DB, license_key, hardware_id, "activate", true, null, request);

  return jsonResponse({
    valid: true,
    message: "Device activated successfully",
    systems_used: systemsUsed + 1,
    systems_allowed: license.systems_allowed
  });
}

async function handleDeactivate(request: Request, env: Env) {
  const body = await request.json() as any;
  const { license_key, hardware_id } = body;

  if (!license_key || !hardware_id) {
    return errorResponse("License key and hardware_id are required");
  }

  const license = await env.DB.prepare(
    "SELECT * FROM licenses WHERE license_key = ?"
  ).bind(license_key).first<any>();

  if (!license) {
    return errorResponse("Invalid license key", 404);
  }

  const result = await env.DB.prepare(
    "UPDATE activations SET active = 0 WHERE license_id = ? AND hardware_id = ?"
  ).bind(license.id, hardware_id).run();

  if (result.meta.changes === 0) {
    return errorResponse("Device not found", 404);
  }

  await logValidation(env.DB, license_key, hardware_id, "deactivate", true, null, request);
  const systemsUsed = await getActiveDeviceCount(env.DB, license.id);

  return jsonResponse({
    success: true,
    message: "Device deactivated",
    systems_used: systemsUsed,
    systems_allowed: license.systems_allowed
  });
}

async function handleStatus(request: Request, env: Env) {
  const url = new URL(request.url);
  const licenseKey = url.searchParams.get("license_key");

  if (!licenseKey) {
    return errorResponse("License key is required");
  }

  const license = await env.DB.prepare(
    "SELECT * FROM licenses WHERE license_key = ?"
  ).bind(licenseKey).first<any>();

  if (!license) {
    return errorResponse("Invalid license key", 404);
  }

  const activations = await env.DB.prepare(
    "SELECT hardware_id, device_name, platform, hostname, first_seen, last_seen, active FROM activations WHERE license_id = ?"
  ).bind(license.id).all();

  const systemsUsed = activations.results?.filter((a: any) => a.active).length || 0;

  return jsonResponse({
    license_key: license.license_key,
    tier: license.tier,
    customer_email: license.customer_email,
    organization: license.organization,
    expires_at: license.expires_at,
    active: license.active === 1,
    systems_used: systemsUsed,
    systems_allowed: license.systems_allowed,
    devices: activations.results || []
  });
}

// ============================================
// REFERRAL HANDLERS
// ============================================
async function handleReferralRegister(request: Request, env: Env) {
  const body = await request.json() as any;
  const { email, name, payout_email, payout_method } = body;

  if (!email) {
    return errorResponse('Email is required');
  }

  // Check if already registered
  const existing = await env.DB.prepare(
    'SELECT * FROM referrers WHERE email = ?'
  ).bind(email).first<any>();

  if (existing) {
    return jsonResponse({
      success: true,
      message: 'Already registered',
      referral_code: existing.referral_code,
      referral_link: `https://cxlinux.com/pricing?ref=${existing.referral_code}`
    });
  }

  const referralCode = generateReferralCode(name);

  await env.DB.prepare(`
    INSERT INTO referrers (referral_code, email, name, payout_email, payout_method)
    VALUES (?, ?, ?, ?, ?)
  `).bind(referralCode, email, name || null, payout_email || email, payout_method || 'paypal').run();

  return jsonResponse({
    success: true,
    referral_code: referralCode,
    referral_link: `https://cxlinux.com/pricing?ref=${referralCode}`,
    commission_rate: '10%',
    message: 'Welcome to the CX Linux referral program!'
  });
}

async function handleReferralStats(request: Request, env: Env) {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const email = url.searchParams.get('email');

  if (!code && !email) {
    return errorResponse('code or email is required');
  }

  let referrer;
  if (code) {
    referrer = await env.DB.prepare(
      'SELECT * FROM referrers WHERE referral_code = ?'
    ).bind(code).first<any>();
  } else {
    referrer = await env.DB.prepare(
      'SELECT * FROM referrers WHERE email = ?'
    ).bind(email).first<any>();
  }

  if (!referrer) {
    return errorResponse('Referrer not found', 404);
  }

  const referrals = await env.DB.prepare(`
    SELECT r.*, l.customer_email, l.tier, l.created_at as license_created
    FROM referrals r
    JOIN licenses l ON r.license_id = l.id
    WHERE r.referrer_id = ?
    ORDER BY r.created_at DESC
  `).bind(referrer.id).all();

  const results = referrals.results || [];
  const totalReferrals = results.length;
  const totalEarned = results.reduce((sum: number, r: any) => sum + (r.commission || 0), 0);
  const unpaidAmount = results.filter((r: any) => !r.paid).reduce((sum: number, r: any) => sum + (r.commission || 0), 0);

  return jsonResponse({
    referral_code: referrer.referral_code,
    referral_link: `https://cxlinux.com/pricing?ref=${referrer.referral_code}`,
    total_referrals: totalReferrals,
    total_earned: totalEarned.toFixed(2),
    unpaid_amount: unpaidAmount.toFixed(2),
    paid_amount: (totalEarned - unpaidAmount).toFixed(2),
    payout_email: referrer.payout_email,
    payout_method: referrer.payout_method || 'paypal',
    recent_referrals: results.slice(0, 10).map((r: any) => ({
      date: r.created_at,
      tier: r.tier || 'unknown',
      commission: (r.commission || 0).toFixed(2),
      paid: r.paid === 1
    }))
  });
}

async function processReferral(env: Env, licenseId: number, priceId: string, referralCode: string): Promise<any> {
  if (!referralCode) return null;

  const referrer = await env.DB.prepare(
    'SELECT * FROM referrers WHERE referral_code = ? AND active = 1'
  ).bind(referralCode).first<any>();

  if (!referrer) {
    console.log(`Referral code ${referralCode} not found or inactive`);
    return null;
  }

  const amount = PRICE_AMOUNTS[priceId] || 0;
  if (amount === 0) {
    console.log(`Unknown price ID for referral: ${priceId}`);
    return null;
  }

  const commission = amount * COMMISSION_RATE;

  await env.DB.prepare(`
    INSERT INTO referrals (referrer_id, license_id, amount_paid, commission)
    VALUES (?, ?, ?, ?)
  `).bind(referrer.id, licenseId, amount, commission).run();

  await env.DB.prepare(`
    UPDATE referrers SET total_earned = total_earned + ? WHERE id = ?
  `).bind(commission, referrer.id).run();

  console.log(`Referral recorded: ${referralCode} earned $${commission.toFixed(2)} from $${amount} sale`);

  return { referrer_id: referrer.id, commission };
}

async function handlePendingPayouts(request: Request, env: Env) {
  const authHeader = request.headers.get('Authorization');
  const apiKey = authHeader?.replace('Bearer ', '');

  if (!env.ADMIN_API_KEY || apiKey !== env.ADMIN_API_KEY) {
    return errorResponse('Unauthorized', 401);
  }

  const pending = await env.DB.prepare(`
    SELECT 
      rr.referral_code,
      rr.email,
      rr.payout_email,
      rr.payout_method,
      SUM(r.commission) as pending_amount,
      COUNT(*) as pending_count
    FROM referrals r
    JOIN referrers rr ON r.referrer_id = rr.id
    WHERE r.paid = 0
    GROUP BY rr.id
    HAVING pending_amount > 0
    ORDER BY pending_amount DESC
  `).all();

  const results = pending.results || [];
  const totalPending = results.reduce((sum: number, p: any) => sum + (p.pending_amount || 0), 0);

  return jsonResponse({
    pending_payouts: results,
    total_pending: totalPending.toFixed(2)
  });
}

async function handleMarkPaid(request: Request, env: Env) {
  const authHeader = request.headers.get('Authorization');
  const apiKey = authHeader?.replace('Bearer ', '');

  if (!env.ADMIN_API_KEY || apiKey !== env.ADMIN_API_KEY) {
    return errorResponse('Unauthorized', 401);
  }

  const body = await request.json() as any;
  const { referral_code, amount } = body;

  if (!referral_code) {
    return errorResponse('referral_code is required');
  }

  const referrer = await env.DB.prepare(
    'SELECT id FROM referrers WHERE referral_code = ?'
  ).bind(referral_code).first<any>();

  if (!referrer) {
    return errorResponse('Referrer not found', 404);
  }

  const unpaid = await env.DB.prepare(`
    SELECT SUM(commission) as amount FROM referrals 
    WHERE referrer_id = ? AND paid = 0
  `).bind(referrer.id).first<any>();

  await env.DB.prepare(`
    UPDATE referrals SET paid = 1, paid_at = CURRENT_TIMESTAMP
    WHERE referrer_id = ? AND paid = 0
  `).bind(referrer.id).run();

  await env.DB.prepare(`
    UPDATE referrers SET total_paid = total_paid + ? WHERE id = ?
  `).bind(unpaid?.amount || 0, referrer.id).run();

  return jsonResponse({
    success: true,
    referral_code,
    amount_paid: (unpaid?.amount || 0).toFixed(2)
  });
}

// ============================================
// STRIPE WEBHOOK
// ============================================
async function verifyStripeSignature(payload: string, signature: string, secret: string, tolerance = 300): Promise<boolean> {
  try {
    const parts = signature.split(",");
    const timestamp = parts.find(p => p.startsWith("t="))?.slice(2);
    const sig = parts.find(p => p.startsWith("v1="))?.slice(3);

    if (!timestamp || !sig) return false;

    const now = Math.floor(Date.now() / 1000);
    const ts = parseInt(timestamp, 10);
    if (Math.abs(now - ts) > tolerance) return false;

    const signedPayload = `${timestamp}.${payload}`;
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const signatureBytes = await crypto.subtle.sign("HMAC", key, encoder.encode(signedPayload));
    const expectedSig = Array.from(new Uint8Array(signatureBytes))
      .map(b => b.toString(16).padStart(2, "0")).join("");

    if (expectedSig.length !== sig.length) return false;
    let result = 0;
    for (let i = 0; i < expectedSig.length; i++) {
      result |= expectedSig.charCodeAt(i) ^ sig.charCodeAt(i);
    }
    return result === 0;
  } catch (e) {
    console.error("Signature verification error:", e);
    return false;
  }
}

async function handleStripeWebhook(request: Request, env: Env) {
  const body = await request.text();
  const signature = request.headers.get("stripe-signature");

  if (!signature) {
    return errorResponse("Missing signature", 401);
  }

  const isValid = await verifyStripeSignature(body, signature, env.STRIPE_WEBHOOK_SECRET);
  if (!isValid) {
    console.log("Invalid Stripe signature");
    return errorResponse("Invalid signature", 401);
  }

  let event;
  try {
    event = JSON.parse(body);
  } catch (e) {
    return errorResponse("Invalid JSON", 400);
  }

  console.log("Stripe webhook verified:", event.type);
  const eventType = event.type;
  const data = event.data?.object;

  try {
    switch (eventType) {
      case "customer.subscription.created":
      case "checkout.session.completed": {
        const customerId = data.customer;
        const customerEmail = data.customer_email || data.receipt_email || "";
        const priceId = data.items?.data?.[0]?.price?.id || data.line_items?.data?.[0]?.price?.id || "";
        const subscriptionId = data.subscription || data.id;
        
        // Get referral code from checkout session metadata or client_reference_id
        const referralCode = data.metadata?.ref || data.metadata?.referral_code || data.client_reference_id?.split('_ref_')[1] || null;

        let tier = "core";
        let systemsAllowed = 2;

        if (priceId === "price_1SqYQkJ4X1wkC4EsCFVBHYnT" || priceId === "price_1SqYQlJ4X1wkC4EsJcPW7Of2") {
          tier = "enterprise";
          systemsAllowed = 100;
        } else if (priceId === "price_1SqYQkJ4X1wkC4Es8OMt79pZ" || priceId === "price_1SqYQkJ4X1wkC4EsWYwUgceu") {
          tier = "pro";
          systemsAllowed = 25;
        } else if (priceId === "price_1SqYQjJ4X1wkC4EsLDB6ZbOk" || priceId === "price_1SqYQjJ4X1wkC4EslIkZEJFZ") {
          tier = "core";
          systemsAllowed = 2;
        }

        const licenseKey = `CX-${tier.toUpperCase()}-${generateRandomString(4)}-${generateRandomString(4)}-${generateRandomString(4)}-${generateRandomString(4)}`;

        const expiresAt = new Date();
        const isAnnual = priceId.includes("year") || data.items?.data?.[0]?.price?.recurring?.interval === "year";
        if (isAnnual) {
          expiresAt.setFullYear(expiresAt.getFullYear() + 1);
        } else {
          expiresAt.setMonth(expiresAt.getMonth() + 1);
        }

        const existing = await env.DB.prepare(
          "SELECT id FROM licenses WHERE stripe_subscription_id = ?"
        ).bind(subscriptionId).first();

        if (!existing) {
          await env.DB.prepare(`
            INSERT INTO licenses (license_key, tier, customer_id, customer_email, systems_allowed, expires_at, stripe_subscription_id, stripe_customer_id, referral_code)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(licenseKey, tier, `stripe_${customerId}`, customerEmail, systemsAllowed, expiresAt.toISOString(), subscriptionId, customerId, referralCode).run();

          console.log(`Created license ${licenseKey} for ${customerEmail} (referral: ${referralCode || 'none'})`);

          // Process referral commission
          if (referralCode) {
            const license = await env.DB.prepare(
              "SELECT id FROM licenses WHERE license_key = ?"
            ).bind(licenseKey).first<any>();
            if (license) {
              await processReferral(env, license.id, priceId, referralCode);
            }
          }
        }
        break;
      }

      case "customer.subscription.updated": {
        const subscriptionId = data.id;
        const status = data.status;

        if (status === "active") {
          const currentPeriodEnd = new Date(data.current_period_end * 1000);
          await env.DB.prepare(
            "UPDATE licenses SET expires_at = ?, active = 1 WHERE stripe_subscription_id = ?"
          ).bind(currentPeriodEnd.toISOString(), subscriptionId).run();
        } else if (status === "past_due" || status === "unpaid") {
          await env.DB.prepare(
            "UPDATE licenses SET active = 0 WHERE stripe_subscription_id = ?"
          ).bind(subscriptionId).run();
        }
        break;
      }

      case "customer.subscription.deleted": {
        const subscriptionId = data.id;
        await env.DB.prepare(
          "UPDATE licenses SET active = 0 WHERE stripe_subscription_id = ?"
        ).bind(subscriptionId).run();
        console.log(`Deactivated license for subscription ${subscriptionId}`);
        break;
      }

      case "invoice.paid": {
        const subscriptionId = data.subscription;
        if (subscriptionId) {
          const periodEnd = new Date(data.lines?.data?.[0]?.period?.end * 1000 || Date.now() + 30 * 24 * 60 * 60 * 1000);
          await env.DB.prepare(
            "UPDATE licenses SET expires_at = ?, active = 1 WHERE stripe_subscription_id = ?"
          ).bind(periodEnd.toISOString(), subscriptionId).run();
        }
        break;
      }
    }

    return jsonResponse({ received: true, event_type: eventType });
  } catch (e) {
    console.error("Webhook processing error:", e);
    return jsonResponse({ received: true, error: String(e) });
  }
}

// ============================================
// ADMIN HANDLERS
// ============================================
async function handleCreateLicense(request: Request, env: Env) {
  const authHeader = request.headers.get("Authorization");
  const apiKey = authHeader?.replace("Bearer ", "");

  if (!env.ADMIN_API_KEY || apiKey !== env.ADMIN_API_KEY) {
    return errorResponse("Unauthorized - Admin API key required", 401);
  }

  const body = await request.json() as any;
  const { customer_email, tier = "pro", systems_allowed = 5, days_valid = 365, organization, referral_code } = body;

  if (!customer_email) {
    return errorResponse("customer_email is required");
  }

  const licenseKey = `CX-${tier.toUpperCase()}-${generateRandomString(4)}-${generateRandomString(4)}-${generateRandomString(4)}-${generateRandomString(4)}`;
  const customerId = `cust_${generateRandomString(16)}`;
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + days_valid);

  await env.DB.prepare(`
    INSERT INTO licenses (license_key, tier, customer_id, customer_email, organization, systems_allowed, expires_at, referral_code)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(licenseKey, tier, customerId, customer_email, organization || null, systems_allowed, expiresAt.toISOString(), referral_code || null).run();

  return jsonResponse({
    success: true,
    license_key: licenseKey,
    tier,
    customer_email,
    systems_allowed,
    expires_at: expiresAt.toISOString()
  });
}

// ============================================
// MAIN ROUTER
// ============================================
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // License endpoints
      if (path === "/api/v1/licenses/validate" && request.method === "POST") {
        return handleValidate(request, env);
      }
      if (path === "/api/v1/licenses/activate" && request.method === "POST") {
        return handleActivate(request, env);
      }
      if (path === "/api/v1/licenses/deactivate" && request.method === "POST") {
        return handleDeactivate(request, env);
      }
      if (path === "/api/v1/licenses/status" && request.method === "GET") {
        return handleStatus(request, env);
      }

      // Referral endpoints
      if (path === "/api/v1/referrals/register" && request.method === "POST") {
        return handleReferralRegister(request, env);
      }
      if (path === "/api/v1/referrals/stats" && request.method === "GET") {
        return handleReferralStats(request, env);
      }

      // Webhook
      if (path === "/webhooks/stripe" && request.method === "POST") {
        return handleStripeWebhook(request, env);
      }

      // Admin endpoints
      if (path === "/admin/create-license" && request.method === "POST") {
        return handleCreateLicense(request, env);
      }
      if (path === "/admin/referrals/pending" && request.method === "GET") {
        return handlePendingPayouts(request, env);
      }
      if (path === "/admin/referrals/mark-paid" && request.method === "POST") {
        return handleMarkPaid(request, env);
      }

      // Health check
      if (path === "/health" || path === "/") {
        return jsonResponse({
          status: "ok",
          service: "CX Linux License Server",
          version: "1.2.0",
          features: ["licensing", "referrals", "stripe-webhooks"]
        });
      }

      return errorResponse("Not found", 404);
    } catch (error) {
      console.error("Error:", error);
      return errorResponse(`Internal server error: ${error}`, 500);
    }
  }
};
