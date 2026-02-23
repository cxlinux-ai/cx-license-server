
var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/index.ts
var corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization"
};
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders
    }
  });
}
__name(jsonResponse, "jsonResponse");
function errorResponse(message, status = 400) {
  return jsonResponse({ error: message, valid: false }, status);
}
__name(errorResponse, "errorResponse");
async function logValidation(db, licenseKey, hardwareId, action, success, errorMessage, request) {
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
__name(logValidation, "logValidation");
async function getActiveDeviceCount(db, licenseId) {
  const result = await db.prepare(
    "SELECT COUNT(*) as count FROM activations WHERE license_id = ? AND active = 1"
  ).bind(licenseId).first();
  return result?.count || 0;
}
__name(getActiveDeviceCount, "getActiveDeviceCount");
async function handleValidate(request, env) {
  const body = await request.json();
  const { license_key, hardware_id } = body;
  if (!license_key) {
    return errorResponse("License key is required");
  }
  const license = await env.DB.prepare(
    "SELECT * FROM licenses WHERE license_key = ? AND active = 1"
  ).bind(license_key).first();
  if (!license) {
    await logValidation(env.DB, license_key, hardware_id || null, "validate", false, "License not found", request);
    return errorResponse("Invalid license key", 404);
  }
  const now = /* @__PURE__ */ new Date();
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
      ).bind(activation.id).run();
    }
  }
  const daysRemaining = Math.ceil((expiresAt.getTime() - now.getTime()) / (1e3 * 60 * 60 * 24));
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
__name(handleValidate, "handleValidate");
async function handleActivate(request, env) {
  const body = await request.json();
  const { license_key, hardware_id, device_name, platform, hostname } = body;
  if (!license_key || !hardware_id) {
    return errorResponse("License key and hardware_id are required");
  }
  const license = await env.DB.prepare(
    "SELECT * FROM licenses WHERE license_key = ? AND active = 1"
  ).bind(license_key).first();
  if (!license) {
    await logValidation(env.DB, license_key, hardware_id, "activate", false, "License not found", request);
    return errorResponse("Invalid license key", 404);
  }
  const now = /* @__PURE__ */ new Date();
  const expiresAt = new Date(license.expires_at);
  if (now > expiresAt) {
    await logValidation(env.DB, license_key, hardware_id, "activate", false, "License expired", request);
    return errorResponse("License has expired", 403);
  }
  const existingActivation = await env.DB.prepare(
    "SELECT * FROM activations WHERE license_id = ? AND hardware_id = ?"
  ).bind(license.id, hardware_id).first();
  if (existingActivation) {
    await env.DB.prepare(
      "UPDATE activations SET active = 1, last_seen = CURRENT_TIMESTAMP, device_name = ?, platform = ?, hostname = ? WHERE id = ?"
    ).bind(device_name || existingActivation.device_name, platform || existingActivation.platform, hostname || existingActivation.hostname, existingActivation.id).run();
    await logValidation(env.DB, license_key, hardware_id, "activate", true, "Reactivated existing device", request);
    const systemsUsed2 = await getActiveDeviceCount(env.DB, license.id);
    return jsonResponse({
      valid: true,
      message: "Device reactivated",
      systems_used: systemsUsed2,
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
__name(handleActivate, "handleActivate");
async function handleDeactivate(request, env) {
  const body = await request.json();
  const { license_key, hardware_id } = body;
  if (!license_key || !hardware_id) {
    return errorResponse("License key and hardware_id are required");
  }
  const license = await env.DB.prepare(
    "SELECT * FROM licenses WHERE license_key = ?"
  ).bind(license_key).first();
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
__name(handleDeactivate, "handleDeactivate");
async function handleStatus(request, env) {
  const url = new URL(request.url);
  const licenseKey = url.searchParams.get("license_key");
  if (!licenseKey) {
    return errorResponse("License key is required");
  }
  const license = await env.DB.prepare(
    "SELECT * FROM licenses WHERE license_key = ?"
  ).bind(licenseKey).first();
  if (!license) {
    return errorResponse("Invalid license key", 404);
  }
  const activations = await env.DB.prepare(
    "SELECT hardware_id, device_name, platform, hostname, first_seen, last_seen, active FROM activations WHERE license_id = ?"
  ).bind(license.id).all();
  const systemsUsed = activations.results?.filter((a) => a.active).length || 0;
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
__name(handleStatus, "handleStatus");
async function verifyStripeSignature(payload, signature, secret, tolerance = 300) {
  try {
    const parts = signature.split(",");
    const timestamp = parts.find((p) => p.startsWith("t="))?.slice(2);
    const sig = parts.find((p) => p.startsWith("v1="))?.slice(3);
    if (!timestamp || !sig) {
      console.log("Invalid signature format");
      return false;
    }
    const now = Math.floor(Date.now() / 1e3);
    const ts = parseInt(timestamp, 10);
    if (Math.abs(now - ts) > tolerance) {
      console.log(`Timestamp outside tolerance: ${now - ts}s difference`);
      return false;
    }
    const signedPayload = `${timestamp}.${payload}`;
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const signatureBytes = await crypto.subtle.sign(
      "HMAC",
      key,
      encoder.encode(signedPayload)
    );
    const expectedSig = Array.from(new Uint8Array(signatureBytes)).map((b) => b.toString(16).padStart(2, "0")).join("");
    if (expectedSig.length !== sig.length) {
      return false;
    }
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
__name(verifyStripeSignature, "verifyStripeSignature");
async function handleStripeWebhook(request, env) {
  const body = await request.text();
  const signature = request.headers.get("stripe-signature");
  if (!signature) {
    console.log("Missing Stripe signature header");
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
        const priceId = data.items?.data?.[0]?.price?.id || data.price?.id || "";
        const subscriptionId = data.subscription || data.id;
        let tier = "core";
        let systemsAllowed = 2;
        if (priceId.includes("enterprise") || priceId === "price_1SqYQkJ4X1wkC4EsCFVBHYnT" || priceId === "price_1SqYQlJ4X1wkC4EsJcPW7Of2") {
          tier = "enterprise";
          systemsAllowed = 100;
        } else if (priceId.includes("managed")) {
          tier = "managed";
          systemsAllowed = 1e3;
        } else if (priceId === "price_1SqYQkJ4X1wkC4Es8OMt79pZ" || priceId === "price_1SqYQkJ4X1wkC4EsWYwUgceu" || priceId.includes("pro")) {
          tier = "pro";
          systemsAllowed = 25;
        } else if (priceId === "price_1SqYQjJ4X1wkC4EsLDB6ZbOk" || priceId === "price_1SqYQjJ4X1wkC4EslIkZEJFZ" || priceId.includes("core")) {
          tier = "core";
          systemsAllowed = 2;
        }
        const licenseKey = `CX-${tier.toUpperCase()}-${generateRandomString(4)}-${generateRandomString(4)}-${generateRandomString(4)}-${generateRandomString(4)}`;
        const expiresAt = /* @__PURE__ */ new Date();
        if (priceId.includes("year") || data.items?.data?.[0]?.price?.recurring?.interval === "year") {
          expiresAt.setFullYear(expiresAt.getFullYear() + 1);
        } else {
          expiresAt.setMonth(expiresAt.getMonth() + 1);
        }
        const existing = await env.DB.prepare(
          "SELECT id FROM licenses WHERE stripe_subscription_id = ?"
        ).bind(subscriptionId).first();
        if (!existing) {
          // Get referral code from metadata
          const referralCode = data.metadata?.referral_code || data.metadata?.ref || null;
          
          await env.DB.prepare(`
            INSERT INTO licenses (license_key, tier, customer_id, customer_email, systems_allowed, expires_at, stripe_subscription_id, stripe_customer_id, referral_code)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(licenseKey, tier, `stripe_${customerId}`, customerEmail, systemsAllowed, expiresAt.toISOString(), subscriptionId, customerId, referralCode).run();
          console.log(`Created license ${licenseKey} for ${customerEmail}`);
          
          // Process referral if applicable
          if (referralCode) {
            const license = await env.DB.prepare(
              "SELECT id FROM licenses WHERE license_key = ?"
            ).bind(licenseKey).first();
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
          const currentPeriodEnd = new Date(data.current_period_end * 1e3);
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
          const periodEnd = new Date(data.lines?.data?.[0]?.period?.end * 1e3 || Date.now() + 30 * 24 * 60 * 60 * 1e3);
          await env.DB.prepare(
            "UPDATE licenses SET expires_at = ?, active = 1 WHERE stripe_subscription_id = ?"
          ).bind(periodEnd.toISOString(), subscriptionId).run();
        }
        break;
      }
      case "invoice.payment_failed": {
        const subscriptionId = data.subscription;
        console.log(`Payment failed for subscription ${subscriptionId}`);
        break;
      }
    }
    return jsonResponse({ received: true, event_type: eventType });
  } catch (e) {
    console.error("Webhook processing error:", e);
    return jsonResponse({ received: true, error: String(e) });
  }
}
__name(handleStripeWebhook, "handleStripeWebhook");
function getTierFeatures(tier) {
  const features = {
    community: ["cx-ask", "cx-status", "local-llm"],
    pro: ["cx-ask", "cx-status", "cx-demo", "cloud-llm", "priority-support"],
    enterprise: ["cx-ask", "cx-status", "cx-demo", "cloud-llm", "sso", "audit-log", "compliance", "dedicated-support"],
    managed: ["cx-ask", "cx-status", "cx-demo", "cloud-llm", "sso", "audit-log", "compliance", "dedicated-support", "custom-features", "sla"]
  };
  return features[tier] || features.community;
}
__name(getTierFeatures, "getTierFeatures");
async function handleCreateLicense(request, env) {
  const authHeader = request.headers.get("Authorization");
  const apiKey = authHeader?.replace("Bearer ", "");
  if (!env.ADMIN_API_KEY || apiKey !== env.ADMIN_API_KEY) {
    return errorResponse("Unauthorized - Admin API key required", 401);
  }
  const body = await request.json();
  const { customer_email, tier = "pro", systems_allowed = 5, days_valid = 365, organization } = body;
  if (!customer_email) {
    return errorResponse("customer_email is required");
  }
  const licenseKey = `CX-${tier.toUpperCase()}-${generateRandomString(4)}-${generateRandomString(4)}-${generateRandomString(4)}-${generateRandomString(4)}`;
  const customerId = `cust_${generateRandomString(16)}`;
  const expiresAt = /* @__PURE__ */ new Date();
  expiresAt.setDate(expiresAt.getDate() + days_valid);
  await env.DB.prepare(`
    INSERT INTO licenses (license_key, tier, customer_id, customer_email, organization, systems_allowed, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).bind(licenseKey, tier, customerId, customer_email, organization || null, systems_allowed, expiresAt.toISOString()).run();
  return jsonResponse({
    success: true,
    license_key: licenseKey,
    tier,
    customer_email,
    systems_allowed,
    expires_at: expiresAt.toISOString()
  });
}
__name(handleCreateLicense, "handleCreateLicense");
function generateRandomString(length) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let result = "";
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}
__name(generateRandomString, "generateRandomString");
var index_default = {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }
    const url = new URL(request.url);
    const path = url.pathname;
    try {
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
      if (path === "/webhooks/stripe" && request.method === "POST") {
        return handleStripeWebhook(request, env);
      }
      if (path === "/admin/create-license" && request.method === "POST") {
        return handleCreateLicense(request, env);
      }
      // Referral endpoints
      if (path === "/api/v1/referrals/register" && request.method === "POST") {
        return handleReferralRegister(request, env);
      }
      if (path === "/api/v1/referrals/stats" && request.method === "GET") {
        return handleReferralStats(request, env);
      }
      if (path === "/admin/referrals/pending" && request.method === "GET") {
        return handlePendingPayouts(request, env);
      }
      if (path === "/admin/referrals/mark-paid" && request.method === "POST") {
        return handleMarkPaid(request, env);
      }
      if (path === "/health" || path === "/") {
        return jsonResponse({
          status: "ok",
          service: "CX Linux License Server",
          version: "1.1.0",
          features: ["licensing", "referrals"]
        });
      }
      return errorResponse("Not found", 404);
    } catch (error) {
      console.error("Error:", error);
      return errorResponse(`Internal server error: ${error}`, 500);
    }
  }
};
export {
  index_default as default
};
//# sourceMappingURL=index.js.map


// ============================================
// REFERRAL SYSTEM
// ============================================

const PRICE_AMOUNTS = {
  'price_1SqYQjJ4X1wkC4EsLDB6ZbOk': 20,
  'price_1SqYQjJ4X1wkC4EslIkZEJFZ': 200,
  'price_1SqYQkJ4X1wkC4Es8OMt79pZ': 99,
  'price_1SqYQkJ4X1wkC4EsWYwUgceu': 990,
  'price_1SqYQkJ4X1wkC4EsCFVBHYnT': 299,
  'price_1SqYQlJ4X1wkC4EsJcPW7Of2': 2990,
};

const COMMISSION_RATE = 0.10;

async function sendReferralEmail(email, name, referralCode, env) {
  try {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from: 'CX Linux <noreply@cxlinux.com>',
        to: email,
        subject: 'Your CX Linux Affiliate Referral Code',
        html: `
          <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h1 style="color: #00FF9F;">Welcome to CX Linux Affiliates!</h1>
            <p>Hi ${name || 'there'},</p>
            <p>Your affiliate account has been created. Here is your referral code:</p>
            <div style="background: #1E1E1E; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0;">
              <span style="font-size: 28px; font-weight: bold; color: #00FF9F; font-family: monospace;">${referralCode}</span>
            </div>
            <p>Share this link with your network:</p>
            <p style="background: #f5f5f5; padding: 10px; border-radius: 4px; word-break: break-all;">
              <a href="https://cxlinux.com/?ref=${referralCode}">https://cxlinux.com/?ref=${referralCode}</a>
            </p>
            <h3>How it works:</h3>
            <ul>
              <li>Share your link with developers and teams</li>
              <li>Earn <strong>10% commission</strong> on every subscription</li>
              <li>Commissions are paid out monthly</li>
            </ul>
            <p>Check your stats anytime at <a href="https://cxlinux.com/affiliates">cxlinux.com/affiliates</a></p>
            <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
            <p style="color: #666; font-size: 12px;">CX Linux - AI-Native Terminal</p>
          </div>
        `
      })
    });
    return response.ok;
  } catch (e) {
    console.error('Failed to send email:', e);
    return false;
  }
}


function generateReferralCode(name) {
  const prefix = name ? name.substring(0, 3).toUpperCase() : 'REF';
  const random = Math.random().toString(36).substring(2, 8).toUpperCase();
  return `${prefix}-${random}`;
}


async function handleReferralRegister(request, env) {
  const body = await request.json();
  const { email, name, payout_email } = body;
  
  if (!email) {
    return errorResponse('Email is required');
  }
  
  const existing = await env.DB.prepare(
    'SELECT * FROM referrers WHERE email = ?'
  ).bind(email).first();
  
  if (existing) {
    // Resend email for existing users
    await sendReferralEmail(email, name || existing.name, existing.referral_code, env);
    return jsonResponse({
      success: true,
      message: 'Referral code sent to your email',
      email_sent: true
    });
  }
  
  const referralCode = generateReferralCode(name);
  
  await env.DB.prepare(`
    INSERT INTO referrers (referral_code, email, name, payout_email)
    VALUES (?, ?, ?, ?)
  `).bind(referralCode, email, name || null, payout_email || email).run();
  
  // Send email with referral code
  const emailSent = await sendReferralEmail(email, name, referralCode, env);
  
  return jsonResponse({
    success: true,
    message: emailSent ? 'Referral code sent to your email' : 'Registration successful',
    email_sent: emailSent
  });
}

async function handleReferralStats(request, env) {
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
    ).bind(code).first();
  } else {
    referrer = await env.DB.prepare(
      'SELECT * FROM referrers WHERE email = ?'
    ).bind(email).first();
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
  
  const totalReferrals = referrals.results?.length || 0;
  const totalEarned = referrals.results?.reduce((sum, r) => sum + r.commission, 0) || 0;
  const unpaidAmount = referrals.results?.filter(r => !r.paid).reduce((sum, r) => sum + r.commission, 0) || 0;
  
  return jsonResponse({
    referral_code: referrer.referral_code,
    referral_link: `https://cxlinux.com/?ref=${referrer.referral_code}`,
    total_referrals: totalReferrals,
    total_earned: totalEarned.toFixed(2),
    unpaid_amount: unpaidAmount.toFixed(2),
    paid_amount: (totalEarned - unpaidAmount).toFixed(2),
    recent_referrals: (referrals.results || []).slice(0, 10).map(r => ({
      date: r.created_at,
      tier: r.tier || 'unknown',
      commission: r.commission.toFixed(2),
      paid: r.paid === 1
    }))
  });
}

async function processReferral(env, licenseId, priceId, referralCode) {
  if (!referralCode) return null;
  
  const referrer = await env.DB.prepare(
    'SELECT * FROM referrers WHERE referral_code = ? AND active = 1'
  ).bind(referralCode).first();
  
  if (!referrer) {
    console.log(`Referral code ${referralCode} not found`);
    return null;
  }
  
  const amount = PRICE_AMOUNTS[priceId] || 0;
  if (amount === 0) {
    console.log(`Unknown price ID: ${priceId}`);
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
  
  await env.DB.prepare(`
    UPDATE licenses SET referral_code = ? WHERE id = ?
  `).bind(referralCode, licenseId).run();
  
  console.log(`Recorded referral: ${referralCode} earned $${commission.toFixed(2)}`);
  
  return { referrer_id: referrer.id, commission };
}

async function handlePendingPayouts(request, env) {
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
  
  return jsonResponse({
    pending_payouts: pending.results || [],
    total_pending: pending.results?.reduce((sum, p) => sum + p.pending_amount, 0) || 0
  });
}

async function handleMarkPaid(request, env) {
  const authHeader = request.headers.get('Authorization');
  const apiKey = authHeader?.replace('Bearer ', '');
  
  if (!env.ADMIN_API_KEY || apiKey !== env.ADMIN_API_KEY) {
    return errorResponse('Unauthorized', 401);
  }
  
  const body = await request.json();
  const { referral_code } = body;
  
  if (!referral_code) {
    return errorResponse('referral_code is required');
  }
  
  const referrer = await env.DB.prepare(
    'SELECT id FROM referrers WHERE referral_code = ?'
  ).bind(referral_code).first();
  
  if (!referrer) {
    return errorResponse('Referrer not found', 404);
  }
  
  const unpaid = await env.DB.prepare(`
    SELECT SUM(commission) as amount FROM referrals 
    WHERE referrer_id = ? AND paid = 0
  `).bind(referrer.id).first();
  
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
    amount_paid: unpaid?.amount || 0
  });
}
