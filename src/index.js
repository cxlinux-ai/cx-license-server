
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

// Normalize email: remove + aliases and lowercase
// user+test@gmail.com -> user@gmail.com
function normalizeEmail(email) {
  if (!email) return email;
  const lower = email.toLowerCase();
  const [localPart, domain] = lower.split('@');
  if (!domain) return lower;
  // Remove everything after + in local part
  const normalizedLocal = localPart.split('+')[0];
  return `${normalizedLocal}@${domain}`;
}
__name(normalizeEmail, "normalizeEmail");

// ============================================
// ANTI-ABUSE MEASURES
// ============================================

// Disposable email domains to block
const DISPOSABLE_EMAIL_DOMAINS = new Set([
  'mailinator.com', 'tempmail.com', 'throwaway.email', 'guerrillamail.com',
  'sharklasers.com', 'guerrillamail.info', 'grr.la', 'guerrillamail.biz',
  'guerrillamail.de', 'guerrillamail.net', 'guerrillamail.org', 'spam4.me',
  'pokemail.net', 'dispostable.com', 'yopmail.com', 'yopmail.fr', 'yopmail.net',
  'cool.fr.nf', 'jetable.fr.nf', 'nospam.ze.tc', 'nomail.xl.cx', 'mega.zik.dj',
  'speed.1s.fr', 'courriel.fr.nf', 'moncourrier.fr.nf', 'monemail.fr.nf',
  'monmail.fr.nf', '10minutemail.com', '10minutemail.net', 'tempinbox.com',
  'fakeinbox.com', 'trashmail.com', 'trashmail.net', 'mailnesia.com',
  'maildrop.cc', 'getnada.com', 'temp-mail.org', 'emailondeck.com',
  'disposableemailaddresses.com', 'mintemail.com', 'spamgourmet.com',
  'mytrashmail.com', 'mailcatch.com', 'mailnull.com', 'spamherelots.com',
  'thisisnotmyrealemail.com', 'dodgeit.com', 'e4ward.com', 'spamex.com',
  'mailmoat.com', 'spamcero.com', 'wh4f.org', 'mailexpire.com', 'tempail.com',
  'discard.email', 'discardmail.com', 'spambog.com', 'spamavert.com',
  'mailforspam.com', 'spamfree24.org', 'objectmail.com', 'proxymail.eu',
  'rcpt.at', 'trash-mail.at', 'wegwerfmail.de', 'wegwerfmail.net',
  'wegwerfmail.org', 'emailsensei.com', 'temp.email', 'tempmailo.com'
]);

// Check if email domain is disposable
function isDisposableEmail(email) {
  if (!email) return false;
  const domain = email.split('@')[1]?.toLowerCase();
  return domain && DISPOSABLE_EMAIL_DOMAINS.has(domain);
}
__name(isDisposableEmail, "isDisposableEmail");

// Check IP rate limit (max registrations per day)
async function checkIPRateLimit(db, ip, maxPerDay = 3) {
  const oneDayAgo = Date.now() - 24 * 60 * 60 * 1000;
  const result = await db.prepare(`
    SELECT COUNT(*) as count FROM licenses 
    WHERE created_at > datetime(?, 'unixepoch') 
    AND customer_id LIKE ?
  `).bind(Math.floor(oneDayAgo / 1000), `%ip:${ip}%`).first();
  
  return (result?.count || 0) < maxPerDay;
}
__name(checkIPRateLimit, "checkIPRateLimit");

// Log registration attempt with IP
async function logRegistration(db, email, ip, success, reason) {
  try {
    await db.prepare(`
      INSERT INTO validation_log (license_key, hardware_id, action, success, error_message, ip_address, user_agent)
      VALUES (?, ?, 'register', ?, ?, ?, ?)
    `).bind(email, '', success ? 1 : 0, reason, ip, 'web').run();
  } catch (e) {
    console.error("Failed to log registration:", e);
  }
}
__name(logRegistration, "logRegistration");

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
          
          // Send license email to customer
          if (customerEmail) {
            await sendPaidLicenseEmail(customerEmail, licenseKey, tier, systemsAllowed, env);
          }
          
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
      // Free License Registration (OTP flow)
      if (path === "/api/v1/licenses/send-otp" && request.method === "POST") {
        return handleLicenseSendOTP(request, env);
      }
      if (path === "/api/v1/licenses/verify-otp" && request.method === "POST") {
        return handleLicenseVerifyOTP(request, env);
      }

      // Referral endpoints
      // OTP Verification Flow
      if (path === "/api/v1/referrals/send-otp" && request.method === "POST") {
        return handleSendOTP(request, env);
      }
      if (path === "/api/v1/referrals/verify-otp" && request.method === "POST") {
        return handleVerifyOTP(request, env);
      }
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
      // Admin Referrer Management
      if (path === "/admin/referrers" && request.method === "GET") {
        return handleAdminListReferrers(request, env);
      }
      if (path === "/admin/referrers" && request.method === "POST") {
        return handleAdminCreateReferrer(request, env);
      }
      if (path.startsWith("/admin/referrers/") && request.method === "PATCH") {
        const code = path.split("/")[3];
        return handleAdminUpdateReferrer(request, env, code);
      }
      if (path.startsWith("/admin/referrers/") && request.method === "DELETE") {
        const code = path.split("/")[3];
        return handleAdminDeleteReferrer(request, env, code);
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
// OTP VERIFICATION SYSTEM
// ============================================

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function sendOTPEmail(email, name, otp, env) {
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
        subject: 'Your CX Linux Verification Code',
        html: `
          <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h1 style="color: #00FF9F;">Verify Your Email</h1>
            <p>Hi ${name || 'there'},</p>
            <p>Your verification code for CX Linux Affiliates is:</p>
            <div style="background: #1E1E1E; padding: 30px; border-radius: 8px; text-align: center; margin: 20px 0;">
              <span style="font-size: 36px; font-weight: bold; color: #00FF9F; font-family: monospace; letter-spacing: 8px;">${otp}</span>
            </div>
            <p style="color: #666;">This code expires in 10 minutes.</p>
            <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
            <p style="color: #666; font-size: 12px;">CX Linux - AI-Native Terminal</p>
          </div>
        `
      })
    });
    return response.ok;
  } catch (e) {
    console.error('Failed to send OTP email:', e);
    return false;
  }
}

async function handleSendOTP(request, env) {
  const body = await request.json();
  const { email, name } = body;
  
  if (!email) {
    return errorResponse('Email is required');
  }
  
  const otp = generateOTP();
  const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes
  
  // Store OTP in database
  await env.DB.prepare(`
    INSERT OR REPLACE INTO otp_codes (email, otp, name, expires_at)
    VALUES (?, ?, ?, ?)
  `).bind(normalizeEmail(email), otp, name || null, expiresAt).run();
  
  // Send OTP email
  const emailSent = await sendOTPEmail(email, name, otp, env);
  
  if (!emailSent) {
    return errorResponse('Failed to send verification email');
  }
  
  return jsonResponse({
    success: true,
    message: 'Verification code sent to your email'
  });
}

async function handleVerifyOTP(request, env) {
  const body = await request.json();
  const { email, otp } = body;
  
  if (!email || !otp) {
    return errorResponse('Email and OTP are required');
  }
  
  // Get stored OTP
  const stored = await env.DB.prepare(
    'SELECT * FROM otp_codes WHERE email = ?'
  ).bind(normalizeEmail(email)).first();
  
  if (!stored) {
    return errorResponse('No verification code found. Please request a new one.');
  }
  
  if (Date.now() > stored.expires_at) {
    // Clean up expired OTP
    await env.DB.prepare('DELETE FROM otp_codes WHERE email = ?').bind(normalizeEmail(email)).run();
    return errorResponse('Verification code expired. Please request a new one.');
  }
  
  if (stored.otp !== otp) {
    return errorResponse('Invalid verification code');
  }
  
  // OTP verified! Now create or get referral code
  const existing = await env.DB.prepare(
    'SELECT * FROM referrers WHERE email = ?'
  ).bind(normalizeEmail(email)).first();
  
  let referralCode;
  if (existing) {
    referralCode = existing.referral_code;
  } else {
    referralCode = await generateUniqueReferralCode(env);
    await env.DB.prepare(`
      INSERT INTO referrers (referral_code, email, name, payout_email)
      VALUES (?, ?, ?, ?)
    `).bind(referralCode, normalizeEmail(email), stored.name || null, normalizeEmail(email)).run();
  }
  
  // Clean up used OTP
  await env.DB.prepare('DELETE FROM otp_codes WHERE email = ?').bind(normalizeEmail(email)).run();
  
  // Send welcome email with referral code
  await sendReferralEmail(email, stored.name, referralCode, env);
  
  return jsonResponse({
    success: true,
    referral_code: referralCode,
    referral_link: `https://cxlinux.com/?ref=${referralCode}`,
    commission_rate: '10%'
  });
}

// ============================================
// FREE LICENSE REGISTRATION (OTP)
// ============================================

async function handleLicenseSendOTP(request, env) {
  const body = await request.json();
  const { email, name } = body;
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  
  if (!email) {
    return errorResponse('Email is required');
  }
  
  if (!name) {
    return errorResponse('Name is required');
  }
  
  // Anti-abuse: Check for disposable email
  if (isDisposableEmail(email)) {
    await logRegistration(env.DB, email, ip, false, 'Disposable email blocked');
    return errorResponse('Please use a permanent email address. Temporary/disposable emails are not allowed.');
  }
  
  // Anti-abuse: Check IP rate limit (max 3 registrations per day per IP)
  const ipAllowed = await checkIPRateLimit(env.DB, ip, 3);
  if (!ipAllowed) {
    await logRegistration(env.DB, email, ip, false, 'IP rate limit exceeded');
    return errorResponse('Too many registration attempts from this IP address. Please try again tomorrow.');
  }
  
  // Check if user already has a license
  const existingLicense = await env.DB.prepare(
    'SELECT * FROM licenses WHERE customer_email = ?'
  ).bind(normalizeEmail(email)).first();
  
  if (existingLicense) {
    // Return existing license instead of creating new OTP
    return jsonResponse({
      success: true,
      existing: true,
      message: 'You already have a license. Check your email for the license key.',
      license_key: existingLicense.license_key,
      tier: existingLicense.tier
    });
  }
  
  const otp = generateOTP();
  const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes
  
  // Store OTP in database (reuse otp_codes table)
  await env.DB.prepare(`
    INSERT OR REPLACE INTO otp_codes (email, otp, name, expires_at)
    VALUES (?, ?, ?, ?)
  `).bind(normalizeEmail(email), otp, name, expiresAt).run();
  
  // Send OTP email
  const emailSent = await sendLicenseOTPEmail(email, name, otp, env);
  
  if (!emailSent) {
    return errorResponse('Failed to send verification email');
  }
  
  return jsonResponse({
    success: true,
    message: 'Verification code sent to your email'
  });
}

async function sendLicenseOTPEmail(email, name, otp, env) {
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
        subject: 'Your CX Linux Verification Code',
        html: `
          <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h1 style="color: #00FF9F;">Verify Your Email</h1>
            <p>Hi ${name},</p>
            <p>Use this code to complete your CX Linux registration:</p>
            <div style="background: #1E1E1E; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0;">
              <span style="font-size: 32px; font-weight: bold; color: #00FF9F; letter-spacing: 4px; font-family: monospace;">${otp}</span>
            </div>
            <p style="color: #666;">This code expires in 10 minutes.</p>
            <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
            <p style="color: #666; font-size: 12px;">CX Linux - AI-Native Terminal</p>
          </div>
        `
      })
    });
    return response.ok;
  } catch (e) {
    console.error('Failed to send license OTP email:', e);
    return false;
  }
}

async function handleLicenseVerifyOTP(request, env) {
  const body = await request.json();
  const { email, otp } = body;
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  
  if (!email || !otp) {
    return errorResponse('Email and verification code are required');
  }
  
  // Get stored OTP
  const stored = await env.DB.prepare(
    'SELECT * FROM otp_codes WHERE email = ?'
  ).bind(normalizeEmail(email)).first();
  
  if (!stored) {
    return errorResponse('No verification code found. Please request a new one.');
  }
  
  if (Date.now() > stored.expires_at) {
    await env.DB.prepare('DELETE FROM otp_codes WHERE email = ?').bind(normalizeEmail(email)).run();
    return errorResponse('Verification code expired. Please request a new one.');
  }
  
  if (stored.otp !== otp) {
    return errorResponse('Invalid verification code');
  }
  
  // Check if user already has a license (race condition check)
  const existingLicense = await env.DB.prepare(
    'SELECT * FROM licenses WHERE customer_email = ?'
  ).bind(normalizeEmail(email)).first();
  
  if (existingLicense) {
    await env.DB.prepare('DELETE FROM otp_codes WHERE email = ?').bind(normalizeEmail(email)).run();
    return jsonResponse({
      success: true,
      existing: true,
      license_key: existingLicense.license_key,
      tier: existingLicense.tier,
      message: 'You already have a license'
    });
  }
  
  // Create free (Core) tier license
  const licenseKey = generateLicenseKey();
  const expiresAt = new Date();
  expiresAt.setFullYear(expiresAt.getFullYear() + 100); // Free tier never expires (effectively)
  
  // Store IP in customer_id for rate limiting tracking (format: email|ip:xxx.xxx.xxx.xxx)
  const customerId = `${normalizeEmail(email)}|ip:${ip}`;
  
  await env.DB.prepare(`
    INSERT INTO licenses (license_key, tier, customer_id, customer_email, systems_allowed, expires_at)
    VALUES (?, 'core', ?, ?, 1, ?)
  `).bind(licenseKey, customerId, normalizeEmail(email), expiresAt.toISOString()).run();
  
  // Log successful registration
  await logRegistration(env.DB, normalizeEmail(email), ip, true, 'Free license created');
  
  // Clean up used OTP
  await env.DB.prepare('DELETE FROM otp_codes WHERE email = ?').bind(normalizeEmail(email)).run();
  
  // Send welcome email with license key
  await sendLicenseWelcomeEmail(email, stored.name, licenseKey, env);
  
  return jsonResponse({
    success: true,
    license_key: licenseKey,
    tier: 'core',
    message: 'License created successfully! Check your email for activation instructions.',
    systems_allowed: 1
  });
}

function generateLicenseKey() {
  // Format: CX-XXXX-XXXX-XXXX-XXXX
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const segments = [];
  for (let s = 0; s < 4; s++) {
    let segment = '';
    for (let i = 0; i < 4; i++) {
      segment += chars[Math.floor(Math.random() * chars.length)];
    }
    segments.push(segment);
  }
  return 'CX-' + segments.join('-');
}

async function sendLicenseWelcomeEmail(email, name, licenseKey, env) {
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
        subject: 'Welcome to CX Linux - Your License Key',
        html: `
          <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h1 style="color: #00FF9F;">Welcome to CX Linux!</h1>
            <p>Hi ${name || 'there'},</p>
            <p>Your free CX Linux license has been created. Here's your license key:</p>
            <div style="background: #1E1E1E; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0;">
              <span style="font-size: 20px; font-weight: bold; color: #00FF9F; font-family: monospace;">${licenseKey}</span>
            </div>
            <h3>Getting Started:</h3>
            <ol>
              <li>Install CX Terminal from <a href="https://cxlinux.com/getting-started">cxlinux.com/getting-started</a></li>
              <li>Open a terminal and run:<br>
                <code style="background: #f5f5f5; padding: 4px 8px; border-radius: 4px;">cx license activate ${licenseKey}</code>
              </li>
              <li>Start using AI-powered terminal commands!</li>
            </ol>
            <h3>Your Free Tier Includes:</h3>
            <ul>
              <li>1 system activation</li>
              <li>3 built-in AI agents</li>
              <li>50 AI queries per day</li>
              <li>Local LLM support (Ollama)</li>
              <li>7-day command history</li>
            </ul>
            <p>Want more? Upgrade anytime at <a href="https://cxlinux.com/pricing">cxlinux.com/pricing</a></p>
            <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
            <p style="color: #666; font-size: 12px;">CX Linux - AI-Native Terminal | <a href="https://cxlinux.com">cxlinux.com</a></p>
          </div>
        `
      })
    });
    return response.ok;
  } catch (e) {
    console.error('Failed to send license welcome email:', e);
    return false;
  }
}

// Send email for paid subscription license
async function sendPaidLicenseEmail(email, licenseKey, tier, systemsAllowed, env) {
  const tierNames = {
    'core': 'Core',
    'pro': 'Pro',
    'team': 'Team',
    'enterprise': 'Enterprise'
  };
  const tierName = tierNames[tier] || tier.charAt(0).toUpperCase() + tier.slice(1);
  
  const tierFeatures = {
    'pro': [
      'Up to 5 server activations',
      'Cloud LLMs (GPT-4, Claude)',
      'Web console dashboard',
      'Email support (24h response)',
      'API access',
      'Commercial license'
    ],
    'team': [
      'Up to 25 server activations',
      'Everything in Pro',
      'Team workspaces',
      'Role-based access control',
      'Shared command history',
      'Priority support (4h response)'
    ],
    'enterprise': [
      'Up to 100 server activations',
      'Everything in Team',
      'SSO/SAML/LDAP integration',
      'Audit logs & compliance',
      'SOC2 & HIPAA reports',
      '99.9% SLA guarantee',
      'Dedicated account manager'
    ]
  };
  
  const features = tierFeatures[tier] || [`Up to ${systemsAllowed} server activations`];
  const featuresList = features.map(f => `<li>${f}</li>`).join('');
  
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
        subject: `Welcome to CX Linux ${tierName} - Your License Key`,
        html: `
          <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h1 style="color: #00FF9F;">Thank You for Subscribing!</h1>
            <p>Your CX Linux <strong>${tierName}</strong> subscription is now active.</p>
            <p>Here's your license key:</p>
            <div style="background: #1E1E1E; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0;">
              <span style="font-size: 20px; font-weight: bold; color: #00FF9F; font-family: monospace;">${licenseKey}</span>
            </div>
            <h3>Getting Started:</h3>
            <ol>
              <li>Install CX Terminal from <a href="https://cxlinux.com/getting-started">cxlinux.com/getting-started</a></li>
              <li>Open a terminal and run:<br>
                <code style="background: #f5f5f5; padding: 4px 8px; border-radius: 4px;">cx license activate ${licenseKey}</code>
              </li>
              <li>Start using AI-powered terminal commands!</li>
            </ol>
            <h3>Your ${tierName} Plan Includes:</h3>
            <ul>
              ${featuresList}
            </ul>
            <p>Manage your subscription at <a href="https://cxlinux.com/account">cxlinux.com/account</a></p>
            <p>Need help? Contact <a href="mailto:support@cxlinux.com">support@cxlinux.com</a></p>
            <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
            <p style="color: #666; font-size: 12px;">CX Linux - AI-Native Terminal | <a href="https://cxlinux.com">cxlinux.com</a></p>
          </div>
        `
      })
    });
    console.log(`Sent license email to ${email}: ${response.ok}`);
    return response.ok;
  } catch (e) {
    console.error('Failed to send paid license email:', e);
    return false;
  }
}

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


function generateReferralCode() {
  // Simple 6-character alphanumeric code
  // 32^6 = 1 billion+ combinations
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Removed confusing: 0OI1
  let code = '';
  for (let i = 0; i < 6; i++) {
    code += chars[Math.floor(Math.random() * chars.length)];
  }
  return code;
}

// Generate unique code with collision check
async function generateUniqueReferralCode(env) {
  const maxAttempts = 10;
  for (let i = 0; i < maxAttempts; i++) {
    const code = generateReferralCode();
    const existing = await env.DB.prepare(
      'SELECT 1 FROM referrers WHERE referral_code = ?'
    ).bind(code).first();
    
    if (!existing) {
      return code;
    }
  }
  // Fallback: add timestamp
  return generateReferralCode() + '-' + Date.now().toString(36).slice(-4).toUpperCase();
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
  
  const referralCode = await generateUniqueReferralCode(env);
  
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

// ============================================
// ADMIN REFERRER MANAGEMENT
// ============================================

async function handleAdminListReferrers(request, env) {
  const apiKey = request.headers.get('Authorization')?.replace('Bearer ', '');
  if (!env.ADMIN_API_KEY || apiKey !== env.ADMIN_API_KEY) {
    return errorResponse('Unauthorized', 401);
  }

  const url = new URL(request.url);
  const limit = parseInt(url.searchParams.get('limit')) || 50;
  const offset = parseInt(url.searchParams.get('offset')) || 0;

  const results = await env.DB.prepare(`
    SELECT referral_code, email, name, payout_email, total_earned, total_paid, created_at
    FROM referrers
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
  `).bind(limit, offset).all();

  const countResult = await env.DB.prepare('SELECT COUNT(*) as total FROM referrers').first();

  return jsonResponse({
    success: true,
    referrers: results.results,
    total: countResult.total,
    limit,
    offset
  });
}

async function handleAdminCreateReferrer(request, env) {
  const apiKey = request.headers.get('Authorization')?.replace('Bearer ', '');
  if (!env.ADMIN_API_KEY || apiKey !== env.ADMIN_API_KEY) {
    return errorResponse('Unauthorized', 401);
  }

  const body = await request.json();
  const { email, name, code } = body;

  if (!email) {
    return errorResponse('Email is required');
  }

  const existing = await env.DB.prepare(
    'SELECT * FROM referrers WHERE email = ?'
  ).bind(normalizeEmail(email)).first();

  if (existing) {
    return errorResponse('Email already registered with code: ' + existing.referral_code);
  }

  let referralCode = code;
  if (!referralCode) {
    referralCode = await generateUniqueReferralCode(env);
  } else {
    const codeExists = await env.DB.prepare(
      'SELECT 1 FROM referrers WHERE referral_code = ?'
    ).bind(referralCode.toUpperCase()).first();
    if (codeExists) {
      return errorResponse('Code already in use');
    }
    referralCode = referralCode.toUpperCase();
  }

  await env.DB.prepare(`
    INSERT INTO referrers (referral_code, email, name, payout_email)
    VALUES (?, ?, ?, ?)
  `).bind(referralCode, normalizeEmail(email), name || null, normalizeEmail(email)).run();

  return jsonResponse({
    success: true,
    referral_code: referralCode,
    email: normalizeEmail(email)
  });
}

async function handleAdminUpdateReferrer(request, env, code) {
  const apiKey = request.headers.get('Authorization')?.replace('Bearer ', '');
  if (!env.ADMIN_API_KEY || apiKey !== env.ADMIN_API_KEY) {
    return errorResponse('Unauthorized', 401);
  }

  const body = await request.json();
  const { new_code, name, payout_email } = body;

  const existing = await env.DB.prepare(
    'SELECT * FROM referrers WHERE referral_code = ?'
  ).bind(code.toUpperCase()).first();

  if (!existing) {
    return errorResponse('Referrer not found', 404);
  }

  const updates = [];
  const values = [];

  if (new_code) {
    const codeExists = await env.DB.prepare(
      'SELECT 1 FROM referrers WHERE referral_code = ? AND id != ?'
    ).bind(new_code.toUpperCase(), existing.id).first();
    if (codeExists) {
      return errorResponse('New code already in use');
    }
    updates.push('referral_code = ?');
    values.push(new_code.toUpperCase());
  }

  if (name !== undefined) {
    updates.push('name = ?');
    values.push(name);
  }

  if (payout_email) {
    updates.push('payout_email = ?');
    values.push(payout_normalizeEmail(email));
  }

  if (updates.length === 0) {
    return errorResponse('No updates provided');
  }

  values.push(existing.id);
  await env.DB.prepare(
    `UPDATE referrers SET ${updates.join(', ')} WHERE id = ?`
  ).bind(...values).run();

  return jsonResponse({ success: true, message: 'Referrer updated' });
}

async function handleAdminDeleteReferrer(request, env, code) {
  const apiKey = request.headers.get('Authorization')?.replace('Bearer ', '');
  if (!env.ADMIN_API_KEY || apiKey !== env.ADMIN_API_KEY) {
    return errorResponse('Unauthorized', 401);
  }

  const result = await env.DB.prepare(
    'DELETE FROM referrers WHERE referral_code = ?'
  ).bind(code.toUpperCase()).run();

  if (result.changes === 0) {
    return errorResponse('Referrer not found', 404);
  }

  return jsonResponse({ success: true, message: 'Referrer deleted' });
}
