// Server route: /api/stripe/checkout-session
// Add this to your Express/Hono server in cx-web

import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: '2023-10-16',
});

interface CheckoutRequest {
  email: string;
  name: string;
  company?: string;
  priceId: string;
  planId: string;
  billingCycle: 'monthly' | 'annual';
  referralCode?: string;
  successUrl: string;
  cancelUrl: string;
}

export async function createCheckoutSession(req: CheckoutRequest) {
  const {
    email,
    name,
    company,
    priceId,
    planId,
    billingCycle,
    referralCode,
    successUrl,
    cancelUrl,
  } = req;

  // Create Stripe checkout session with metadata
  const session = await stripe.checkout.sessions.create({
    mode: 'subscription',
    payment_method_types: ['card'],
    customer_email: email,
    line_items: [
      {
        price: priceId,
        quantity: 1,
      },
    ],
    // Pass referral code in metadata - this gets forwarded to webhooks
    metadata: {
      ref: referralCode || '',
      referral_code: referralCode || '',
      plan_id: planId,
      billing_cycle: billingCycle,
      customer_name: name,
      company: company || '',
    },
    // Also use client_reference_id as backup
    client_reference_id: referralCode 
      ? `${email}_ref_${referralCode}`
      : email,
    subscription_data: {
      // Metadata also goes on the subscription object
      metadata: {
        ref: referralCode || '',
        plan_id: planId,
      },
    },
    success_url: successUrl,
    cancel_url: cancelUrl,
    allow_promotion_codes: true,  // Allow Stripe promo codes too
  });

  return {
    url: session.url,
    sessionId: session.id,
  };
}

// Example Express handler:
/*
app.post('/api/stripe/checkout-session', async (req, res) => {
  try {
    const result = await createCheckoutSession(req.body);
    res.json(result);
  } catch (error) {
    console.error('Stripe checkout error:', error);
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
});
*/

// Example Hono handler:
/*
app.post('/api/stripe/checkout-session', async (c) => {
  try {
    const body = await c.req.json();
    const result = await createCheckoutSession(body);
    return c.json(result);
  } catch (error) {
    console.error('Stripe checkout error:', error);
    return c.json({ error: 'Failed to create checkout session' }, 500);
  }
});
*/
