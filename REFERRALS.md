# CX Linux Referral System

## Overview

The referral system allows users to earn **10% commission** on sales they refer.

## How It Works

1. **User registers** as a referrer via `/api/v1/referrals/register`
2. Gets a unique referral link: `https://cxlinux.com/pricing?ref=XXX-YYYYYY`
3. When someone purchases via their link, the referral code is tracked
4. Commission (10%) is recorded and paid out periodically

## API Endpoints

### Public

#### Register as Referrer
```
POST /api/v1/referrals/register
{
  "email": "user@example.com",
  "name": "John Doe",
  "payout_email": "paypal@example.com",  // optional
  "payout_method": "paypal"               // paypal, wise, crypto
}

Response:
{
  "success": true,
  "referral_code": "JOH-AB3X7K",
  "referral_link": "https://cxlinux.com/pricing?ref=JOH-AB3X7K",
  "commission_rate": "10%"
}
```

#### Check Referral Stats
```
GET /api/v1/referrals/stats?code=JOH-AB3X7K
or
GET /api/v1/referrals/stats?email=user@example.com

Response:
{
  "referral_code": "JOH-AB3X7K",
  "referral_link": "https://cxlinux.com/pricing?ref=JOH-AB3X7K",
  "total_referrals": 5,
  "total_earned": "49.90",
  "unpaid_amount": "29.90",
  "paid_amount": "20.00",
  "recent_referrals": [
    {
      "date": "2024-01-15T10:30:00Z",
      "tier": "pro",
      "commission": "9.90",
      "paid": false
    }
  ]
}
```

### Admin (requires Bearer token)

#### View Pending Payouts
```
GET /admin/referrals/pending
Authorization: Bearer <ADMIN_API_KEY>

Response:
{
  "pending_payouts": [
    {
      "referral_code": "JOH-AB3X7K",
      "email": "user@example.com",
      "payout_email": "paypal@example.com",
      "payout_method": "paypal",
      "pending_amount": 49.90,
      "pending_count": 5
    }
  ],
  "total_pending": "149.70"
}
```

#### Mark Referrer as Paid
```
POST /admin/referrals/mark-paid
Authorization: Bearer <ADMIN_API_KEY>
{
  "referral_code": "JOH-AB3X7K"
}

Response:
{
  "success": true,
  "referral_code": "JOH-AB3X7K",
  "amount_paid": "49.90"
}
```

## Commission Rates

| Plan | Monthly Price | Commission |
|------|---------------|------------|
| Core+ | $20 | $2.00 |
| Core+ Annual | $200 | $20.00 |
| Pro+ | $99 | $9.90 |
| Pro+ Annual | $990 | $99.00 |
| Enterprise+ | $299 | $29.90 |
| Enterprise+ Annual | $2990 | $299.00 |

## Website Integration

### Capturing Referral Code

The checkout page captures `?ref=` from URL and stores in localStorage:

```typescript
// Parse URL params
const params = new URLSearchParams(window.location.search);
const referralCode = params.get("ref") || localStorage.getItem("cx_referral");

// Store for persistence
useEffect(() => {
  const urlRef = params.get("ref");
  if (urlRef) {
    localStorage.setItem("cx_referral", urlRef);
  }
}, []);
```

### Passing to Stripe

Pass `referralCode` to `/api/stripe/checkout-session`:

```typescript
const response = await fetch("/api/stripe/checkout-session", {
  method: "POST",
  body: JSON.stringify({
    email,
    priceId,
    referralCode,  // <-- Include this
    // ...
  }),
});
```

Server creates Stripe session with metadata:

```typescript
const session = await stripe.checkout.sessions.create({
  metadata: {
    ref: referralCode,
    referral_code: referralCode,
  },
  client_reference_id: `${email}_ref_${referralCode}`,
  // ...
});
```

## Database Schema

### referrers
```sql
CREATE TABLE referrers (
  id INTEGER PRIMARY KEY,
  referral_code TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  name TEXT,
  payout_email TEXT,
  payout_method TEXT DEFAULT 'paypal',
  total_earned REAL DEFAULT 0,
  total_paid REAL DEFAULT 0,
  active INTEGER DEFAULT 1,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
```

### referrals
```sql
CREATE TABLE referrals (
  id INTEGER PRIMARY KEY,
  referrer_id INTEGER NOT NULL,
  license_id INTEGER NOT NULL,
  amount_paid REAL NOT NULL,
  commission REAL NOT NULL,
  paid INTEGER DEFAULT 0,
  paid_at TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
```

## Payout Process

1. Admin views `/admin/referrals/pending` weekly/monthly
2. Pays referrers via PayPal/Wise/Crypto
3. Marks as paid via `/admin/referrals/mark-paid`

## Files Updated

### License Server (`/tmp/cx-license-server-repo/`)
- `src/index.ts` - Added referral handlers
- `schema.sql` - Added referrers/referrals tables

### Website (`cx-web`)
- `client/src/pages/pricing/checkout.tsx` - Capture & pass ref code
- `server/routes/stripe.ts` - Include ref in Stripe metadata
