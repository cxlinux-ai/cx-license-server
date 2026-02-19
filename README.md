# CX License Server

Cloudflare Worker-based license server for CX Linux with referral program.

## Features

- License validation and activation
- Device limit enforcement
- Stripe webhook integration for automatic provisioning
- Hardware ID fingerprinting
- **Referral program** (10% commission)

## API Endpoints

### License Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/v1/licenses/validate` | POST | Validate license key |
| `/api/v1/licenses/activate` | POST | Activate device |
| `/api/v1/licenses/deactivate` | POST | Deactivate device |
| `/api/v1/licenses/status` | GET | Get license status |
| `/webhooks/stripe` | POST | Stripe webhook handler |
| `/admin/create-license` | POST | Create license (admin) |

### Referral Program

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/referrals/register` | POST | Register as referrer |
| `/api/v1/referrals/stats` | GET | Get referral stats |
| `/admin/referrals/pending` | GET | List pending payouts (admin) |
| `/admin/referrals/mark-paid` | POST | Mark referral as paid (admin) |

## Referral Program

### How it works

1. **Register**: Call `/api/v1/referrals/register` with email to get a referral code
2. **Share**: Share link `https://cxlinux.com/?ref=YOUR_CODE`
3. **Earn**: Get 10% commission on every purchase made through your link
4. **Payout**: Monthly payouts via PayPal

### Register as Referrer

```bash
curl -X POST https://license.cxlinux.com/api/v1/referrals/register \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com", "name": "Your Name"}'
```

Response:
```json
{
  "success": true,
  "referral_code": "YOU-ABC123",
  "referral_link": "https://cxlinux.com/?ref=YOU-ABC123",
  "commission_rate": "10%"
}
```

### Check Stats

```bash
curl "https://license.cxlinux.com/api/v1/referrals/stats?code=YOU-ABC123"
```

### Commission Rates

| Product | Price | Commission (10%) |
|---------|-------|------------------|
| CX Core+ Monthly | $20 | $2 |
| CX Core+ Annual | $200 | $20 |
| CX Pro+ Monthly | $99 | $9.90 |
| CX Pro+ Annual | $990 | $99 |
| CX Enterprise+ Monthly | $299 | $29.90 |
| CX Enterprise+ Annual | $2990 | $299 |

## Deployment

```bash
npm install -g wrangler
wrangler deploy
```

## Environment Variables

- `STRIPE_WEBHOOK_SECRET` - Stripe webhook signing secret
- `ADMIN_API_KEY` - Admin API key for `/admin/*` endpoints

## Database

Uses Cloudflare D1 (SQLite). Run `schema.sql` to set up tables.

## License

BSL 1.1
