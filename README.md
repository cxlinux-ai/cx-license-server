# CX License Server

Cloudflare Worker-based license server for CX Linux.

## Features

- License validation and activation
- Device limit enforcement
- Stripe webhook integration for automatic provisioning
- Hardware ID fingerprinting

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/v1/licenses/validate` | POST | Validate license key |
| `/api/v1/licenses/activate` | POST | Activate device |
| `/api/v1/licenses/deactivate` | POST | Deactivate device |
| `/api/v1/licenses/status` | GET | Get license status |
| `/webhooks/stripe` | POST | Stripe webhook handler |
| `/admin/create-license` | POST | Create license (admin) |

## Deployment

```bash
# Install dependencies
npm install -g wrangler

# Deploy
wrangler deploy
```

## Environment Variables

Set these in Cloudflare Dashboard or wrangler.toml:

- `STRIPE_WEBHOOK_SECRET` - Stripe webhook signing secret
- `ADMIN_API_KEY` - Admin API key for `/admin/*` endpoints

## Database

Uses Cloudflare D1 (SQLite). See `schema.sql` for table structure.

## License

BSL 1.1 - See LICENSE
