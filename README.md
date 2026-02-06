# boneIO Black Cloud API

Cloudflare Worker API for boneIO Black PWA - handles DNS registration and SSL certificate distribution.

## Features

- **DNS Registration**: Devices register their serial + local IP → creates `{serial}.black.boneio.app` DNS record
- **SSL Certificate Distribution**: Wildcard cert for `*.black.boneio.app` distributed to devices
- **Rate Limiting**: 10 requests/hour per IP to prevent abuse

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/register` | Register/update device DNS |
| GET | `/cert` | Get SSL certificate |
| GET | `/health` | Health check |

### POST /register

```json
{
  "serial": "blkf8dc18",
  "ip": "192.168.1.100"
}
```

Response:
```json
{
  "success": true,
  "domain": "blkf8dc18.black.boneio.app",
  "ip": "192.168.1.100"
}
```

### GET /cert

Response:
```json
{
  "cert": "base64-encoded-certificate",
  "key": "base64-encoded-private-key",
  "domain": "*.black.boneio.app",
  "expiresAt": "2024-03-15T00:00:00Z"
}
```

## Setup

### 1. Create KV Namespace

```bash
wrangler kv:namespace create BONEIO_KV
```

Update `wrangler.toml` with the returned namespace ID.

### 2. Set Secrets

```bash
wrangler secret put CF_API_TOKEN    # Cloudflare API token with DNS edit
wrangler secret put CF_ZONE_ID      # Zone ID for boneio.app
```

### 3. GitHub Secrets (for Actions)

- `CF_API_TOKEN` - Cloudflare API token (Workers deploy)
- `CF_DNS_API_TOKEN` - Cloudflare API token (DNS edit for cert)
- `CF_ACCOUNT_ID` - Cloudflare account ID
- `CF_ZONE_ID` - Zone ID for boneio.app
- `CF_KV_NAMESPACE_ID` - KV namespace ID
- `CERT_EMAIL` - Email for Let's Encrypt

### 4. Deploy

```bash
npm install
npm run deploy
```

### 5. Initial Certificate

Run the "Renew SSL Certificate" workflow manually to generate the first certificate.

## Development

```bash
npm install
npm run dev
```
