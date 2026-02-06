/**
 * boneIO Black Cloud API Worker
 * 
 * Handles DNS registration for boneIO Black devices and SSL certificate distribution.
 * 
 * Endpoints:
 * - POST /register - Register/update DNS record for a device
 * - GET /cert - Get wildcard SSL certificate
 * - GET /health - Health check
 */

export interface Env {
  BONEIO_KV: KVNamespace;
  CF_API_TOKEN: string;
  CF_ZONE_ID: string;
  MASTER_SECRET: string;
  SUBDOMAIN_SUFFIX: string;
  RATE_LIMIT_MAX: string;
  RATE_LIMIT_WINDOW_HOURS: string;
}

interface RegisterRequest {
  serial: string;
  ip: string;
}

/**
 * Computes HMAC-SHA256 token for a given serial using the master secret.
 */
async function computeHMAC(secret: string, serial: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(serial));
  return Array.from(new Uint8Array(signature))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Verifies the Authorization header contains a valid HMAC token for the given serial.
 * Expected format: "Bearer <hmac-hex>"
 */
async function verifyAuth(
  request: Request,
  serial: string,
  masterSecret: string
): Promise<boolean> {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return false;
  }
  const token = authHeader.slice(7);
  const expected = await computeHMAC(masterSecret, serial);
  return token === expected;
}

/**
 * Validates that an IPv4 address is in a private range.
 * Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
 */
function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split('.').map(p => parseInt(p, 10));
  if (parts.length !== 4) return false;
  // 10.0.0.0/8
  if (parts[0] === 10) return true;
  // 172.16.0.0/12
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  // 192.168.0.0/16
  if (parts[0] === 192 && parts[1] === 168) return true;
  return false;
}

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

/**
 * Validates serial number format (e.g., "blkf8dc18").
 */
function isValidSerial(serial: string): boolean {
  return /^blk[a-f0-9]{6}$/.test(serial);
}

/**
 * Validates IPv4 address format.
 */
function isValidIPv4(ip: string): boolean {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every(part => {
    const num = parseInt(part, 10);
    return num >= 0 && num <= 255 && part === num.toString();
  });
}

/**
 * Checks and updates rate limit for an IP address.
 * Returns true if request is allowed, false if rate limited.
 */
async function checkRateLimit(
  kv: KVNamespace,
  clientIP: string,
  maxRequests: number,
  windowHours: number
): Promise<{ allowed: boolean; remaining: number; resetAt: number }> {
  const key = `ratelimit:${clientIP}`;
  const now = Date.now();
  const windowMs = windowHours * 60 * 60 * 1000;

  const existing = await kv.get<RateLimitEntry>(key, 'json');

  if (!existing || existing.resetAt < now) {
    // New window
    const entry: RateLimitEntry = {
      count: 1,
      resetAt: now + windowMs,
    };
    await kv.put(key, JSON.stringify(entry), { expirationTtl: windowHours * 60 * 60 + 60 });
    return { allowed: true, remaining: maxRequests - 1, resetAt: entry.resetAt };
  }

  if (existing.count >= maxRequests) {
    return { allowed: false, remaining: 0, resetAt: existing.resetAt };
  }

  // Increment counter
  const entry: RateLimitEntry = {
    count: existing.count + 1,
    resetAt: existing.resetAt,
  };
  await kv.put(key, JSON.stringify(entry), { expirationTtl: Math.ceil((existing.resetAt - now) / 1000) + 60 });
  return { allowed: true, remaining: maxRequests - entry.count, resetAt: existing.resetAt };
}

/**
 * Creates or updates DNS A record in Cloudflare.
 */
async function upsertDNSRecord(
  apiToken: string,
  zoneId: string,
  subdomain: string,
  ip: string
): Promise<{ success: boolean; error?: string }> {
  const baseUrl = `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`;
  const headers = {
    'Authorization': `Bearer ${apiToken}`,
    'Content-Type': 'application/json',
  };

  // First, check if record exists
  const listResponse = await fetch(`${baseUrl}?type=A&name=${subdomain}`, { headers });
  const listData = await listResponse.json() as { success: boolean; result: Array<{ id: string }> };

  if (!listData.success) {
    return { success: false, error: 'Failed to query DNS records' };
  }

  const recordData = {
    type: 'A',
    name: subdomain,
    content: ip,
    ttl: 300, // 5 minutes - good for dynamic IPs
    proxied: false, // Direct connection needed for local access
  };

  if (listData.result.length > 0) {
    // Update existing record
    const recordId = listData.result[0].id;
    const updateResponse = await fetch(`${baseUrl}/${recordId}`, {
      method: 'PUT',
      headers,
      body: JSON.stringify(recordData),
    });
    const updateData = await updateResponse.json() as { success: boolean; errors?: Array<{ message: string }> };

    if (!updateData.success) {
      return { success: false, error: updateData.errors?.[0]?.message || 'Failed to update DNS record' };
    }
  } else {
    // Create new record
    const createResponse = await fetch(baseUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(recordData),
    });
    const createData = await createResponse.json() as { success: boolean; errors?: Array<{ message: string }> };

    if (!createData.success) {
      return { success: false, error: createData.errors?.[0]?.message || 'Failed to create DNS record' };
    }
  }

  return { success: true };
}

/**
 * Handles POST /register endpoint.
 */
async function handleRegister(request: Request, env: Env): Promise<Response> {
  const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';

  // Rate limiting
  const maxRequests = parseInt(env.RATE_LIMIT_MAX || '10', 10);
  const windowHours = parseInt(env.RATE_LIMIT_WINDOW_HOURS || '1', 10);
  const rateLimit = await checkRateLimit(env.BONEIO_KV, clientIP, maxRequests, windowHours);

  if (!rateLimit.allowed) {
    return new Response(JSON.stringify({
      error: 'Rate limit exceeded',
      retryAfter: Math.ceil((rateLimit.resetAt - Date.now()) / 1000),
    }), {
      status: 429,
      headers: {
        'Content-Type': 'application/json',
        'X-RateLimit-Remaining': '0',
        'X-RateLimit-Reset': rateLimit.resetAt.toString(),
        'Retry-After': Math.ceil((rateLimit.resetAt - Date.now()) / 1000).toString(),
      },
    });
  }

  // Parse request body
  let body: RegisterRequest;
  try {
    body = await request.json() as RegisterRequest;
  } catch {
    return new Response(JSON.stringify({ error: 'Invalid JSON body' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Validate serial
  if (!body.serial || !isValidSerial(body.serial)) {
    return new Response(JSON.stringify({
      error: 'Invalid serial number format. Expected: blk[6 hex chars], e.g., blkf8dc18',
    }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Validate IP
  if (!body.ip || !isValidIPv4(body.ip)) {
    return new Response(JSON.stringify({
      error: 'Invalid IPv4 address format',
    }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Validate private IP
  if (!isPrivateIPv4(body.ip)) {
    return new Response(JSON.stringify({
      error: 'Only private IP addresses are allowed (10.x.x.x, 172.16-31.x.x, 192.168.x.x)',
    }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Verify HMAC authentication
  const isAuthorized = await verifyAuth(request, body.serial, env.MASTER_SECRET);
  if (!isAuthorized) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Create DNS record
  const subdomain = `${body.serial}.${env.SUBDOMAIN_SUFFIX}`;
  const result = await upsertDNSRecord(env.CF_API_TOKEN, env.CF_ZONE_ID, subdomain, body.ip);

  if (!result.success) {
    return new Response(JSON.stringify({ error: result.error }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Store registration info in KV for tracking
  await env.BONEIO_KV.put(`device:${body.serial}`, JSON.stringify({
    ip: body.ip,
    registeredAt: new Date().toISOString(),
    lastSeen: new Date().toISOString(),
  }));

  return new Response(JSON.stringify({
    success: true,
    domain: subdomain,
    ip: body.ip,
  }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'X-RateLimit-Remaining': rateLimit.remaining.toString(),
      'X-RateLimit-Reset': rateLimit.resetAt.toString(),
    },
  });
}

/**
 * Handles GET /cert endpoint.
 */
async function handleGetCert(request: Request, env: Env): Promise<Response> {
  // Extract serial from query param for auth
  const url = new URL(request.url);
  const serial = url.searchParams.get('serial');

  if (!serial || !isValidSerial(serial)) {
    return new Response(JSON.stringify({
      error: 'Missing or invalid serial query parameter',
    }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Verify HMAC authentication
  const isAuthorized = await verifyAuth(request, serial, env.MASTER_SECRET);
  if (!isAuthorized) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Check device is registered
  const device = await env.BONEIO_KV.get(`device:${serial}`);
  if (!device) {
    return new Response(JSON.stringify({
      error: 'Device not registered. Call /register first.',
    }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Get certificate from KV
  const cert = await env.BONEIO_KV.get('ssl:cert');
  const key = await env.BONEIO_KV.get('ssl:key');

  if (!cert || !key) {
    return new Response(JSON.stringify({
      error: 'Certificate not available. Please try again later.',
    }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Get certificate metadata
  const metadata = await env.BONEIO_KV.get<{ expiresAt: string; issuedAt: string }>('ssl:metadata', 'json');

  return new Response(JSON.stringify({
    cert,
    key,
    domain: `*.${env.SUBDOMAIN_SUFFIX}`,
    expiresAt: metadata?.expiresAt,
    issuedAt: metadata?.issuedAt,
  }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * Handles GET /health endpoint.
 */
function handleHealth(): Response {
  return new Response(JSON.stringify({
    status: 'ok',
    timestamp: new Date().toISOString(),
  }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * Main request handler.
 */
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS headers for all responses
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    let response: Response;

    try {
      switch (true) {
        case path === '/register' && request.method === 'POST':
          response = await handleRegister(request, env);
          break;

        case path === '/cert' && request.method === 'GET':
          response = await handleGetCert(request, env);
          break;

        case path === '/health' && request.method === 'GET':
          response = handleHealth();
          break;

        default:
          response = new Response(JSON.stringify({
            error: 'Not found',
            endpoints: {
              'POST /register': 'Register device DNS',
              'GET /cert': 'Get SSL certificate',
              'GET /health': 'Health check',
            },
          }), {
            status: 404,
            headers: { 'Content-Type': 'application/json' },
          });
      }
    } catch (error) {
      console.error('Worker error:', error);
      response = new Response(JSON.stringify({
        error: 'Internal server error',
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Add CORS headers to response
    Object.entries(corsHeaders).forEach(([key, value]) => {
      response.headers.set(key, value);
    });

    return response;
  },
};
