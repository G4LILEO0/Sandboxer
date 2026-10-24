// AbuseIPDB lookups (IP only), forwarded by the sandbox API (/v1/intel/abuseipdb).
async function abuseIpLookup(ip) {
  if (!ip) return { ok: false, error: 'empty ip' };
  return window.vtClient.intelGet(`/abuseipdb/${encodeURIComponent(ip)}`);
}

window.abuseClient = { abuseIpLookup };
