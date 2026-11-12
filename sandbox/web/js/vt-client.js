// VirusTotal API v3 lookups, forwarded by the sandbox API (/v1/intel/vt) so the
// key stays server-side. For URLs the server submits and polls if VT has no report yet.
// Returns a normalized promise: {ok:true, data:...} or {ok:false, error:...}.

function vtUrlId(url) {
  // VT's url_id is the URL itself, base64-url-safe encoded, no padding.
  const b64 = btoa(unescape(encodeURIComponent(url)));
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function intelGet(path) {
  try {
    // Api.headers() carries the dev sign-in (X-Dev-User), so lookups are logged under
    // the analyst the picker shows, not the default dev@localhost.
    const headers = typeof Api !== 'undefined' ? Api.headers() : {};
    const resp = await fetch(`${CONFIG.INTEL_BASE_URL}${path}`, { headers, credentials: 'same-origin' });
    const data = await resp.json().catch(() => null);
    if (!resp.ok) {
      const msg = data && (data.detail && typeof data.detail === 'string' ? `${data.error}: ${data.detail}` : data.error);
      return { ok: false, status: resp.status, error: msg || `HTTP ${resp.status}` };
    }
    return { ok: true, data };
  } catch (e) { return { ok: false, error: e.message }; }
}

async function vtLookup(type, value) {
  if (!value) return { ok: false, error: 'empty value' };
  return intelGet(`/vt/${encodeURIComponent(type)}/${encodeURIComponent(value)}`);
}

window.vtClient = { vtLookup, vtUrlId, intelGet };
