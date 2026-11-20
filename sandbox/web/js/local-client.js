// Lookups in what Sandboxer already holds (/v1/intel/local): feed indicators and the
// IoCs collected by past analyses. app.js runs this before VirusTotal and AbuseIPDB.

const LOCAL_SUMMARY_LABELS = {
  listed: 'Listed in threat feeds',
  related_malicious: 'Related to known-bad activity',
  related_suspicious: 'Related to suspicious activity',
  allowlisted: 'On the allowlist',
  seen: 'Seen in past analyses',
  unknown: 'Not in Sandboxer',
};

async function localLookup(type, value) {
  if (!value) return { ok: false, error: 'empty value' };
  return window.vtClient.intelGet(`/local/${encodeURIComponent(type)}/${encodeURIComponent(value)}`);
}

window.localClient = { localLookup, LOCAL_SUMMARY_LABELS };
