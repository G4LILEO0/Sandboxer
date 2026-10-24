// config.js — API locations. The page is served by the sandbox API, so both are
// same-origin and API keys live only in the server's SANDBOX_* environment.
const CONFIG = {
  INTEL_BASE_URL: '/v1/intel',    // VirusTotal / AbuseIPDB forwarding + redirect walk
  SANDBOX_BASE_URL: '/v1',        // analyses (detonation) API
};
