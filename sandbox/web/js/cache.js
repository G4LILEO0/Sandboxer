// localStorage cache (TTL) + a small per-vendor rate-limit queue.
//
// Cache: successful lookups are cached keyed by `type:ioc` so repeat pastes
// within a session don't re-spend API quota.
//
// RateLimiter: VT's free tier is 4 req/min & 500/day; AbuseIPDB's free tier
// is 1000/day. Calls are queued and throttled rather than fired blindly —
// callers get a "queued, retry in Ns" style status via subscribe().

const Cache = (function () {
  const PREFIX = 'iocagg:';
  const DAILY_PREFIX = 'iocagg:daily:';

  function key(k) { return PREFIX + k; }

  function set(k, v, ttlSeconds = 3600) {
    const payload = { ts: Date.now(), ttl: ttlSeconds * 1000, v };
    try { localStorage.setItem(key(k), JSON.stringify(payload)); } catch (e) { /* quota exceeded etc — non-fatal */ }
  }

  function get(k) {
    const raw = localStorage.getItem(key(k));
    if (!raw) return null;
    try {
      const p = JSON.parse(raw);
      if (Date.now() - p.ts > p.ttl) { localStorage.removeItem(key(k)); return null; }
      return p.v;
    } catch (e) { localStorage.removeItem(key(k)); return null; }
  }

  function del(k) { localStorage.removeItem(key(k)); }

  function today() { return new Date().toISOString().slice(0, 10); }

  function getDailyCount(vendor) {
    const raw = localStorage.getItem(DAILY_PREFIX + vendor);
    if (!raw) return 0;
    try {
      const p = JSON.parse(raw);
      if (p.date !== today()) return 0;
      return p.count || 0;
    } catch (e) { return 0; }
  }

  function incrDailyCount(vendor) {
    const count = getDailyCount(vendor) + 1;
    try { localStorage.setItem(DAILY_PREFIX + vendor, JSON.stringify({ date: today(), count })); } catch (e) { /* non-fatal */ }
    return count;
  }

  return { set, get, del, getDailyCount, incrDailyCount };
})();

const RateLimiter = (function () {
  const LIMITS = {
    vt: { perMinute: Infinity, perDay: 500 },
    abuseipdb: { perMinute: Infinity, perDay: 1000 },
  };
  const queues = {};
  const recentCalls = {};
  const processing = {};
  const listeners = new Set();

  function sleep(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }
  function limitFor(vendor) { return LIMITS[vendor] || { perMinute: Infinity, perDay: Infinity }; }
  function notify(vendor, info) { listeners.forEach((cb) => { try { cb(vendor, info); } catch (e) { /* listener error, ignore */ } }); }

  function subscribe(cb) { listeners.add(cb); return () => listeners.delete(cb); }

  async function processQueue(vendor) {
    if (processing[vendor]) return;
    processing[vendor] = true;
    const limit = limitFor(vendor);
    while (queues[vendor] && queues[vendor].length) {
      const dailyCount = Cache.getDailyCount(vendor);
      if (dailyCount >= limit.perDay) {
        const item = queues[vendor].shift();
        item.resolve({ ok: false, error: `${vendor}: daily quota (${limit.perDay}) reached — try again tomorrow or add a paid key` });
        continue;
      }

      recentCalls[vendor] = (recentCalls[vendor] || []).filter((t) => Date.now() - t < 60000);
      if (recentCalls[vendor].length >= limit.perMinute) {
        const oldest = recentCalls[vendor][0];
        const waitMs = Math.max(60000 - (Date.now() - oldest) + 50, 250);
        notify(vendor, { queued: queues[vendor].length, waitMs });
        await sleep(Math.min(waitMs, 5000));
        continue;
      }

      const item = queues[vendor].shift();
      recentCalls[vendor].push(Date.now());
      Cache.incrDailyCount(vendor);
      notify(vendor, { queued: queues[vendor].length, waitMs: 0 });
      try {
        item.resolve(await item.fn());
      } catch (e) {
        item.resolve({ ok: false, error: e.message });
      }
    }
    processing[vendor] = false;
  }

  function schedule(vendor, fn) {
    return new Promise((resolve) => {
      queues[vendor] = queues[vendor] || [];
      queues[vendor].push({ fn, resolve });
      processQueue(vendor);
    });
  }

  function usage(vendor) {
    const limit = limitFor(vendor);
    return { used: Cache.getDailyCount(vendor), limitPerDay: limit.perDay, limitPerMinute: limit.perMinute };
  }

  return { schedule, subscribe, usage };
})();

window.Cache = Cache;
window.RateLimiter = RateLimiter;
