import assert from 'node:assert/strict';
import { test } from 'node:test';
import { load, plain } from './harness.mjs';

const ctx = load('detector.js', 'redirect-check.js', 'url-heuristics.js', 'normalize.js', 'render.js', 'copy-report.js');
const { normalize, urlHeuristics, redirectCheck, copyReport } = ctx;

function verdictFor(type, vt, abuse) {
  const norm = normalize.normalizeResult({ value: 'x', raw: 'x', type });
  normalize.mergeVendorData(norm, 'vt', vt);
  if (abuse !== undefined) normalize.mergeVendorData(norm, 'abuseipdb', abuse);
  normalize.computeInfrastructureFlag(norm);
  normalize.computeVerdict(norm);
  return norm;
}

const vtReport = (malicious) => ({
  ok: true,
  data: { data: { id: 'x', attributes: { last_analysis_stats: { malicious, suspicious: 0, harmless: 60, undetected: 20 } } } },
});

test('a failed or empty VirusTotal answer is unknown, not clean', () => {
  assert.equal(verdictFor('domain', { ok: false, status: 503, error: 'vendor_not_configured' }).verdict, 'unknown');
  assert.equal(verdictFor('domain', { ok: false, status: 429, error: 'VirusTotal HTTP 429' }).verdict, 'unknown');
  const notFound = verdictFor('hash', { ok: false, status: 404, error: 'VirusTotal HTTP 404: not found' });
  assert.equal(notFound.verdict, 'unknown');
  assert.equal(notFound.vt_not_found, true);
  // AbuseIPDB alone, with a low score, is not enough to call an IP clean.
  assert.equal(verdictFor('ip', { ok: false, error: 'x' }, { ok: true, data: { data: { abuseConfidenceScore: 0 } } }).verdict, 'unknown');
  assert.equal(verdictFor('domain', vtReport(0)).verdict, 'clean');
  assert.equal(verdictFor('domain', vtReport(2)).verdict, 'suspicious');
  assert.equal(verdictFor('domain', vtReport(9)).verdict, 'malicious');
});

const codes = (url) => plain(urlHeuristics.analyzeUrl(url)).map((w) => w.code);

test('lookalike check: no false alarms on real words and brand domains', () => {
  for (const url of [
    'https://finance.yahoo.com/',
    'https://apply.workable.com/x',
    'https://www.paypal.com/signin',
    'https://outlook.office365.com/mail',
    'https://www.googleapis.com/x',
    'https://www.google.com.kw/',
    'https://phase.example/',
    // Reported: "share" is two edits from "chase" and raised a Chase lookalike alert.
    'https://share.google/cg0sNh9Sa48oSYxhf',
    'https://google.com.kw/share.google?q=cg0sNh9Sa48oSYxhf?876164590083787650943',
    'https://share.example.com/',
  ]) assert.deepEqual(codes(url).filter((c) => c.includes('brand')), [], url);
});

test('lookalike check: catches typosquats, digit swaps and combosquats', () => {
  assert.ok(codes('https://micros0ft-login.example/').includes('lookalike_brand'));
  assert.ok(codes('https://paypa1.example/').includes('lookalike_brand'));
  assert.ok(codes('https://micrsoft.example/').includes('lookalike_brand'));
  assert.ok(codes('https://paypal-secure-login.example/').includes('brand_in_foreign_domain'));
  assert.ok(codes('https://paypal.com.account-check.example/').includes('brand_in_foreign_domain'));
});

test('a data:text/html URL gets one scheme warning, not two', () => {
  assert.equal(codes('data:text/html,<b>x</b>').filter((c) => c === 'suspicious_scheme').length, 1);
});

test('registrable domain handles generic second levels under country codes', () => {
  assert.equal(redirectCheck.registrableDomain('www.google.com.kw'), 'google.com.kw');
  assert.equal(redirectCheck.registrableDomain('a.b.example.co.uk'), 'example.co.uk');
  assert.equal(redirectCheck.registrableDomain('a.example.com'), 'example.com');
});

test('redirect analysis: hop limit, meta refresh and script redirects are reported', () => {
  const hop = (url, extra = {}) => ({ url, status: 302, location: '/n', ...extra });
  const long = Array.from({ length: 15 }, (_, i) => hop(`https://h${i}.example/`));
  long.push({ url: 'https://h15.example/', note: 'hop limit reached', location: null });
  assert.ok(plain(redirectCheck.analyzeChain(long)).some((w) => w.code === 'excessive_hops'));

  const short = [hop('https://a.example/'), { url: 'https://a.example/n', status: 200, location: null }];
  assert.ok(!plain(redirectCheck.analyzeChain(short)).some((w) => w.code === 'excessive_hops'));

  const meta = [
    { url: 'https://bucket.s3.example/x.html', status: 200, location: 'https://evil.example/', via: 'meta-refresh' },
    { url: 'https://evil.example/', status: 200, location: null, script_redirect: true, title: 'Twitch' },
  ];
  const got = plain(redirectCheck.analyzeChain(meta)).map((w) => w.code);
  assert.ok(got.includes('refresh_redirect'));
  assert.ok(got.includes('script_redirect'));

  // The reported chain: S3 page with a meta refresh to twitch.tv and a redirect script.
  const cloaked = [
    { url: 'https://bucket.s3.ap-south-1.amazonaws.com/x', status: 200, location: 'https://www.twitch.tv/', via: 'meta-refresh', script_redirect: true },
    { url: 'https://www.twitch.tv/', status: 200, location: null, title: 'Twitch' },
  ];
  assert.ok(plain(redirectCheck.analyzeChain(cloaked)).some((w) => w.code === 'script_and_meta_redirect'));
});

test('twimch.com looks like Twitch', () => {
  assert.ok(codes('https://twimch.com/').includes('lookalike_brand'));
  assert.deepEqual(codes('https://www.twitch.tv/').filter((c) => c.includes('brand')), []);
});

test('CSV and spreadsheet copies neutralise formula cells', () => {
  const norm = { ioc: 'evil.example', type: 'domain', verdict: 'malicious', score_summary: {}, network: {}, tags: ['=HYPERLINK("http://x","y")'], urls: {}, vendor_links: {} };
  const csv = copyReport.renderMany([norm], { fields: ['ioc', 'tags'], format: 'csv', includeEmpty: true });
  assert.match(csv.split('\n')[1], /^evil\.example,"'=HYPERLINK/);
  const tsv = copyReport.renderMany([norm], { fields: ['tags'], format: 'values', includeEmpty: true });
  assert.ok(tsv.startsWith("'="));
});

test('the hosting/proxy flag is for IPs only', () => {
  const vt = { ok: true, data: { data: { id: 'h', attributes: { tags: ['via-tor'], last_analysis_stats: { malicious: 60 } } } } };
  assert.equal(verdictFor('hash', vt).infrastructure_flag, null);
  assert.equal(verdictFor('ip', vt).infrastructure_flag.label, 'Possible Proxy');
});

test('a newly registered domain is a warning and makes the verdict suspicious', () => {
  const now = Math.floor(Date.now() / 1000);
  const vt = (created) => ({ ok: true, data: { data: { id: 'd', attributes: { creation_date: created, last_analysis_stats: { malicious: 0, harmless: 70 } } } } });
  const fresh = verdictFor('domain', vt(now - 3 * 86400));
  assert.equal(fresh.domain_age_days, 3);
  assert.equal(fresh.verdict, 'suspicious');
  assert.deepEqual(plain(fresh.warnings).map((w) => w.code), ['new_domain']);
  const old = verdictFor('email', vt(now - 4000 * 86400));
  assert.equal(old.verdict, 'clean');
  assert.deepEqual(plain(old.warnings), []);
});
