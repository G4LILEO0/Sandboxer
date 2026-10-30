import assert from 'node:assert/strict';
import { test } from 'node:test';
import { load, loadWith, plain } from './harness.mjs';

const SCRIPTS = ['detector.js', 'cache.js', 'vt-client.js', 'redirect-check.js', 'url-heuristics.js', 'normalize.js', 'render.js', 'copy-report.js', 'pivots.js'];

test('resolutions pivot to the other side of the record', () => {
  const { pivots } = load(...SCRIPTS);
  const body = {
    meta: { count: 57 },
    data: [{ type: 'resolution', id: '1.2.3.4evil.example', attributes: { ip_address: '1.2.3.4', host_name: 'evil.example', date: 1700000000 } }],
  };
  assert.deepEqual(plain(pivots.summarizeRelation(body, 'domain')), { items: [{ value: '1.2.3.4', kind: 'ip', detail: '2023-11-14', malicious: null }], count: 57 });
  assert.equal(pivots.summarizeRelation(body, 'ip').items[0].value, 'evil.example');
});

test('files, hosts and single-object relationships are summarised', () => {
  const { pivots } = load(...SCRIPTS);
  const file = { type: 'file', id: 'a'.repeat(64), attributes: { meaningful_name: 'inv.exe', type_description: 'Win32 EXE', last_analysis_stats: { malicious: 41 } } };
  assert.deepEqual(plain(pivots.summarizeObject(file, 'domain')), { value: 'a'.repeat(64), kind: 'hash', detail: 'inv.exe, Win32 EXE, 41 engines', malicious: 41 });
  const ip = { data: { type: 'ip_address', id: '5.6.7.8', attributes: { as_owner: 'Hoster', country: 'NL' } } };
  assert.deepEqual(plain(pivots.summarizeRelation(ip, 'url').items.map((i) => i.value)), ['5.6.7.8']);
  const url = { type: 'url', id: 'abc', attributes: { url: 'https://evil.example/x', title: 'Sign in' } };
  assert.equal(pivots.summarizeObject(url, 'domain').value, 'https://evil.example/x');
});

test('sandbox sightings query by URL, domain or IoC value', () => {
  const { pivots } = load(...SCRIPTS);
  assert.equal(pivots.sightingQuery({ type: 'url', ioc: 'https://w.example/a', urls: { unwrapped: 'https://evil.example/' } }), 'url=https%3A%2F%2Fevil.example%2F');
  assert.equal(pivots.sightingQuery({ type: 'domain', ioc: 'evil.example' }), 'domain=evil.example');
  assert.equal(pivots.sightingQuery({ type: 'hash', ioc: 'ab' }), 'ioc=ab');
});

test('the report basket survives a reload, without raw vendor payloads', () => {
  const first = load(...SCRIPTS);
  const norm = { ioc: 'evil.example', type: 'domain', verdict: 'malicious', score_summary: {}, network: {}, tags: [], urls: {}, vendor_links: {}, raw: { vt: { big: 1 } } };
  first.copyReport.ReportBasket.add(norm);
  first.copyReport.ReportBasket.add({ ...norm, verdict: 'suspicious' }); // same IoC: replaced

  const reloaded = loadWith({ 'ioc-report-basket': first.localStorage.getItem('ioc-report-basket') }, ...SCRIPTS);
  const items = plain(reloaded.copyReport.ReportBasket.list());
  assert.equal(items.length, 1);
  assert.equal(items[0].verdict, 'suspicious');
  assert.deepEqual(items[0].raw, {});
});
