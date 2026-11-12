import assert from 'node:assert/strict';
import { test } from 'node:test';
import { load, plain } from './harness.mjs';

const { detector } = load('detector.js');
const detect = (s) => {
  const d = detector.detectIoC(s);
  return [d.type, d.value];
};

test('refangs the common defang styles', () => {
  for (const [input, expected] of [
    ['hxxps://evil[.]example/a', 'https://evil.example/a'],
    ['hxx[t]p://evil[.]example/', 'http://evil.example/'],
    ['hXXps[:]//evil[.]example', 'https://evil.example'],
    ['h**p://evil(.)example', 'http://evil.example'],
    ['evil[dot]example', 'evil.example'],
    ['1 . 2 . 3 . 4', '1.2.3.4'],
  ]) assert.equal(detector.refang(input), expected, input);
});

test('detects types and normalises values', () => {
  assert.deepEqual(detect('44D88612FEA8A8F36DE82E1278ABB02F'), ['hash', '44d88612fea8a8f36de82e1278abb02f']);
  assert.deepEqual(detect('Evil.Example.COM'), ['domain', 'evil.example.com']);
  assert.deepEqual(detect('evil.example.'), ['domain', 'evil.example']);
  assert.deepEqual(detect('_dmarc.example.com'), ['domain', '_dmarc.example.com']);
  assert.deepEqual(detect('xn--e1afmkfd.xn--p1ai'), ['domain', 'xn--e1afmkfd.xn--p1ai']);
  assert.deepEqual(detect('пример.рф'), ['domain', 'xn--e1afmkfd.xn--p1ai']);
  assert.deepEqual(detect('[2001:DB8::1]'), ['ip', '2001:db8::1']);
  assert.deepEqual(detect('https://evil.example/x'), ['url', 'https://evil.example/x']);
});

test('an address with a port is an IP, and keeps the port', () => {
  const d = detector.detectIoC('185.220.101.4:9001');
  assert.deepEqual([d.type, d.value, d.port], ['ip', '185.220.101.4', '9001']);
  const v6 = detector.detectIoC('[2606:4700::1111]:443');
  assert.deepEqual([v6.type, v6.value, v6.port], ['ip', '2606:4700::1111', '443']);
});

test('strips wrapping that pastes from mail and chat carry', () => {
  assert.deepEqual(detect('<https://evil.example/a>'), ['url', 'https://evil.example/a']);
  assert.deepEqual(detect('"evil.example",'), ['domain', 'evil.example']);
  assert.deepEqual(detect('(1.2.3.4)'), ['ip', '1.2.3.4']);
  assert.deepEqual(detect('evil.example.'), ['domain', 'evil.example']);
  // A closing parenthesis that belongs to the URL stays.
  assert.deepEqual(detect('https://en.wikipedia.org/wiki/Foo_(bar)'), ['url', 'https://en.wikipedia.org/wiki/Foo_(bar)']);
});

test('splits a paste without breaking URLs that contain commas', () => {
  assert.deepEqual(plain(detector.splitIoCs('1.2.3.4, 5.6.7.8\nevil.example;bad.example')), ['1.2.3.4', '5.6.7.8', 'evil.example', 'bad.example']);
  assert.deepEqual(plain(detector.splitIoCs('https://x.example/a,b,c')), ['https://x.example/a,b,c']);
  assert.deepEqual(plain(detector.splitIoCs('https://x.example/a,evil.example')), ['https://x.example/a', 'evil.example']);
  assert.deepEqual(plain(detector.splitIoCs('1.2.3.4\t80\tevil.example')), ['1.2.3.4', '80', 'evil.example']);
  assert.deepEqual(plain(detector.splitIoCs('1 . 2 . 3 . 4 evil [.] example')), ['1.2.3.4', 'evil[.]example']);
});

test('defangText defangs hosts inside prose only', () => {
  assert.equal(
    detector.defangText('Hop 1 -> 2 crosses domains (a.example -> https://b.example/x) at 1.5 seconds'),
    'Hop 1 -> 2 crosses domains (a[.]example -> hxxps://b[.]example/x) at 1.5 seconds',
  );
  assert.equal(detector.defangText('IP-literal host (10.1.2.3)'), 'IP-literal host (10[.]1[.]2[.]3)');
});

test('email addresses, defanged or not, are looked up by their domain', () => {
  const d = detector.detectIoC('Billing[at]Evil-Pay[.]example');
  assert.deepEqual([d.type, d.value, d.email_domain], ['email', 'billing@evil-pay.example', 'evil-pay.example']);
  assert.equal(detector.detectIoC('mailto:a@b.example').type, 'email');
  // A URL with credentials is still a URL.
  assert.equal(detector.detectIoC('https://user@evil.example/').type, 'url');
});
