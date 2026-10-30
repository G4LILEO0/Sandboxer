// Loads the lookup page's classic scripts into one fresh VM context, the way the page
// loads them, so their window.* exports can be tested without a browser.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const JS = fileURLToPath(new URL('../../sandbox/web/js/', import.meta.url));

function memoryStorage() {
  const data = new Map();
  return {
    getItem: (k) => (data.has(k) ? data.get(k) : null),
    setItem: (k, v) => { data.set(k, String(v)); },
    removeItem: (k) => { data.delete(k); },
    clear: () => data.clear(),
    key: (i) => [...data.keys()][i] ?? null,
    get length() { return data.size; },
  };
}

export function load(...scripts) {
  return loadWith({}, ...scripts);
}

// As load(), with localStorage already holding `storage` (a page reload).
export function loadWith(storage, ...scripts) {
  const context = {
    console, URL, URLSearchParams, TextEncoder, TextDecoder, atob, btoa, setTimeout, clearTimeout,
    escape, unescape, encodeURIComponent, decodeURIComponent,
    localStorage: memoryStorage(),
    document: { getElementById: () => null },
  };
  for (const [k, v] of Object.entries(storage)) context.localStorage.setItem(k, v);
  context.window = context;
  vm.createContext(context);
  for (const name of scripts) {
    vm.runInContext(readFileSync(JS + name, 'utf8'), context, { filename: name });
  }
  return context;
}

// Values from the VM have the VM's prototypes, which deepStrictEqual rejects.
export const plain = (v) => JSON.parse(JSON.stringify(v));
