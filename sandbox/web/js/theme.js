// theme.js: light or dark. Follows the operating system until the analyst picks one with
// the toggle; the choice is remembered per browser. Loaded in <head> so the saved theme
// applies before the first paint.
(function () {
  const KEY = 'sandbox-theme';
  const root = document.documentElement;
  let saved = null;
  try { saved = localStorage.getItem(KEY); } catch (e) { /* storage unavailable */ }
  if (saved === 'light' || saved === 'dark') root.dataset.theme = saved;

  function current() {
    if (root.dataset.theme) return root.dataset.theme;
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  document.addEventListener('DOMContentLoaded', () => {
    const toggle = document.getElementById('theme-toggle');
    if (!toggle) return;
    const label = () => { toggle.title = current() === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'; };
    label();
    toggle.addEventListener('click', () => {
      const next = current() === 'dark' ? 'light' : 'dark';
      root.dataset.theme = next;
      try { localStorage.setItem(KEY, next); } catch (e) { /* storage unavailable */ }
      label();
    });
  });
})();
