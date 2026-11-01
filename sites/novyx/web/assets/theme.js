// Remove credentials left by older form submissions from the current history entry.
(() => {
  const url = new URL(location.href);
  if (url.searchParams.has('username') || url.searchParams.has('password')) {
    url.searchParams.delete('username');
    url.searchParams.delete('password');
    history.replaceState(history.state, '', url.pathname + url.search + url.hash);
  }
})();
// Only the display preference is persisted; credentials stay in page memory.
(() => {
  let theme;
  try { theme = localStorage.getItem('novyx-theme'); } catch {}
  if (!['light','dark'].includes(theme)) theme = matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  document.documentElement.dataset.theme = theme;
})();
