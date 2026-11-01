// Only the display preference is persisted; credentials stay in page memory.
(() => {
  let theme;
  try { theme = localStorage.getItem('novyx-theme'); } catch {}
  if (!['light','dark'].includes(theme)) theme = matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  document.documentElement.dataset.theme = theme;
})();
