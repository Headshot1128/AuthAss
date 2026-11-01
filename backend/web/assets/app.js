'use strict';
const $ = (selector) => document.querySelector(selector);
const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const paths = {
  overview:'<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  users:'<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2m20 0v-2a4 4 0 0 0-3-3.87M15 3.13a4 4 0 0 1 0 7.75"/><circle cx="9" cy="7" r="4"/>',
  key:'<circle cx="8" cy="8" r="5"/><path d="m12 12 9 9m-4-4 3-3m-6 0 3-3"/>',
  variables:'<path d="M8 4H6a2 2 0 0 0-2 2v3l-2 3 2 3v3a2 2 0 0 0 2 2h2m8-16h2a2 2 0 0 1 2 2v3l2 3-2 3v3a2 2 0 0 1-2 2h-2M10 9l4 6m0-6-4 6"/>',
  files:'<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Zm0 0v6h6M9 15l2 2 4-4"/>',
  activity:'<path d="M3 12h4l3-8 4 16 3-8h4"/>',
  shield:'<path d="m12 3-8 3v6c0 5 8 9 8 9s8-4 8-9V6l-8-3Z"/><path d="m8 12 3 3 5-6"/>',
  logout:'<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4m7 14 5-5-5-5m5 5H9"/>',
  refresh:'<path d="M20 7a9 9 0 0 0-15-2L2 8m0-6v6h6m-4 9a9 9 0 0 0 15 2l3-3m0 6v-6h-6"/>',
  plus:'<path d="M12 5v14M5 12h14"/>',
  search:'<circle cx="10.5" cy="10.5" r="7"/><path d="m16 16 5 5"/>',
  menu:'<path d="M3 6h18M3 12h18M3 18h18"/>',
};
const icon = (name) => `<svg viewBox="0 0 24 24" aria-hidden="true">${paths[name] || paths.shield}</svg>`;
document.querySelectorAll('[data-icon]').forEach((element) => { element.innerHTML = icon(element.dataset.icon); });
function syncThemeButtons() {
  const dark = document.documentElement.dataset.theme === 'dark';
  document.querySelectorAll('.theme-toggle').forEach((button) => {
    button.textContent = dark ? 'Light mode' : 'Dark mode';
    button.setAttribute('aria-label',dark ? 'Switch to light mode' : 'Switch to dark mode');
    button.setAttribute('aria-pressed',String(dark));
  });
}
document.querySelectorAll('.theme-toggle').forEach((button) => button.addEventListener('click',() => {
  const theme = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = theme;
  try { localStorage.setItem('novyx-theme',theme); } catch {}
  syncThemeButtons();
}));
syncThemeButtons();

const views = {
  overview: { title:'Overview', eyebrow:'YOUR CONTROL CENTER', description:'A clear view of your application’s access and activity.', action:'Create user' },
  users: { title:'Users', eyebrow:'IDENTITY & ACCESS', description:'Manage accounts and who can sign in to this website.', action:'Create user' },
  licenses: { title:'Licenses', eyebrow:'ACCESS ON YOUR TERMS', description:'Create license keys and control their lifetime.', action:'Create license' },
  variables: { title:'Variables', eyebrow:'APPLICATION CONFIGURATION', description:'Deliver the right values to the right people.', action:'Add variable' },
  files: { title:'Protected files', eyebrow:'CONTROLLED DISTRIBUTION', description:'Manage the files your authorized users can download.', action:'Register file' },
  audit: { title:'Activity log', eyebrow:'VISIBILITY & ACCOUNTABILITY', description:'A record of authentication, access, and administrative actions.' },
};
const messages = {
  invalid_credentials:'The username or password is incorrect, or this account cannot sign in.',
  invalid_request:'Check the fields and try again. Passwords must contain 12–128 characters.',
  rate_limited:'Too many attempts. Please wait a few minutes before trying again.',
  permission_denied:'Your account does not have permission for this action.',
  expired:'Your session expired. Sign in again.', revoked:'Your session was revoked. Sign in again.',
  invalid_token:'Your session is no longer valid. Sign in again.', authentication_required:'Sign in to continue.',
  user_exists:'That username is already in use.', variable_exists:'A variable with this name and scope already exists.',
  file_exists:'That storage file is already registered under a different ID.',
  subscription_frozen:'Your subscription is frozen. Contact your administrator.',
  license_revoked:'Revoked licenses cannot be extended or reset.',
  hardware_binding_disabled:'This license does not use hardware binding.',
  cannot_disable_own_access:'You cannot remove website access from your own account.',
  cannot_delete_own_account:'You cannot delete the account you are signed in with.',
  owner_required:'Only the website owner can manage users and grant access.',
  website_approval_required:'Your website access has not been approved. Ask gerry2.0 to grant permission.',
  invalid_storage_file:'The file must already exist in the server’s private storage and fit within the size limit.',
  not_found:'This record no longer exists.', server_error:'The server could not complete the request. Please sign in and try again.',
  network_failure:'Could not reach the server. Check your connection and sign in again.',
  invalid_response:'The server returned an unexpected response. Please sign in again.',
};
class ApiError extends Error {
  constructor(code, status = 0) { super(messages[code] || `Request failed (${status || code}).`); this.code = code; this.status = status; }
}
let isOwner = false;
let access = '', refreshToken = '', expiry = 0, epoch = 0, currentView = 'overview', offset = 0;
let records = [], ticket = 0, queue = Promise.resolve(), refreshTimer, toastTimer;

function signedOut(message = '') {
  access = ''; refreshToken = ''; expiry = 0; isOwner = false; epoch++; ticket++;
  clearTimeout(refreshTimer);
  $('#modal').close(); $('#modal-content').replaceChildren();
  $('#console').hidden = true; $('#login-screen').hidden = false;
  $('#password').value = ''; $('#page-content').replaceChildren();
  $('#sidebar').classList.remove('open');
  $('#login-error').textContent = message; $('#login-error').hidden = !message;
}
async function wire(path, method, body, token = '') {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  try {
    const headers = { 'Accept':'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (token) headers.Authorization = `Bearer ${token}`;
    const response = await fetch(path, { method, headers, body:body === undefined ? undefined : JSON.stringify(body),
      cache:'no-store', credentials:'omit', redirect:'error', signal:controller.signal });
    let data;
    try { data = await response.json(); } catch { throw new ApiError('invalid_response', response.status); }
    if (!response.ok || data?.success !== true) throw new ApiError(data?.error || 'invalid_response', response.status);
    return data;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError('network_failure');
  } finally { clearTimeout(timeout); }
}
function acceptTokens(data) {
  if (typeof data.access_token !== 'string' || !/^[\w-]{32,256}$/.test(data.access_token) ||
      typeof data.refresh_token !== 'string' || !/^[\w-]{32,256}$/.test(data.refresh_token) ||
      !Number.isSafeInteger(data.expires_at) || data.expires_at <= Date.now()/1000) throw new ApiError('invalid_response');
  access = data.access_token; refreshToken = data.refresh_token; expiry = data.expires_at;
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(() => { api('/v1/admin/session').catch(() => {}); }, Math.max(1000, (expiry*1000 - Date.now()) - 10000));
}
async function rotate() {
  if (!refreshToken) throw new ApiError('authentication_required', 401);
  acceptTokens(await wire('/v1/refresh', 'POST', { refresh_token:refreshToken }));
}
function api(path, method = 'GET', body) {
  const expectedEpoch = epoch;
  const task = queue.then(async () => {
    if (expectedEpoch !== epoch || !access) throw new ApiError('authentication_required', 401);
    try {
      if (expiry * 1000 <= Date.now() + 15000) await rotate();
      try { return await wire(path, method, body, access); }
      catch (error) {
        if (error.code !== 'expired') throw error;
        await rotate();
        return await wire(path, method, body, access);
      }
    } catch (error) {
      if (error.status === 401 || error.status >= 500 || !error.status || error.code === 'invalid_response') signedOut(error.message);
      throw error;
    }
  });
  queue = task.catch(() => {});
  return task;
}
function toast(message) {
  clearTimeout(toastTimer); $('#toast').textContent = message; $('#toast').hidden = false;
  toastTimer = setTimeout(() => { $('#toast').hidden = true; }, 4500);
}
function stamp(value) { return value ? new Date(value*1000).toLocaleString(undefined, {dateStyle:'medium', timeStyle:'short'}) : 'Not set'; }
function shortId(value) { return value ? String(value).slice(0,8) : '—'; }
function dateValue(value) {
  if (!value) return '';
  const date = new Date(value*1000);
  return new Date(date.getTime()-date.getTimezoneOffset()*60000).toISOString().slice(0,16);
}
function unix(value) { return value ? Math.floor(new Date(value).getTime()/1000) : 0; }
function badge(label, variant = '') { return `<span class="badge ${esc(variant)}">${esc(label)}</span>`; }
function eventName(event) { return String(event).replace(/^admin\./, '').replace(/[._]/g, ' '); }
function outcome(value) { return badge(value, ['denied','revoked'].includes(value) || /^\d/.test(value) ? 'bad' : ''); }
function empty(title, description, type = 'files') {
  return `<div class="empty-state"><span>${icon(type)}</span><h3>${esc(title)}</h3><p>${esc(description)}</p></div>`;
}
function eventList(events) {
  if (!events.length) return empty('A fresh start', 'Administrative activity will appear here as you work.', 'activity');
  return `<div class="activity-list">${events.map((row) => `<div class="activity-item"><span class="event-symbol">${icon(row.event.includes('login') ? 'shield' : 'activity')}</span><div class="activity-main"><strong>${esc(eventName(row.event))}</strong><small>${esc(row.actor_id ? `Actor ${shortId(row.actor_id)}` : 'System event')} · ${esc(row.outcome)}</small></div><span class="activity-time">${esc(new Date(row.timestamp*1000).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}))}</span></div>`).join('')}</div>`;
}
function renderOverview(data) {
  const cards = [ ['Total users',data.counts.users,'users','Accounts in your workspace'], ['Active subscriptions',data.counts.subscribers,'shield','Active accounts with time remaining'], ['Active licenses',data.counts.licenses,'key','Unexpired and available for access'], ['Protected files',data.counts.files,'files','Enabled for authorized downloads'] ];
  return `<div class="stats-grid">${cards.map(([label,count,type,note]) => `<div class="stat-card"><div class="stat-top"><span>${label}</span><span class="stat-icon">${icon(type)}</span></div><div class="stat-number">${esc(count)}</div><div class="stat-bottom"><span class="status-dot"></span>${note}</div></div>`).join('')}</div>
  <div class="overview-columns"><section class="card"><div class="card-heading"><div><h2>Recent activity</h2><p>The latest events across your workspace</p></div><button class="text-button" data-view="audit">View all activity ↗</button></div>${eventList(data.recent)}</section>
  <div class="overview-side"><section class="card"><div class="card-heading"><div><h2>Access by design</h2><p>The controls behind your application</p></div><span class="stat-icon">${icon('shield')}</span></div><div class="posture"><div class="posture-item"><span class="check-icon">✓</span><div><strong>Server-side authorization</strong><p>Sessions and permissions are checked on every protected request.</p></div></div><div class="posture-item"><span class="check-icon">✓</span><div><strong>Short-lived sessions</strong><p>Access tokens expire. Refresh tokens rotate with replay detection.</p></div></div><div class="posture-item"><span class="check-icon">✓</span><div><strong>Private file delivery</strong><p>Files stream through authenticated endpoints, with no public storage links.</p></div></div></div></section>
  <section class="quickstart"><span class="eyebrow">MAKE IT YOURS</span><h3>Your next user starts here.</h3><p>Invite another administrator to manage this website with their own account.</p><button class="button" data-command="create-user">Create a user <span aria-hidden="true">↗</span></button></section></div></div>`;
}
const headings = {
  users:['User','Status','Website access','Role','Actions'],
  licenses:['License','Permission','Assigned to','Expires','Status','Actions'],
  variables:['Name','Value','Scope','Permission','Actions'],
  files:['File','Storage name','Permission','Limit','Status','Actions'],
  audit:['Event','Outcome','Actor','Target','Time'],
};
function rowMarkup(row) {
  const id = esc(row.id);
  const actions = (buttons) => `<div class="row-actions">${buttons.map(([action,label]) => `<button data-row-action="${action}" data-id="${id}">${label}</button>`).join('')}</div>`;
  let cells;
  if (currentView === 'users') cells = [
    `<div class="user-cell"><span class="avatar">${esc(row.username.charAt(0).toUpperCase())}</span><div><strong>${esc(row.username)}</strong><span class="cell-subtitle">${esc(shortId(row.id))}</span></div></div>`,
    badge(row.status, row.status === 'active' ? '' : 'bad'), row.is_owner ? badge('Owner') : row.web_approved ? badge('Approved') : badge('Not approved','warn'), badge(row.is_owner ? 'owner' : row.console_only ? 'website user' : row.role,'neutral'),
    actions([['edit','Manage'],['permissions','Website access'],['delete-user','Delete user']]) ];
  else if (currentView === 'licenses') cells = [
    `<strong class="license-key">${esc(row.key || 'Legacy key unavailable')}</strong><span class="cell-subtitle">${row.hardware_bound ? 'Hardware bound' : 'Account license'} · ${esc(shortId(row.id))}</span>`,
    `<code class="code-pill">${esc(row.permission)}</code>`, esc(row.username || 'Unassigned'), esc(row.frozen_at != null ? 'Frozen' : stamp(row.expires_at)),
    row.revoked ? badge('Revoked','bad') : row.frozen_at != null ? badge('Frozen','warn') : row.expires_at <= Date.now()/1000 ? badge('Expired','warn') : badge('Active'), row.revoked ? '—' : actions([...(row.hardware_bound ? [['reset-hwid','HWID Reset']] : []),['freeze',row.frozen_at != null ? 'Unfreeze' : 'Freeze'],['extend','Add days'],['revoke','Revoke']]) ];
  else if (currentView === 'variables') cells = [
    `<strong>${esc(row.name)}</strong><span class="cell-subtitle">${esc(row.id)}</span>`, esc(row.value.length > 45 ? row.value.slice(0,45)+'…' : row.value),
    row.user_id ? `<span title="${esc(row.user_id)}">User ${esc(shortId(row.user_id))}</span>` : badge('Application','neutral'),
    `<code class="code-pill">${esc(row.permission)}</code>`, actions([['edit','Edit'],['delete','Delete']]) ];
  else if (currentView === 'files') cells = [
    `<strong>${esc(row.id)}</strong>`, `<code class="code-pill">${esc(row.storage_name)}</code>`, `<code class="code-pill">${esc(row.permission)}</code>`,
    `${esc((row.max_bytes/1048576).toLocaleString(undefined,{maximumFractionDigits:2}))} MiB`, badge(row.enabled ? 'Enabled' : 'Disabled',row.enabled ? '' : 'neutral'), actions([['edit','Manage']]) ];
  else cells = [ `<strong>${esc(eventName(row.event))}</strong><span class="cell-subtitle">#${esc(row.id)}</span>`, outcome(row.outcome), `<span title="${esc(row.actor_id)}">${esc(shortId(row.actor_id))}</span>`, `<span title="${esc(row.target)}">${esc(shortId(row.target))}</span>`, esc(stamp(row.timestamp)) ];
  return `<tr>${cells.map((value) => `<td>${value}</td>`).join('')}</tr>`;
}
function tableBody(query = '') {
  const filtered = records.filter((row) => Object.values(row).some((value) => String(value ?? '').toLowerCase().includes(query.toLowerCase())));
  $('#table-rows').innerHTML = filtered.map(rowMarkup).join('');
  $('#table-empty').hidden = !!filtered.length;
  $('#table-data').hidden = !filtered.length;
}
function renderTable() {
  const title = views[currentView].title;
  return `<section class="card"><div class="table-toolbar"><h2>${esc(title)} <span>${records.length}${records.length === 100 ? '+' : ''}</span></h2><div class="search-wrap">${icon('search')}<input id="table-search" type="search" placeholder="Search this page…" aria-label="Search ${esc(title)} on this page"></div></div><div class="table-scroll" id="table-data"><table><thead><tr>${headings[currentView].map((heading) => `<th scope="col">${heading}</th>`).join('')}</tr></thead><tbody id="table-rows"></tbody></table></div><div id="table-empty" hidden>${empty(`No ${title.toLowerCase()} found`,currentView === 'files' ? 'Register a file from your server’s private storage to control access to it.' : 'New records will appear here. Try a different search or add your first record.',currentView === 'audit' ? 'activity' : currentView === 'licenses' ? 'key' : currentView === 'users' ? 'users' : 'files')}</div><div class="table-footer"><span>Page ${Math.floor(offset/100)+1} · ${records.length} records loaded</span><div class="pagination"><button id="previous-page" ${offset === 0 ? 'disabled' : ''}>← Previous</button><button id="next-page" ${records.length < 100 ? 'disabled' : ''}>Next →</button></div></div></section>`;
}
async function loadPage(view = currentView, reset = false) {
  if (!access) return;
  if (!views[view] || (view === 'users' && !isOwner)) view = 'overview';
  if (view !== currentView || reset) offset = 0;
  currentView = view; const myTicket = ++ticket;
  const config = views[view];
  $('#breadcrumb').textContent = config.title; $('#page-title').textContent = config.title;
  $('#page-eyebrow').textContent = config.eyebrow; $('#page-description').textContent = config.description;
  $('#action-label').textContent = config.action || ''; $('#page-action').hidden = !config.action || (!isOwner && (view === 'overview' || view === 'users'));
  document.querySelectorAll('.nav-item').forEach((item) => { const active = item.dataset.view === view; item.classList.toggle('active',active); if (active) item.setAttribute('aria-current','page'); else item.removeAttribute('aria-current'); });
  $('#sidebar').classList.remove('open'); $('#menu-toggle').setAttribute('aria-expanded','false');
  $('#page-error').hidden = true; $('#page-content').innerHTML = '<div class="loading">Loading workspace data…</div>';
  try {
    const data = await api(view === 'overview' ? '/v1/admin/overview' : view === 'audit' ? `/v1/admin/audit?recent=true&offset=${offset}` : `/v1/admin/${view}?offset=${offset}`);
    if (myTicket !== ticket || !access) return;
    if (view === 'overview') { $('#page-content').innerHTML = renderOverview(data); if (!isOwner) $('.quickstart').hidden = true; }
    else { records = data[view === 'audit' ? 'events' : view]; $('#page-content').innerHTML = renderTable(); tableBody(); }
  } catch (error) {
    if (myTicket !== ticket || !access) return;
    $('#page-content').innerHTML = empty('Unable to load this view', 'Use the refresh button to try again.', 'refresh');
    $('#page-error').textContent = error.message; $('#page-error').hidden = false;
  }
}

function field(name, label, type = 'text', value = '', options = {}) {
  const required = options.optional ? '' : ' required';
  let control;
  if (type === 'select') control = `<select name="${name}" id="field-${name}">${options.choices.map(([v,l]) => `<option value="${esc(v)}" ${String(value) === String(v) ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select>`;
  else if (type === 'textarea') control = `<textarea id="field-${name}" name="${name}" maxlength="16384"${required}>${esc(value)}</textarea>`;
  else if (type === 'checkbox') return `<div class="field"><label class="checkbox-label"><input name="${name}" type="checkbox" ${value ? 'checked' : ''}>${label}</label>${options.help ? `<small>${options.help}</small>` : ''}</div>`;
  else control = `<input id="field-${name}" name="${name}" type="${type}" value="${type === 'password' ? '' : esc(value)}"${required}${type === 'password' ? ' minlength="12" maxlength="128" autocomplete="new-password"' : ''}${type === 'number' ? ` min="1" max="${options.numberMax || 1073741824}" step="1"` : ''}${options.pattern ? ` pattern="${options.pattern.replace(/-\]/g,'\\-]')}"` : ''}${options.max ? ` maxlength="${options.max}"` : ''}>`;
  return `<div class="field"><label for="field-${name}">${label}</label>${control}${options.help ? `<small>${options.help}</small>` : ''}</div>`;
}
function openModal(title, description, fields, label, submit) {
  $('#modal-content').innerHTML = `<div class="modal-heading"><div><h2 id="modal-title">${esc(title)}</h2><p>${esc(description)}</p></div><button type="button" class="icon-button" data-close aria-label="Close dialog">×</button></div><form id="modal-form"><div class="modal-body">${fields}<p id="modal-error" class="form-error" role="alert" hidden></p></div><div class="modal-footer"><button type="button" class="button" data-close>Cancel</button><button type="submit" class="button primary">${esc(label)}</button></div></form>`;
  if (!$('#modal').open) $('#modal').showModal();
  const form = $('#modal-form');
  form.addEventListener('submit', async (event) => {
    event.preventDefault(); const button = form.querySelector('[type=submit]'); button.disabled = true;
    $('#modal-error').hidden = true;
    try { await submit(new FormData(form)); }
    catch (error) { if ($('#modal-error')) { $('#modal-error').textContent = error.message; $('#modal-error').hidden = false; } }
    finally { if (button.isConnected) button.disabled = false; }
  });
}
async function changed(message) { $('#modal').close(); $('#modal-content').replaceChildren(); toast(message); await loadPage(); }
const permissionField = (value = '') => field('permission','Required permission','text',value,{ pattern:'[a-zA-Z0-9_.:-]{1,100}',max:100,help:'For example: premium, downloads, or feature:reports.' });
function createUser() {
  openModal('Create a website user','New accounts cannot sign in until you approve their website access. They cannot use the application or SDK.',
    field('username','Username','text','',{pattern:'[A-Za-z0-9_.-]{3,64}',max:64})+field('password','Password','password','',{help:'Use a unique password of 12–128 characters.'}), 'Create user', async (form) => {
      await api('/v1/admin/users','POST',{username:form.get('username'),password:form.get('password')});
      await changed('User created. Grant website access before they can sign in.');
    });
}
function manageUser(row) {
  openModal(`Manage ${row.username}`,'Only the owner can grant website login. Approved users cannot create users or approve other accounts.',
    field('status','Account status','select',row.status,{choices:[['active','Active'],['suspended','Suspended'],['revoked','Revoked']]})+
    (row.is_owner ? '<p class=muted>This is the website owner.</p>' : field('web_access','Approve login to this website','checkbox',!!row.web_approved,{help:'Grant or remove website login. Removing access also revokes existing sessions.'}))+
    (row.console_only || row.role === 'admin' ? '' : field('subscription','Subscription expires','datetime-local',dateValue(row.subscription_until),{optional:true,help:'Application subscription; not needed for website access.'}))+
    field('password_expiry','Password expires','datetime-local',dateValue(row.password_until),{optional:true,help:'Leave empty for no password expiration.'}), 'Save changes', async (form) => {
      const body = {status:form.get('status'),subscription_until:form.has('subscription') ? unix(form.get('subscription')) : row.subscription_until,password_until:unix(form.get('password_expiry')) || null};
      if (!row.is_owner && (row.console_only || row.role === 'admin' || form.get('web_access') === 'on')) body.web_access = form.get('web_access') === 'on';
      await api(`/v1/admin/users/${encodeURIComponent(row.id)}`,'PUT',body);
      await changed('Account updated.');
    });
}
function managePermissions(row) {
  if (row.is_owner) { toast('The owner always has website access.'); return; }
  openModal(`Website access for ${row.username}`,'Approved accounts can use the workspace, but only the owner can manage users or grant access.',
    field('web_access','Allow this user to sign in','checkbox',!!row.web_approved,{help:'New users are blocked until approved. Removing approval ends their active sessions.'}),
    'Save permission',async (form) => {
      await api(`/v1/admin/users/${encodeURIComponent(row.id)}`,'PUT',{
        status:row.status,subscription_until:row.subscription_until,password_until:row.password_until,
        web_access:form.get('web_access') === 'on'
      });
      await changed('Website login permission updated.');
    });
}

function createLicense() {
  openModal('Create a license','New keys use NOVYX-XXXXXX-XXXXXX and remain visible to administrators.',
    field('days','License duration (days)','number',30,{numberMax:999,help:'Enter 1–999 days. The key automatically expires this many days after creation.'})+
    field('hardware','Require hardware binding','checkbox',false,{help:'An optional anti-abuse measure. Hardware IDs can be spoofed.'}),'Create license',async (form) => {
      const days = Number(form.get('days'));
      if (!Number.isInteger(days) || days < 1 || days > 999) throw new Error('Enter a whole number from 1 to 999 days.');
      const data = await api('/v1/admin/licenses','POST',{days,hardware_bound:form.get('hardware') === 'on'});
      await loadPage();
      openModal('Your license is ready','This key is also available in your license list.',`<div class="secret-key" id="new-license-key">${esc(data.key)}</div><p>Deliver it privately to its intended user. Activation binds the key to one account.</p>`, 'Done', async () => { $('#modal').close(); $('#modal-content').replaceChildren(); });
    });
}
function editVariable(row) {
  openModal(row ? 'Edit variable' : 'Add a variable','Personal values take precedence over an application-wide value with the same name.',
    field('name','Variable name','text',row?.name || '',{pattern:'[a-zA-Z0-9_.-]{1,100}',max:100})+
    field('value','Value','textarea',row?.value || '',{optional:true})+permissionField(row?.permission)+
    field('user','User ID (optional)','text',row?.user_id || '',{optional:true,help:'Leave empty for an application-wide variable. Use the full user ID for a personal value.'}), 'Save variable', async (form) => {
      const id = row?.id || crypto.randomUUID();
      await api(`/v1/admin/variables/${encodeURIComponent(id)}`,'PUT',{name:form.get('name'),value:form.get('value'),permission:form.get('permission'),user_id:form.get('user') || null});
      await changed('Variable saved.');
    });
}
function extendLicense(row) {
  openModal('Add days to license',`Current expiry: ${stamp(row.expires_at)}. Active licenses extend from their expiry; expired licenses restart from now.`,
    field('days','Days to add','number',1,{numberMax:999,help:'Enter a whole number from 1 to 999.'}),'Add days',async (form) => {
      const days = Number(form.get('days'));
      if (!Number.isInteger(days) || days < 1 || days > 999) throw new Error('Enter a whole number from 1 to 999 days.');
      await api(`/v1/admin/licenses/${encodeURIComponent(row.id)}/extend`,'POST',{days});
      await changed('License expiry extended.');
    });
}
function editFile(row) {
  openModal(row ? 'Manage protected file' : 'Register a file','The file must already exist in the server’s configured private storage.',
    (row ? `<div class="field"><label>File ID</label><code class="code-pill">${esc(row.id)}</code></div>` : field('id','File ID','text','',{pattern:'[a-zA-Z0-9_.-]{1,100}',max:100,help:'The identifier used by your C++ application.'}))+
    field('storage','Storage filename','text',row?.storage_name || '',{pattern:'[a-zA-Z0-9_.-]{1,128}',max:128,help:'A filename only, for example release.zip.'})+
    permissionField(row?.permission)+field('limit','Maximum file size (bytes)','number',row?.max_bytes || 67108864,{help:'The C++ SDK accepts downloads up to 64 MiB (67108864 bytes).'})+
    field('enabled','Enable authorized downloads','checkbox',row ? !!row.enabled : true),'Save file',async (form) => {
      await api(`/v1/admin/files/${encodeURIComponent(row?.id || form.get('id'))}`,'PUT',{storage_name:form.get('storage'),permission:form.get('permission'),max_bytes:Number(form.get('limit')),enabled:form.get('enabled') === 'on'});
      await changed('Protected file updated.');
    });
}
function confirmAction(title, description, action) {
  openModal(title,description,'<p>This change will take effect on the server immediately.</p>','Confirm',async () => { await action(); await changed('Change applied.'); });
}
function pageAction() {
  if (currentView === 'overview' || currentView === 'users') createUser();
  else if (currentView === 'licenses') createLicense();
  else if (currentView === 'variables') editVariable();
  else if (currentView === 'files') editFile();
}

$('#login-form').addEventListener('submit', async (event) => {
  event.preventDefault(); const button = $('#login-form [type=submit]'); button.disabled = true;
  $('#login-error').hidden = true;
  const username = $('#username').value.trim(); const password = $('#password').value;
  $('#password').value = '';
  try {
    signedOut();
    const data = await wire('/v1/admin/login','POST',{username,password});
    acceptTokens(data);
    const me = await api('/v1/admin/session');
    isOwner = me.is_owner === true;
    $('.nav-item[data-view=users]').hidden = !isOwner;
    $('.profile small').textContent = isOwner ? 'Owner' : 'Website user';
    $('#profile-name').textContent = me.username; $('#avatar').textContent = me.username.charAt(0).toUpperCase();
    $('#login-screen').hidden = true; $('#console').hidden = false;
    await loadPage('overview',true);
  } catch (error) { signedOut(error.message); }
  finally { button.disabled = false; }
});
$('#toggle-password').addEventListener('click', () => {
  const show = $('#password').type === 'password'; $('#password').type = show ? 'text' : 'password';
  $('#toggle-password').textContent = show ? 'Hide' : 'Show'; $('#toggle-password').setAttribute('aria-label',show ? 'Hide password' : 'Show password');
});
$('#logout').addEventListener('click', async () => {
  $('#logout').disabled = true;
  try { await api('/v1/admin/logout','POST',{}); signedOut(); }
  catch (error) { signedOut(error.message); }
  finally { $('#logout').disabled = false; }
});
$('#refresh').addEventListener('click', () => loadPage());
$('#page-action').addEventListener('click',pageAction);
$('#menu-toggle').addEventListener('click',() => { const open = $('#sidebar').classList.toggle('open'); $('#menu-toggle').setAttribute('aria-expanded',String(open)); });
$('#modal').addEventListener('close', () => { $('#modal-content').replaceChildren(); });
document.addEventListener('input',(event) => { if (event.target.id === 'table-search') tableBody(event.target.value); });
document.addEventListener('click',async (event) => {
  if (!(event.target instanceof Element)) return;
  const button = event.target.closest('button'); if (!button) return;
  if (button.hasAttribute('data-close')) { $('#modal').close(); return; }
  if (button.dataset.view) { loadPage(button.dataset.view); return; }
  if (button.dataset.command === 'create-user') { createUser(); return; }
  if (button.id === 'previous-page') { offset = Math.max(0,offset-100); loadPage(); return; }
  if (button.id === 'next-page') { offset += 100; loadPage(); return; }
  if (!button.dataset.rowAction) return;
  const row = records.find((item) => String(item.id) === button.dataset.id); if (!row) return;
  const id = encodeURIComponent(row.id); const action = button.dataset.rowAction;
  if (action === 'permissions') managePermissions(row);
  else if (action === 'extend') extendLicense(row);
  else if (action === 'delete-user') confirmAction(`Delete ${row.username}?`,'This permanently deletes the account and personal variables, ends all its sessions, and revokes its assigned licenses.',() => api(`/v1/admin/users/${id}`,'DELETE'));
  else if (action === 'reset-hwid') confirmAction('Reset hardware binding?','The assigned account keeps this license. Its application sessions will be signed out, and the next activation can bind a new device.',() => api(`/v1/admin/licenses/${id}/reset-hwid`,'POST',{}));
  else if (action === 'freeze') { button.disabled = true; try { await api(`/v1/admin/licenses/${id}/freeze`,'POST'); await loadPage(); } catch(error) { toast(error.message); } finally { button.disabled = false; } }
  else if (action === 'revoke') confirmAction('Revoke this license?','The permission granted by this license will no longer authorize access.',() => api(`/v1/admin/licenses/${id}`,'DELETE'));
  else if (action === 'delete') confirmAction('Delete this variable?',`Remove ${row.name} from its current scope.`,() => api(`/v1/admin/variables/${id}`,'DELETE'));
  else if (action === 'edit') { if (currentView === 'users') manageUser(row); else if (currentView === 'variables') editVariable(row); else if (currentView === 'files') editFile(row); }
});
