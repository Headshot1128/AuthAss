'use strict';
import { validateApplication, packageApplication, sha256 } from './bootstrapper.js';
import { createSessionRequests } from './session-requests.js';
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

const DEFAULT_APPLICATION = '00000000-0000-4000-8000-000000000001';
let activeApplication = DEFAULT_APPLICATION, applications = [];
const views = {
  resellers:{title:'Reseller accounts',eyebrow:'GROW YOUR NETWORK',description:'Give partners a focused workspace to issue license keys and reset customer HWIDs.',action:'Add reseller'},
  reseller_licenses:{title:'License keys',eyebrow:'RESELLER WORKSPACE',description:'Create keys for your customers. Each key belongs to your assigned application.',action:'Create license key'},
  reseller_hwid:{title:'HWID reset',eyebrow:'CUSTOMER SUPPORT',description:'Find a customer by username and reset their Windows account binding.'},
  account:{title:'My account',eyebrow:'ACCOUNT SECURITY',description:'Manage your recovery email for this website account.'},
  applications: {title:'Applications',eyebrow:'YOUR PRODUCTS',description:'Create separate panels for products such as External and Spoofer. Each application has its own ID, users, license keys, variables and files.',action:'New application'},
  overview: { title:'Overview', eyebrow:'YOUR CONTROL CENTER', description:'A clear view of your application’s access and activity.', action:'Create user' },
  users: { title:'Users', eyebrow:'APPLICATION CUSTOMERS', description:'Registered usernames and license keys for the selected application.', action:'Create user' },
  website_users: {title:'Website accounts',eyebrow:'OWNER ONLY',description:'Website administrators and access approvals, separate from application customers.',action:'Create website account'},
  licenses: { title:'Licenses', eyebrow:'ACCESS ON YOUR TERMS', description:'Create license keys and control their lifetime.', action:'Create license' },
  variables: { title:'Variables', eyebrow:'APPLICATION CONFIGURATION', description:'Deliver the right values to the right people.', action:'Add variable' },
  files: { title:'Protected files', eyebrow:'CONTROLLED DISTRIBUTION', description:'Upload a file and get its ID for your C++ application.', action:'Upload file' },
  bootstrapper: { title:'Bootstrapper', eyebrow:'BUILD & DISTRIBUTE', description:'Package your application and authentication DLL into one EXE.' },
  audit: { title:'Activity log', eyebrow:'VISIBILITY & ACCOUNTABILITY', description:'A record of authentication, access, and administrative actions.' },
};
const messages = {
  email_not_configured:'Email recovery is not available yet. The owner must connect the email service first.',
  email_delivery_failed:'The verification email could not be sent. Please try again later.',
  invalid_email_link:'This link has expired or was already used. Request a new link.',
  application_not_found:'This application does not exist.', invalid_application:'Check the Application ID.',
  application_disabled:'This application is disabled.',application_mismatch:'This session belongs to another application.',
  hardware_mismatch:'This account is bound to another SID. Ask the owner to reset its HWID.',
  invalid_credentials:'The username or password is incorrect, or this account cannot sign in.',
  invalid_request:'Check the required fields and try again.',
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
  owner_required:'Only the website owner can create accounts, manage website accounts and grant website access.',
  website_approval_required:'Your website access has not been approved. Ask the website owner to grant permission.',
  invalid_storage_file:'The file must already exist in the server’s private storage and fit within the size limit.',
  not_found:'This record no longer exists.', server_error:'The server could not complete the request. Please sign in and try again.',
  network_failure:'Could not reach the server. Check your connection and sign in again.',
  invalid_response:'The server returned an unexpected response. Please sign in again.',
};
class ApiError extends Error {
  constructor(code, status = 0) { super(messages[code] || `Request failed (${status || code}).`); this.code = code; this.status = status; }
}
let isOwner = false, isReseller = false, resellerMaxDays = 30, resellerRevision = 0;
let rememberedSession = false;
let access = '', refreshToken = '', expiry = 0, epoch = 0, currentView = 'overview', offset = 0;
let records = [], ticket = 0, refreshTimer, toastTimer, pageController;
const pageCache = new Map();
const requests = createSessionRequests({
  session:() => ({access,expiry,epoch}), refresh:rotate, send:wire,
  fatal:error => signedOut(error.message), changed:() => pageCache.clear(),
});

function signedOut(message = '') {
  rememberedSession = false;
  access = ''; refreshToken = ''; expiry = 0; isOwner = false; isReseller = false; epoch++; ticket++;
  pageController?.abort(); pageCache.clear(); requests.reset(); records = [];
  clearTimeout(refreshTimer);
  activeApplication=DEFAULT_APPLICATION; applications=[];
  $('#application-selector').replaceChildren(); $('#application-selector').disabled=true;
  $('#modal').close(); $('#modal-content').replaceChildren();
  $('#console').hidden = true; $('#login-screen').hidden = false;
  $('#password').value = ''; $('#page-content').replaceChildren();
  $('#sidebar').classList.remove('open');
  $('#login-error').textContent = message; $('#login-error').hidden = !message;
}
async function wire(path, method, body, token = '', binaryResponse = false, signal) {
  const controller = new AbortController();
  const abort = () => controller.abort();
  signal?.addEventListener('abort',abort,{once:true});
  if (signal?.aborted) controller.abort();
  const timeout = setTimeout(() => controller.abort(), binaryResponse || body instanceof Blob ? 300000 : 15000);
  try {
    const headers = { 'Accept':binaryResponse ? 'application/vnd.novyx.asset' : 'application/json' };
    const binary = body instanceof Blob;
    if (body !== undefined) headers['Content-Type'] = binary ? 'application/octet-stream' : 'application/json';
    if (token) headers.Authorization = `Bearer ${token}`;
    const response = await fetch(path, { method, headers, body:body === undefined ? undefined : binary ? body : JSON.stringify(body),
      cache:'no-store', credentials:'same-origin', redirect:'error', signal:controller.signal });
    if (response.status >= 500 && response.status !== 503) throw new ApiError('server_error',response.status);
    if (binaryResponse && response.ok) {
      if (response.headers.get('Content-Type') !== 'application/vnd.novyx.asset') throw new ApiError('invalid_response',response.status);
      return new Uint8Array(await response.arrayBuffer());
    }
    let data;
    try { data = await response.json(); } catch { throw new ApiError('invalid_response', response.status); }
    if (!response.ok || data?.success !== true) throw new ApiError(data?.error || 'invalid_response', response.status);
    return data;
  } catch (error) {
    if (signal?.aborted) throw new DOMException('Request cancelled','AbortError');
    if (error instanceof ApiError) throw error;
    throw new ApiError('network_failure');
  } finally { clearTimeout(timeout); signal?.removeEventListener('abort',abort); }
}
function acceptTokens(data) {
  if (typeof data.access_token !== 'string' || !/^[\w-]{32,256}$/.test(data.access_token) ||
      typeof data.refresh_token !== 'string' || !/^[\w-]{32,256}$/.test(data.refresh_token) ||
      !Number.isSafeInteger(data.expires_at) || data.expires_at <= Date.now()/1000) throw new ApiError('invalid_response');
  access = data.access_token; refreshToken = data.refresh_token; expiry = data.expires_at;
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(() => { api('/v1/admin/session').catch(() => {}); }, Math.max(1000, (expiry*1000 - Date.now()) - 10000));
}
async function rotate(expectedEpoch) {
  if (expectedEpoch !== epoch || !refreshToken) throw new ApiError('authentication_required', 401);
  const data = rememberedSession ? await wire('/v1/admin/resume','POST',{}) : await wire('/v1/refresh', 'POST', { refresh_token:refreshToken });
  if (expectedEpoch !== epoch) throw new ApiError('authentication_required',401);
  acceptTokens(data);
}
function api(path, method = 'GET', body, binaryResponse = false, options) {
  if(path.startsWith('/v1/admin/')&&!path.startsWith('/v1/admin/applications')&&!['/v1/admin/session','/v1/admin/logout'].includes(path)) path += (path.includes('?')?'&':'?')+'application_id='+encodeURIComponent(activeApplication);
  return requests.request(path,method,body,binaryResponse,options);
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
  resellers:['Reseller','Status','Maximum key duration','Added','Actions'],
  reseller_licenses:['License key','Customer','Expires','Status','Actions'],
  applications:['Application','Application ID','Status','Actions'],
  users:['Username','Registered license key','Status','HWID','Subscription','Actions'],
  website_users:['User','Status','Website access','Role','Actions'],
  licenses:['License','Permission','Assigned to','Expires','Status','Actions'],
  variables:['Name','Value','Scope','Permission','Actions'],
  files:['File','Storage name','Permission','Limit','Status','Actions'],
  audit:['Event','Outcome','Actor','Target','Time'],
};
function rowMarkup(row) {
  const id = esc(row.id);
  const actions = (buttons) => `<div class="row-actions">${buttons.map(([action,label]) => `<button data-row-action="${action}" data-id="${id}">${label}</button>`).join('')}</div>`;
  let cells;
  if (currentView === 'resellers') cells=[`<div class="user-cell"><span class="avatar">${esc(row.username[0].toUpperCase())}</span><div><strong>${esc(row.username)}</strong><span class="cell-subtitle">Reseller account</span></div></div>`,badge(row.status,row.status==='active'?'':'warn'),`${esc(row.max_days)} days`,esc(stamp(row.created_at)),actions([['edit-reseller','Manage']])];
  else if(currentView==='reseller_licenses')cells=[`<strong class="license-key">${esc(row.key||'Unavailable')}</strong><span class="cell-subtitle">SID binding enabled</span>`,esc(row.username||'Ready to assign'),esc(stamp(row.expires_at)),badge(row.revoked?'Revoked':row.expires_at<=Date.now()/1000?'Expired':'Active',row.revoked?'bad':''),actions([['copy-license','Copy key']])];
  else if (currentView === 'applications') cells = [
    `<strong>${esc(row.name)}</strong>`, `<code class=code-pill>${esc(row.id)}</code>`,badge(row.status,row.status==='active'?'':'warn'),actions([['copy-application','Copy ID'],['edit-application','Manage']])];
  else if (currentView === 'users') cells = [
    `<strong>${esc(row.username)}</strong>`,
    row.licenses?.length?row.licenses.map(license=>`<div><strong class=license-key>${esc(license.key||'Legacy key unavailable')}</strong><span class=cell-subtitle>${esc(license.revoked?'Revoked':license.expires_at<=Date.now()/1000?'Expired':'Active')} ? ${esc(stamp(license.expires_at))}</span></div>`).join(''):badge('No key registered','neutral'),
    badge(row.status==='suspended'?'Banned':row.status,row.status==='active'?'':'bad'),badge(row.hwid_bound?'Bound':'Not bound','neutral'),esc(stamp(row.subscription_until)),
    actions([['edit','Manage'],['reset-user-hwid','Reset HWID'],[row.status==='active'?'ban-user':'unban-user',row.status==='active'?'Ban':'Unban'],['delete-user','Delete user']]) ];
  else if (currentView === 'website_users') cells = [
    `<div class="user-cell"><span class="avatar">${esc(row.username.charAt(0).toUpperCase())}</span><div><strong>${esc(row.username)}</strong><span class="cell-subtitle">${esc(shortId(row.id))}</span></div></div>`,
    badge(row.status==='suspended'&&!row.console_only?'Banned':row.status, row.status === 'active' ? '' : 'bad'), row.is_owner ? badge('Owner') : !row.console_only && row.role !== 'admin' ? badge('EXE only','neutral') : row.web_approved ? badge('Approved') : badge('Not approved','warn'), badge(row.is_owner ? 'owner' : row.console_only ? 'website user' : 'application (EXE)','neutral'),
    actions([['edit','Manage'],...(row.console_only || row.role === 'admin' ? [['permissions','Website access']] : []),['delete-user','Delete user'],...(!row.console_only&&row.role!=='admin'?[['reset-user-hwid','Reset HWID'],[row.status==='active'?'ban-user':'unban-user',row.status==='active'?'Ban':'Unban']]:[])]) ];
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
    `${esc((row.max_bytes/1048576).toLocaleString(undefined,{maximumFractionDigits:2}))} MiB`, badge(row.enabled ? 'Enabled' : 'Disabled',row.enabled ? '' : 'neutral'), actions([['download-code','C++ download'],['edit','Manage']]) ];
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
  return `<section class="card"><div class="table-toolbar"><h2>${esc(title)} <span>${records.length}${records.length === 100 ? '+' : ''}</span></h2>${currentView==='users'?'<button class=button data-command=lookup-user>Find username</button>':''}<div class="search-wrap">${icon('search')}<input id="table-search" type="search" placeholder="Search this page…" aria-label="Search ${esc(title)} on this page"></div></div><div class="table-scroll" id="table-data"><table><thead><tr>${headings[currentView].map((heading) => `<th scope="col">${heading}</th>`).join('')}</tr></thead><tbody id="table-rows"></tbody></table></div><div id="table-empty" hidden>${empty(`No ${title.toLowerCase()} found`,currentView === 'files' ? 'Choose Upload file above to get a file ID for your C++ application.' : 'New records will appear here. Try a different search or add your first record.',currentView === 'audit' ? 'activity' : currentView === 'licenses' ? 'key' : currentView === 'users' ? 'users' : 'files')}</div><div class="table-footer"><span>Page ${Math.floor(offset/100)+1} · ${records.length} records loaded</span><div class="pagination"><button id="previous-page" ${offset === 0 ? 'disabled' : ''}>← Previous</button><button id="next-page" ${records.length < 100 ? 'disabled' : ''}>Next →</button></div></div></section>`;
}
function renderPageData(view,data,preserveSearch = true) {
  if(view==='reseller_licenses')renderResellerLicenses(data);
  else if (view === 'reseller_hwid') renderResellerHwid();
  else if (view === 'account') renderAccount(data);
  else if (view === 'bootstrapper') renderBootstrapper(data);
  else if (view === 'overview') {
    $('#page-content').innerHTML = renderOverview(data);
    if (!isOwner) $('.quickstart').hidden = true;
  } else {
    const query = preserveSearch ? $('#table-search')?.value || '' : '';
    if(view==='reseller_licenses')resellerMaxDays=data.max_days;
    records = data[view === 'audit' ? 'events' : view === 'website_users' ? 'users' : view];
    $('#page-content').innerHTML = renderTable();
    $('#table-search').value = query; tableBody(query);
  }
}
function pagePlaceholder(view) {
  const columns = headings[view];
  if (!columns) return '<section class="card page-placeholder" role="status">Loading this page…<div class="skeleton-line"></div><div class="skeleton-line"></div></section>';
  return `<section class="card" data-loading-view="${esc(view)}"><div class="card-heading"><h2>${esc(views[view].title)}</h2><span role="status">Loading…</span></div><div class="table-scroll"><table><thead><tr>${columns.map(column=>`<th scope="col">${esc(column)}</th>`).join('')}</tr></thead><tbody aria-hidden="true">${Array.from({length:5},()=>`<tr>${columns.map(()=>'<td><span class="skeleton-line"></span></td>').join('')}</tr>`).join('')}</tbody></table></div></section>`;
}
async function loadPage(view = currentView, reset = false) {
  if (!access) return;
  pageController?.abort(); pageController = new AbortController();
  if (isReseller && !['reseller_licenses','reseller_hwid'].includes(view)) view='reseller_licenses';
  if (!views[view] || (view === 'website_users' && !isOwner)) view = isReseller?'reseller_licenses':'overview';
  const changingView = view !== currentView || reset;
  if (changingView) offset = 0;
  currentView = view; const myTicket = ++ticket, revision=resellerRevision;
  const selectedApp=applications.find(app=>app.id===activeApplication);
  $('#workspace-context').innerHTML=`<div class="workspace-path"><span class="workspace-app-icon">${icon(isReseller?'key':'overview')}</span><strong>${esc(selectedApp?.name||'Application')}</strong><span class="workspace-path-separator">/</span><span>${isReseller?'Partner workspace':'Product workspace'}</span></div><span class="workspace-role">${isReseller?'Reseller':isOwner?'Owner':'Administrator'}</span>`;
  const config = views[view];
  $('#breadcrumb').textContent = config.title; $('#page-title').textContent = config.title;
  $('#page-eyebrow').textContent = config.eyebrow; $('#page-description').textContent = config.description;
  $('#action-label').textContent = config.action || ''; $('#page-action').hidden = !config.action || (!isOwner && (view === 'overview' || view === 'users' || view === 'website_users'));
  document.querySelectorAll('.nav-item').forEach((item) => { const active = item.dataset.view === view; item.classList.toggle('active',active); if (active) item.setAttribute('aria-current','page'); else item.removeAttribute('aria-current'); });
  $('#sidebar').classList.remove('open'); $('#menu-toggle').setAttribute('aria-expanded','false');
  $('#page-error').hidden = true;
  $('#page-content').setAttribute('aria-busy','true'); $('#page-action').disabled = true;
  const cacheKey = `${activeApplication}:${view}:${offset}`, cached = pageCache.get(cacheKey);
  if (cached && Date.now()-cached.at < 30000) {
    renderPageData(view,cached.data,!changingView);
    $('#page-description').textContent = config.description+' Updating…';
    if(view!=='reseller_licenses')$('#page-content').querySelectorAll('button').forEach(button=>{button.disabled=true;});
  } else {
    records = [];
    $('#page-content').innerHTML = pagePlaceholder(view);
  }
  try {
    const data = view==='reseller_hwid'?{}:await api(view==='reseller_licenses'?`/v1/admin/reseller/licenses?offset=${offset}`:view === 'overview' ? '/v1/admin/overview' : view === 'audit' ? `/v1/admin/audit?recent=true&offset=${offset}` : view === 'website_users' ? `/v1/admin/users?scope=website&offset=${offset}` : `/v1/admin/${view}?offset=${offset}`, 'GET',undefined,false,{signal:pageController.signal});
    if (myTicket !== ticket || !access) return;
    if(view==='reseller_licenses'&&revision!==resellerRevision)return;
    if(view==='reseller_licenses'&&cached&&$('#quick-license-form')){
      resellerMaxDays=data.max_days;records=data.reseller_licenses;
      tableBody($('#table-search')?.value||'');updateResellerSummary();
      $('#quick-license-days').max=String(resellerMaxDays);
    }else renderPageData(view,data);
    if (view !== 'bootstrapper') {
      pageCache.delete(cacheKey); pageCache.set(cacheKey,{data,at:Date.now()});
      if (pageCache.size > 10) pageCache.delete(pageCache.keys().next().value);
    }
  } catch (error) {
    if (error.name === 'AbortError' || myTicket !== ticket || !access) return;
    $('#page-content').innerHTML = empty('Unable to load this view', 'Use the refresh button to try again.', 'refresh');
    $('#page-error').textContent = error.message; $('#page-error').hidden = false;
  } finally {
    if (myTicket === ticket) {
      $('#page-content').removeAttribute('aria-busy'); $('#page-action').disabled = false;
      $('#page-description').textContent = config.description;
    }
  }
}

function renderAccount(data) {
  $('#page-content').innerHTML=`<section class="card"><div class="card-heading"><div><h2>Recovery email</h2><p>${esc(data.username)}</p></div></div><div class="bootstrap-body"><p>${data.email_verified?`Verified email: <strong>${esc(data.email)}</strong>`:'No verified recovery email. Add one to recover your password if you lose access.'}</p>${!data.email_delivery_ready?'<p class="form-error" role="status">Email delivery is not configured yet. Recovery will be available after the owner connects the email service.</p>':''}<form id="account-email-form"><div class="field"><label for="recovery-email">Email address</label><input id="recovery-email" name="email" type="email" autocomplete="email" maxlength="254" value="${esc(data.email||'')}" required></div><div class="field"><label for="email-password">Current password</label><input id="email-password" name="password" type="password" autocomplete="current-password" minlength="12" maxlength="128" required></div><button class="button primary" type="submit" ${data.email_delivery_ready?'':'disabled'}>Send verification email</button><p id="email-feedback" role="status"></p></form><p class="muted">Confirm the link in your inbox. Your current recovery email remains active until the new address is verified.</p></div></section>`;
  const form=$('#account-email-form');
  form.addEventListener('submit',async event=>{
    event.preventDefault();const button=form.querySelector('[type=submit]'),feedback=$('#email-feedback');button.disabled=true;
    const input=new FormData(form);$('#email-password').value='';
    try {const result=await api('/v1/admin/account/email','POST',{email:input.get('email'),password:input.get('password')});if(feedback.isConnected)feedback.textContent=result.message;}
    catch(error){if(feedback.isConnected)feedback.textContent=error.message;}
    finally {if(button.isConnected)button.disabled=false;}
  });
}
$('#forgot-password').addEventListener('click',()=>{
  openModal('Reset your password','Enter the verified recovery email for your website account.',field('email','Email address','email','',{max:254}),'Send reset link',async form=>{
    const result=await wire('/v1/auth/password/forgot','POST',{email:form.get('email')});$('#modal').close();toast(result.message);
  });
});
// Fragments stay out of server request logs. Clear the address bar before any API call.
const openedRecoveryLink=location.hash.includes('action=');
function handleRecoveryLink(){
const recoveryLink=new URLSearchParams(location.hash.slice(1));
if(recoveryLink.has('action')){
  const action=recoveryLink.get('action'),token=recoveryLink.get('token');history.replaceState(null,'',location.pathname+location.search);
  if(['verify-email','reset-password'].includes(action)&&/^[A-Za-z0-9_-]{64}$/.test(token||'')){
    queueMicrotask(()=>{
      if(action==='verify-email')openModal('Verify recovery email','Confirm this address for your website account.','','Verify email',async()=>{
        const result=await wire('/v1/auth/email/verify','POST',{token});$('#modal').close();toast(result.message);
      });
      else openModal('Choose a new password','Use 12 to 128 characters.',field('password','New password','password')+field('confirm','Confirm password','password'),'Change password',async form=>{
        if(form.get('password')!==form.get('confirm'))throw new Error('Passwords must match.');
        const result=await wire('/v1/auth/password/reset','POST',{token,password:form.get('password')});$('#modal').close();toast(result.message);
      });
    });
  }else queueMicrotask(()=>toast(messages.invalid_email_link));
}
}
window.addEventListener('hashchange',handleRecoveryLink);
handleRecoveryLink();
function renderBootstrapper(data) {
  $('#page-content').innerHTML = `<div class="bootstrap-grid"><section class="card"><div class="card-heading"><div><h2>1. Compile with the DLL SDK</h2><p>Keep authentication in the embedded DLL.</p></div></div><div class="bootstrap-body"><p>Download the SDK, add its include folder, and use <code>novyx::Client</code> in your application. Compile a Windows x64 EXE with C++17.</p><pre class="bootstrap-code">#include &lt;novyx/bootstrap.hpp&gt;

novyx::Client auth("https://novyx.online", novyx::CurrentUserSid(), "", "${esc(activeApplication)}");
if (!auth.Initialize()) return 1;
if (!auth.Login(username, password).success) return 1;</pre><button class="button" id="bootstrap-sdk" type="button">Download Bootstrapper SDK</button><p id="bootstrap-sdk-status" role="status"></p><p class="muted">Includes headers, an example and a compiled test EXE. Existing applications using the static SDK need to be rebuilt.</p></div></section><section class="card"><div class="card-heading"><div><h2>2. Build your application</h2><p>Choose your compiled EXE and download one ready-to-run file.</p></div></div><form id="bootstrap-form" class="bootstrap-body"><label for="bootstrap-file">Compiled application (.exe)</label><input id="bootstrap-file" name="application" type="file" accept=".exe" required><p class="muted">Windows x64, up to 64 MiB. Your selected EXE stays in your browser. Authentication DLLs are embedded automatically.</p><button class="button primary" type="submit">Build application</button><p id="bootstrap-status" role="status" aria-live="polite"></p><p id="bootstrap-error" class="form-error" role="alert" hidden></p><a id="bootstrap-result" class="button" hidden>Download packaged application</a></form></section></div>`;
  const form = $('#bootstrap-form');
  $('#bootstrap-sdk').addEventListener('click',async event => {
    const button=event.currentTarget, message=$('#bootstrap-sdk-status'), expectedEpoch=epoch;
    button.disabled=true;message.textContent='Downloading SDK…';
    try {
      const bytes=await api(data.sdk_url,'GET',undefined,true);
      if(expectedEpoch!==epoch||!access||!form.isConnected)return;
      const url=URL.createObjectURL(new Blob([bytes],{type:'application/zip'}));
      const link=document.createElement('a');link.href=url;link.download='novyx-bootstrap-sdk.zip';link.click();
      setTimeout(()=>URL.revokeObjectURL(url),60000);
      message.textContent='SDK ready. Extract the ZIP and follow README.md.';
    }catch(error){message.textContent=error.message;}
    finally{button.disabled=false;}
  });
  let resultUrl = '';
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const button = form.querySelector('[type=submit]');
    const status = $('#bootstrap-status'), errorBox = $('#bootstrap-error'), resultLink = $('#bootstrap-result');
    const expectedEpoch = epoch;
    button.disabled = true; errorBox.hidden = true; resultLink.hidden = true;
    if (resultUrl) { URL.revokeObjectURL(resultUrl); resultUrl = ''; }
    try {
      const file = $('#bootstrap-file').files[0];
      if (!file || file.size > data.max_bytes) throw new Error('Choose an EXE up to 64 MiB.');
      status.textContent = 'Checking application…';
      const application = new Uint8Array(await file.arrayBuffer());
      validateApplication(application,activeApplication);
      status.textContent = 'Loading authentication bootstrapper…';
      const template = await api(data.template_url,'GET',undefined,true);
      if (template.length !== data.template_bytes || await sha256(template) !== data.template_sha256)
        throw new Error('The bootstrap template changed. Refresh this page and try again.');
      const output = packageApplication(template,application);
      // Revalidate the admin session before releasing a generated download.
      await api('/v1/admin/bootstrapper','POST',{size:file.size,sha256:await sha256(application)});
      if (expectedEpoch !== epoch || !access || !form.isConnected) return;
      const name = file.name.replace(/\.exe$/i,'').replace(/[^a-zA-Z0-9_.-]/g,'_') || 'application';
      resultUrl = URL.createObjectURL(output);
      resultLink.href = resultUrl; resultLink.download = `${name}-bootstrap.exe`; resultLink.hidden = false;
      status.textContent = 'Ready. Your application and authentication DLL are embedded in one EXE.';
      resultLink.click();
    } catch (error) {
      if (!form.isConnected) return;
      status.textContent = ''; errorBox.textContent = error.message; errorBox.hidden = false;
    } finally { button.disabled = false; }
  });
  // Object URLs retain the packaged EXE in memory until the view is replaced.
  const observer = new MutationObserver(() => {
    if (form.isConnected) return;
    if (resultUrl) URL.revokeObjectURL(resultUrl);
    observer.disconnect();
  });
  observer.observe($('#page-content'),{childList:true});
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
    const label = button.textContent;
    if (form.querySelector('input[type=file]')?.files.length) {
      button.textContent = 'Uploading…';
      form.setAttribute('aria-busy','true');
    }
    $('#modal-error').hidden = true;
    try { await submit(new FormData(form)); }
    catch (error) { if ($('#modal-error')) { $('#modal-error').textContent = error.message; $('#modal-error').hidden = false; } }
    finally { if (button.isConnected) { button.disabled = false; button.textContent = label; form.removeAttribute('aria-busy'); } }
  });
}
async function changed(message) { $('#modal').close(); $('#modal-content').replaceChildren(); toast(message); await loadPage(); }
const permissionField = (value = '') => field('permission','Required permission','text',value,{ pattern:'[a-zA-Z0-9_.:-]{1,100}',max:100,help:'For example: premium, downloads, or feature:reports.' });
function createUser() {
  if(!isOwner)return;
  openModal('Create a user','Choose an application user, a website user, or a reseller. Resellers can only issue license keys and reset customer HWIDs in the selected application.',
    field('account_type','Account type','select',currentView==='website_users'?'website':'application',{choices:currentView==='website_users'?[['website','Website user'],['reseller','Reseller account']]:[['application','Application (EXE)'],['reseller','Reseller account']]})+
    field('username','Username','text','',{pattern:'[A-Za-z0-9_.-]{3,64}',max:64})+field('password','Password','password','',{help:'Application passwords have no length rule. Website and reseller passwords require 12 to 128 characters.'})+
    `<div id="reseller-create-options" hidden>${field('max_days','Maximum license duration (days)','number',30,{numberMax:999,help:'The reseller can create hardware-bound keys up to this duration in the selected application.'})}</div>`, 'Create user', async (form) => {
      const account_type = form.get('account_type');
      if(account_type==='reseller'){
        await api('/v1/admin/resellers','POST',{username:form.get('username'),password:form.get('password'),max_days:Number(form.get('max_days'))});
        $('#modal').close();$('#modal-content').replaceChildren();pageCache.clear();
        toast('Reseller account created. They can sign in through the website.');
        await loadPage('resellers',true);return;
      }
      await api('/v1/admin/users','POST',{username:form.get('username'),password:form.get('password'),account_type});
      await changed(account_type === 'application' ? 'Application account created. Sign in to the EXE and activate a license.' : 'User created. Grant website access before they can sign in.');
    });
  const type = $('#modal [name=account_type]'), password = $('#modal [name=password]');
  const syncPasswordRule=() => {
    const reseller=type.value==='reseller';
    $('#reseller-create-options').hidden=!reseller;
    $('#modal [name=max_days]').disabled=!reseller;
    $('#modal-form [type=submit]').textContent=reseller?'Create reseller':'Create user';
    if (type.value === 'application') { password.removeAttribute('minlength'); password.removeAttribute('maxlength'); }
    else { password.minLength = 12; password.maxLength = 128; }
  };
  type.addEventListener('change',syncPasswordRule);syncPasswordRule();
}
function manageUser(row) {
  openModal(`Manage ${row.username}`,row.console_only||row.role==='admin'?'Only the owner can manage website accounts and grant website login.':'Manage this application customer\'s status, subscription and password expiration.',
    field('status','Account status','select',row.status,{choices:[['active','Active'],['suspended','Suspended'],['revoked','Revoked']]})+
    (row.is_owner ? '<p class=muted>This is the website owner.</p>' : !row.console_only && row.role !== 'admin' ? '<p class=muted>This account signs in to the EXE only. Activate a license to unlock protected resources.</p>' : field('web_access','Approve login to this website','checkbox',!!row.web_approved,{help:'Grant or remove website login. Removing access also revokes existing sessions.'}))+
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
  openModal(`Website access for ${row.username}`,'Approved accounts can manage application customers. Only the owner can create accounts and grant website access.',
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
  const applicationId = activeApplication, applicationName = applications.find(app=>app.id===applicationId)?.name || 'Application';
  openModal('Create a license',`Create a key for ${applicationName}. Keys work only in this application.`,
    field('days','License duration (days)','number',30,{numberMax:999,help:'Enter 1–999 days. The key automatically expires this many days after creation.'})+
    field('hardware','Require hardware binding','checkbox',false,{help:'An optional anti-abuse measure. Hardware IDs can be spoofed.'}),'Create license',async (form) => {
      const days = Number(form.get('days'));
      if (!Number.isInteger(days) || days < 1 || days > 999) throw new Error('Enter a whole number from 1 to 999 days.');
      if (activeApplication !== applicationId) throw new Error('The selected application changed. Open Create license again.');
      const data = await requests.request('/v1/admin/licenses?application_id='+encodeURIComponent(applicationId),'POST',{days,hardware_bound:form.get('hardware') === 'on'});
      if (activeApplication !== applicationId) return;
      await loadPage('licenses',true);
      if (activeApplication !== applicationId) return;
      openModal('Your license is ready',`Application: ${applicationName}. This key is at the top of its license list.`,`<div class="secret-key" id="new-license-key">${esc(data.key)}</div><p>Deliver it privately to its intended user. Activation binds the key to one account.</p>`, 'Done', async () => { $('#modal').close(); $('#modal-content').replaceChildren(); });
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
  if (!row) {
    openModal('Upload a file','Choose a file. Its file ID is generated automatically. Downloads require the premium permission.',
      field('upload','File','file','',{help:'Choose a nonempty file up to 64 MiB.'}), 'Upload', async (form) => {
        const file = form.get('upload');
        if (!(file instanceof File) || !file.name || !file.size) throw new Error('Choose a nonempty file.');
        if (file.size > 67108864) throw new Error('Choose a file no larger than 64 MiB.');
        const data = await api('/v1/admin/files','POST',file);
        await changed('File uploaded.');
        showDownloadCode(data);
      });
    return;
  }
  openModal(row ? 'Manage protected file' : 'Register a file','Upload a private file or register a filename already in hosted storage.',
    (row ? `<div class="field"><label>File ID</label><code class="code-pill">${esc(row.id)}</code></div>` : field('id','File ID','text','',{pattern:'[a-zA-Z0-9_.-]{1,100}',max:100,help:'The identifier used by your C++ application.'}))+
    field('storage','Storage filename','text',row?.storage_name || '',{pattern:'[a-zA-Z0-9_.-]{1,128}',max:128,help:'A filename only, for example release.zip.'})+
    field('upload','Upload private file (optional)','file','',{optional:true,help:'Upload up to 64 MiB to private hosted storage. Use the storage filename above.'})+
    permissionField(row?.permission)+field('limit','Maximum file size (bytes)','number',row?.max_bytes || 67108864,{help:'The C++ SDK accepts downloads up to 64 MiB (67108864 bytes).'})+
    field('enabled','Enable authorized downloads','checkbox',row ? !!row.enabled : true),'Save file',async (form) => {
      const upload = form.get('upload');
      if (upload instanceof File && upload.name) {
        if (upload.size > 67108864) throw new Error('Choose a file no larger than 64 MiB.');
        await api(`/v1/admin/storage/${encodeURIComponent(form.get('storage'))}`,'PUT',upload);
      }
      await api(`/v1/admin/files/${encodeURIComponent(row?.id || form.get('id'))}`,'PUT',{storage_name:form.get('storage'),permission:form.get('permission'),max_bytes:Number(form.get('limit')),enabled:form.get('enabled') === 'on'});
      await changed('Protected file updated.');
    });
}
function showDownloadCode(row) {
  const code = `auto file = auth.downloadfile(${JSON.stringify(row.id)}, "download.bin");`;
  openModal('Your file is ready','Use this file ID after signing in through the C++ SDK. The result contains success and bytes.',
    `<div class="field"><label>File ID</label><input readonly value="${esc(row.id)}"></div><div class="field"><label>C++ download</label><textarea readonly>${esc(code)}</textarea></div><p>Required permission: ${esc(row.permission)}. Use Manage to change download access.</p>`,
    'Done', async () => { $('#modal').close(); });
}
function confirmAction(title, description, action) {
  openModal(title,description,'<p>This change will take effect on the server immediately.</p>','Confirm',async () => { await action(); await changed('Change applied.'); });
}
function pageAction() {
  if (currentView === 'resellers') editReseller();
  else if (currentView === 'reseller_licenses') createResellerLicense();
  else if (currentView === 'applications') editApplication();
  else if (currentView === 'overview' || currentView === 'users' || currentView === 'website_users') createUser();
  else if (currentView === 'licenses') createLicense();
  else if (currentView === 'variables') editVariable();
  else if (currentView === 'files') editFile();
}

async function loadApplications(preferred = activeApplication) {
  const data=await api('/v1/admin/applications');
  applications=data.applications;
  activeApplication=applications.some(app=>app.id===preferred)?preferred:data.default_application_id;
  const select=$('#application-selector');
  select.innerHTML=applications.map(app=>`<option value="${esc(app.id)}">${esc(app.name)}${app.status==='active'?'':' (disabled)'}</option>`).join('');
  select.value=activeApplication;select.disabled=false;
}
function editApplication(row) {
  openModal(row?'Manage application':'Create application','EXE accounts and keys belong to one application. Approved website accounts can create and manage applications.',
    field('name','Application name','text',row?.name||'',{max:64,help:'For example: External or Spoofer. An Application ID is generated automatically.'})+
    (row?field('status','Status','select',row.status,{choices:[['active','Active'],['disabled','Disabled — block EXE access']]})+`<p>Application ID: <code>${esc(row.id)}</code></p>`:''),
    row?'Save application':'Create application',async form=>{
      const data=await api(row?`/v1/admin/applications/${encodeURIComponent(row.id)}`:'/v1/admin/applications',row?'PUT':'POST',{name:form.get('name'),...(row?{status:form.get('status')}:{})});
      pageCache.clear();await loadApplications(row?activeApplication:data.id);
      await changed(row?'Application updated.':'Application created and selected.');
      if (!row) {
        openModal('Application created',`${data.name} is selected. New users, licenses, variables and files will belong to this application.`,
          `<div class="field"><label for="new-application-id">Application ID</label><input id="new-application-id" readonly value="${esc(data.id)}"></div><button class="button" id="copy-new-application-id" type="button">Copy Application ID</button><p>Use this ID in your C++ SDK. Switch products using the Application selector in the sidebar.</p>`,
          'Done',async()=>$('#modal').close());
        $('#copy-new-application-id').addEventListener('click',async()=>{
          try { await navigator.clipboard.writeText(data.id); toast('Application ID copied.'); }
          catch { $('#new-application-id').select(); toast('Select and copy the Application ID.'); }
        });
      }
    });
}
function userOperation(row,operation) {
  const label=operation==='reset-hwid'?'Reset HWID':operation==='ban'?'Ban':'Unban';
  confirmAction(`${label}: ${row.username}?`,operation==='reset-hwid'?'Clear this account’s device binding and revoke its sessions. The next login binds the new SID.':operation==='ban'?'Block this application account and revoke its active sessions.':'Allow this account to sign in again. Existing license expiry still applies.',
    ()=>api(`/v1/admin/users/${encodeURIComponent(row.id)}/${operation}`,'POST',{}));
}
function lookupUser() {
  openModal('Find application user','Find an account in the selected application by username.',field('username','Username','text','',{max:64}),'Find user',async form=>{
    const data=await api('/v1/admin/users/lookup?username='+encodeURIComponent(form.get('username'))),row=data.user;
    openModal(row.username,`Status: ${row.status}. HWID: ${row.hwid_bound?'bound':'not bound'}.`,
      '<div class="row-actions"><button type=button data-user-operation="reset-hwid">Reset HWID</button><button type=button data-user-operation="'+(row.status==='active'?'ban':'unban')+'">'+(row.status==='active'?'Ban':'Unban')+'</button></div>',
      'Done',async()=>$('#modal').close());
    $('#modal').querySelectorAll('[data-user-operation]').forEach(button=>button.addEventListener('click',()=>userOperation(row,button.dataset.userOperation)));
  });
}
$('#application-selector').addEventListener('change',async event=>{
  pageController?.abort();ticket++;pageCache.clear();records=[];
  $('#modal').close(); $('#modal-content').replaceChildren();
  activeApplication=event.target.value;
  await loadPage(currentView,true);
});

async function finishSignIn(data){
    acceptTokens(data);
    const me = data.user || await api('/v1/admin/session');
    if (typeof me.username !== 'string' || typeof me.user_id !== 'string' || typeof me.is_owner !== 'boolean') throw new ApiError('invalid_response');
    isOwner = me.is_owner === true;isReseller=me.role==='reseller';
    document.body.dataset.role=isReseller?'reseller':'admin';
    document.querySelectorAll('.nav-item').forEach(item=>{item.hidden=isReseller?!['reseller_licenses','reseller_hwid'].includes(item.dataset.view):['reseller_licenses','reseller_hwid'].includes(item.dataset.view);});
    $('.nav-label-second').hidden=isReseller;
    $('#workspace-label').textContent=isReseller?'RESELLER WORKSPACE':'CONTROL CENTER';
    $('#workspace-crumb').textContent=isReseller?'Reseller workspace':'Control center';
    $('#sidebar-note-title').textContent=isReseller?'Your customer desk.':'Built for your next release.';
    $('#sidebar-note-description').textContent=isReseller?'Issue license keys and help customers reconnect.':'Manage access, deliver updates, and keep every product in sync.';
    $('.nav-item[data-view=website_users]').hidden = !isOwner;
    $('.profile small').textContent = isReseller?'Reseller':isOwner?'Owner':'Website administrator';
    $('#profile-name').textContent = me.username; $('#avatar').textContent = me.username.charAt(0).toUpperCase();
    $('#login-screen').hidden = true; $('#console').hidden = false;
    await loadApplications();
    await loadPage(isReseller?'reseller_licenses':'overview',true);
}
$('#login-form').addEventListener('submit', async (event) => {
  event.preventDefault(); const button = $('#login-form [type=submit]'); button.disabled = true;
  const buttonLabel = button.textContent;
  button.textContent = 'Signing in…'; $('#login-form').setAttribute('aria-busy','true');
  $('#login-error').hidden = true;
  const username = $('#username').value.trim(); const password = $('#password').value;
  const remember = $('#remember-session').checked;
  $('#password').value = '';
  try {
    signedOut();
    const data = await wire('/v1/admin/login','POST',{username,password,remember});
    rememberedSession=remember;
    await finishSignIn(data);
  } catch (error) { signedOut(error.message); }
  finally { button.disabled = false; button.textContent = buttonLabel; $('#login-form').removeAttribute('aria-busy'); }
});
async function restoreSignIn(){
  if(openedRecoveryLink)return;
  const button=$('#login-form [type=submit]');button.disabled=true;button.textContent='Checking session...';
  try{const data=await wire('/v1/admin/resume','POST',{});rememberedSession=true;await finishSignIn(data);}
  catch{if(access)signedOut();}
  finally{button.disabled=false;button.textContent='Sign in';}
}
restoreSignIn();
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
$('#modal').addEventListener('close', () => { if (!$('#modal').open) $('#modal-content').replaceChildren(); });
document.addEventListener('input',(event) => { if (event.target.id === 'table-search') tableBody(event.target.value); });
document.addEventListener('click',async (event) => {
  if (!(event.target instanceof Element)) return;
  const button = event.target.closest('button'); if (!button) return;
  if (button.hasAttribute('data-close')) { $('#modal').close(); return; }
  if (button.dataset.view) {
    if (button.dataset.view === currentView && $('#page-content').getAttribute('aria-busy') === 'true') return;
    loadPage(button.dataset.view); return;
  }
  if (button.dataset.command === 'lookup-user') { lookupUser(); return; }
  if (button.dataset.command === 'create-user') { createUser(); return; }
  if (button.id === 'previous-page') { offset = Math.max(0,offset-100); loadPage(); return; }
  if (button.id === 'next-page') { offset += 100; loadPage(); return; }
  if (!button.dataset.rowAction) return;
  const row = records.find((item) => String(item.id) === button.dataset.id); if (!row) return;
  const id = encodeURIComponent(row.id); const action = button.dataset.rowAction;
  if(action==='edit-reseller')editReseller(row);
  else if(action==='copy-license')navigator.clipboard.writeText(row.key).then(()=>toast('License key copied.')).catch(()=>toast('Select the license key to copy it.'));
  else if (action === 'copy-application') { navigator.clipboard.writeText(row.id).then(()=>toast('Application ID copied.')).catch(()=>openModal('Application ID','Copy this ID into your C++ application.',field('application','Application ID','text',row.id),'Done',async()=>$('#modal').close())); }
  else if (action === 'edit-application') editApplication(row);
  else if (action === 'reset-user-hwid') userOperation(row,'reset-hwid');
  else if (action === 'ban-user') userOperation(row,'ban');
  else if (action === 'unban-user') userOperation(row,'unban');
  else if (action === 'download-code') showDownloadCode(row);
  else if (action === 'permissions') managePermissions(row);
  else if (action === 'extend') extendLicense(row);
  else if (action === 'delete-user') confirmAction(`Delete ${row.username}?`,'This permanently deletes the account and personal variables, ends all its sessions, and revokes its assigned licenses.',() => api(`/v1/admin/users/${id}`,'DELETE'));
  else if (action === 'reset-hwid') confirmAction('Reset hardware binding?','The assigned account keeps this license. Its application sessions will be signed out, and the next activation can bind a new device.',() => api(`/v1/admin/licenses/${id}/reset-hwid`,'POST',{}));
  else if (action === 'freeze') { button.disabled = true; try { await api(`/v1/admin/licenses/${id}/freeze`,'POST'); await loadPage(); } catch(error) { toast(error.message); } finally { button.disabled = false; } }
  else if (action === 'revoke') confirmAction('Revoke and delete this license?','This permanently deletes the key from the license list. It will no longer authorize access.',() => api(`/v1/admin/licenses/${id}`,'DELETE'));
  else if (action === 'delete') confirmAction('Delete this variable?',`Remove ${row.name} from its current scope.`,() => api(`/v1/admin/variables/${id}`,'DELETE'));
  else if (action === 'edit') { if ((currentView === 'users' || currentView === 'website_users')) manageUser(row); else if (currentView === 'variables') editVariable(row); else if (currentView === 'files') editFile(row); }
});


function editReseller(row){
  openModal(row?'Manage reseller':'Add reseller account',`This account can only create license keys and reset customer HWIDs in the selected application.`,
    (row?`<p><strong>${esc(row.username)}</strong></p>`+field('status','Account status','select',row.status,{choices:[['active','Active'],['suspended','Suspended']]}):field('username','Reseller username','text','',{pattern:'[A-Za-z0-9_.-]{3,64}',max:64})+field('password','Password','password'))+
    field('max_days','Maximum license duration (days)','number',row?.max_days||30,{numberMax:999,help:'Resellers can create hardware-bound premium keys up to this duration. Updating an account signs out its existing sessions.'}),row?'Save changes':'Create reseller',async form=>{
      const payload={max_days:Number(form.get('max_days')),...(row?{status:form.get('status')}:{username:form.get('username'),password:form.get('password')})};
      await api('/v1/admin/resellers'+(row?'/'+encodeURIComponent(row.id):''),row?'PUT':'POST',payload);
      await changed(row?'Reseller updated.':'Reseller created. They can sign in using the website login.');
    });
}
function createResellerLicense(){
  const input=$('#quick-license-days');
  if(input){input.focus();input.select();$('#quick-license-form').scrollIntoView({behavior:'smooth',block:'center'});}
}
function updateResellerSummary(){
  const count=$('.table-toolbar h2 span'),pagination=$('.table-footer>span'),next=$('#next-page');
  if(count)count.textContent=String(records.length)+(records.length===100?'+':'');
  if(pagination)pagination.textContent=`Page ${Math.floor(offset/100)+1} / ${records.length} records loaded`;
  if(next)next.disabled=records.length<100;
  const now=Date.now()/1000;
  for(const [id,count] of [['reseller-active',records.filter(r=>!r.revoked&&r.expires_at>now).length],['reseller-unassigned',records.filter(r=>!r.revoked&&r.expires_at>now&&!r.username).length],['reseller-listed',records.length]]){
    const element=$('#'+id);if(element)element.textContent=count.toLocaleString();
  }
}
function renderResellerLicenses(data){
  resellerMaxDays=data.max_days;records=data.reseller_licenses;
  const presets=[1,7,30,90].filter(days=>days<=resellerMaxDays),defaultDays=Math.min(30,resellerMaxDays);
  $('#page-content').innerHTML=`<section class="reseller-workbench"><div class="workbench-intro"><span class="eyebrow">YOUR CUSTOMER DESK</span><h2>From key to customer.<br><span>Without the extra steps.</span></h2><p>Issue a key, copy it, and keep moving. Your application and SID binding are already set.</p><div class="workbench-tags"><span>${icon('shield')}SID binding</span><span>${icon('key')}Premium access</span><span>Up to ${esc(resellerMaxDays)} days</span></div></div><section class="card quick-license-card"><div class="quick-card-heading"><span class="quick-symbol">${icon('plus')}</span><div><h3>Create a license</h3><p>Ready to share as soon as it's created.</p></div></div><form id="quick-license-form"><label for="quick-license-days">Access duration</label><div class="duration-presets">${presets.map(days=>`<button type="button" data-duration="${days}" aria-pressed="${days===defaultDays}" class="duration-preset ${days===defaultDays?'selected':''}">${days===1?'1 day':days+' days'}</button>`).join('')}</div><div class="quick-create-row"><div class="duration-input"><input id="quick-license-days" name="days" type="number" min="1" max="${esc(resellerMaxDays)}" value="${defaultDays}" required aria-label="Custom license duration in days"><span>days</span></div><button class="button primary" type="submit">${icon('plus')}Create key</button></div><p id="quick-license-error" class="form-error" role="alert" hidden></p></form><div id="quick-license-result" class="issued-result" role="status" hidden><span class="eyebrow">KEY CREATED</span><div class="issued-key-row"><input id="issued-license-key" readonly aria-label="New license key"><button type="button" class="button" id="copy-issued-key">${icon('files')}Copy key</button></div><p>Share this key with your customer.</p></div></section></section><div class="reseller-summary"><div><span class="summary-dot"></span><strong id="reseller-active">0</strong><span>active on this page</span></div><div><strong id="reseller-unassigned">0</strong><span>ready to assign</span></div><div><strong id="reseller-listed">0</strong><span>keys on this page</span></div><button class="text-button" data-view="reseller_hwid">Reset a customer's HWID ${icon('refresh')}</button></div>${renderTable()}`;
  tableBody();updateResellerSummary();
  const form=$('#quick-license-form'),input=$('#quick-license-days');
  const syncPresets=()=>document.querySelectorAll('[data-duration]').forEach(button=>{const selected=Number(button.dataset.duration)===Number(input.value);button.classList.toggle('selected',selected);button.setAttribute('aria-pressed',String(selected));});
  document.querySelectorAll('[data-duration]').forEach(button=>button.addEventListener('click',()=>{input.value=button.dataset.duration;syncPresets();}));
  input.addEventListener('input',syncPresets);
  $('#copy-issued-key').addEventListener('click',async()=>{
    const value=$('#issued-license-key').value;
    try{await navigator.clipboard.writeText(value);toast('License key copied.');}catch{$('#issued-license-key').select();toast('Select and copy the key.');}
  });
  form.addEventListener('submit',async event=>{
    event.preventDefault();const button=form.querySelector('[type=submit]'),error=$('#quick-license-error'),result=$('#quick-license-result'),keyInput=$('#issued-license-key'),expectedEpoch=epoch;
    if(button.disabled)return;button.disabled=true;button.textContent='Creating...';error.hidden=true;
    try{
      const data=await api('/v1/admin/reseller/licenses','POST',{days:Number(input.value)});
      resellerRevision++;
      if(!form.isConnected||epoch!==expectedEpoch)return;
      if(offset===0){records=[data.license,...records.filter(row=>row.id!==data.id)].slice(0,100);tableBody($('#table-search')?.value||'');updateResellerSummary();}
      keyInput.value=data.key;result.hidden=false;toast('License key ready to share.');
    }catch(failure){if(form.isConnected){error.textContent=failure.message;error.hidden=false;}}
    finally{if(button.isConnected){button.disabled=false;button.innerHTML=icon('plus')+'Create key';}}
  });
}
function renderResellerHwid(){
  $('#page-content').innerHTML=`<div class="reseller-support-grid"><section class="card support-card"><span class="support-symbol">${icon('shield')}</span><span class="eyebrow">HELP YOUR CUSTOMER RECONNECT</span><h2>A fresh start.<br>Same license.</h2><p>Reset the Windows account binding using their username. Their subscription and license expiry stay exactly as they are.</p><form id="reseller-hwid-form"><label for="reset-username">Customer username</label><input id="reset-username" name="username" placeholder="Enter their exact username" autocomplete="off" required pattern="[A-Za-z0-9_.-]{3,64}" maxlength="64"><button class="button primary" id="review-hwid-reset" type="submit">${icon('refresh')}Review HWID reset</button><div id="hwid-reset-confirmation" class="inline-confirmation" hidden><strong id="hwid-reset-question"></strong><p>This signs out the customer and clears their existing SID binding.</p><div><button type="button" class="button primary" id="confirm-hwid-reset">Confirm reset</button><button type="button" class="button" id="cancel-hwid-reset">Cancel</button></div></div><p id="reset-feedback" class="inline-feedback" role="status" hidden></p></form></section><section class="card support-explainer"><span class="eyebrow">THREE SIMPLE STEPS</span><h3>Back to their product.</h3><ol><li><strong>Find the username</strong><span>Use the exact application username supplied by your customer.</span></li><li><strong>Confirm the reset</strong><span>Current sessions end and the old binding is cleared.</span></li><li><strong>Ask them to sign in</strong><span>Their next login binds the new Windows account SID.</span></li></ol><div class="support-return"><span>Need a new license instead?</span><button class="button" data-view="reseller_licenses">${icon('key')}Open license desk</button></div></section></div>`;
  const form=$('#reseller-hwid-form'),input=$('#reset-username'),confirmation=$('#hwid-reset-confirmation'),feedback=$('#reset-feedback'),review=$('#review-hwid-reset');
  let reviewedUsername='';
  const cancel=()=>{confirmation.hidden=true;review.hidden=false;reviewedUsername='';};
  input.addEventListener('input',()=>{cancel();feedback.hidden=true;});
  $('#cancel-hwid-reset').addEventListener('click',cancel);
  form.addEventListener('submit',event=>{
    event.preventDefault();reviewedUsername=input.value.trim();
    $('#hwid-reset-question').textContent=`Reset HWID for ${reviewedUsername}?`;
    confirmation.hidden=false;review.hidden=true;feedback.hidden=true;$('#confirm-hwid-reset').focus();
  });
  $('#confirm-hwid-reset').addEventListener('click',async()=>{
    const button=$('#confirm-hwid-reset'),cancelButton=$('#cancel-hwid-reset'),expectedEpoch=epoch;
    if(button.disabled||!reviewedUsername)return;
    const username=reviewedUsername;button.disabled=true;cancelButton.disabled=true;input.disabled=true;button.textContent='Resetting...';
    try{
      const result=await api('/v1/admin/reseller/reset-hwid','POST',{username});
      if(form.isConnected&&expectedEpoch===epoch){feedback.textContent=`${result.username}: ${result.message}`;feedback.classList.remove('error');feedback.hidden=false;cancel();}
    }catch(error){if(form.isConnected){feedback.textContent=error.message;feedback.classList.add('error');feedback.hidden=false;}}
    finally{if(form.isConnected){button.disabled=false;cancelButton.disabled=false;input.disabled=false;button.textContent='Confirm reset';}}
  });
}
