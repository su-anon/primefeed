/* PrimeFeed / CipherDeck — shared API client.
 *
 * Talks to the FastAPI backend. The token is kept in localStorage under
 * 'pf_session' and sent as the 'x-session-token' header. All endpoints are
 * same-origin ('/api/...') since the pages are served by the same process,
 * but functions use an overridable base in case pages are opened standalone.
 */

const PF_API = (localStorage.getItem('pf_api_base') || '').replace(/\/+$/, '');
const PF_SESSION_KEY = 'pf_session';
const PF_TOTP_KEY = 'pf_totp_secrets';   // username -> base32 secret (dev convenience)

/* ---- session helpers ---------------------------------------------------- */

function pfGetSession() { return localStorage.getItem(PF_SESSION_KEY); }
function pfSetSession(token) { localStorage.setItem(PF_SESSION_KEY, token); }
function pfClearSession() { localStorage.removeItem(PF_SESSION_KEY); }
function pfRequireAuth() {
  if (!pfGetSession()) { location.href = '/login/'; return false; }
  return true;
}

/* ---- low-level fetch ---------------------------------------------------- */

async function pfFetch(path, method, body) {
  const headers = { 'Content-Type': 'application/json' };
  const token = pfGetSession();
  if (token) headers['x-session-token'] = token;
  let res;
  try {
    res = await fetch(PF_API + path, {
      method: method || 'GET',
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch (e) {
    throw new Error('Network error — is the backend running?');
  }
  let data = {};
  try { data = await res.json(); } catch (e) { /* non-JSON body */ }
  if (!res.ok) {
    const msg = (typeof data.detail === 'string') ? data.detail
      : (Array.isArray(data.detail) && data.detail.length) ? data.detail[0].msg
      : ('HTTP ' + res.status);
    throw new Error(msg);
  }
  return data;
}

/* ---- auth --------------------------------------------------------------- */

const pfLogin = (username, password) => pfFetch('/api/auth/login', 'POST', { username, password });
const pfLogin2FA = (ticket, code) => pfFetch('/api/auth/login/2fa', 'POST', { ticket, code });
const pfRegister = (payload) => pfFetch('/api/auth/register', 'POST', payload);
const pfLogoutAPI = () => pfFetch('/api/auth/logout', 'POST', { session_token: pfGetSession() });
const pfMe = () => pfFetch('/api/auth/me');

/* ---- feed --------------------------------------------------------------- */

const pfFeed = (limit, offset) => pfFetch(`/api/posts?limit=${limit}&offset=${offset}`);
const pfCreatePost = (content) => pfFetch('/api/posts', 'POST', { content });
const pfDeletePost = (id) => pfFetch(`/api/posts/${id}`, 'DELETE');
const pfGetPost = (id) => pfFetch(`/api/posts/${id}`);

/* ---- dev helpers -------------------------------------------------------- */

const pfDevTotp = (username) => pfFetch(`/api/dev/totp/${encodeURIComponent(username)}`);

/* ---- small UI helpers --------------------------------------------------- */

function pfStatus(elId, msg, ok) {
  const el = document.getElementById(elId);
  if (!el) return;
  el.textContent = msg;
  el.classList.remove('hidden', 'pf-ok', 'pf-err', 'text-secondary', 'text-error');
  void el.offsetHeight; // restart animation
  if (ok === false) {
    el.classList.add('pf-err');
    el.classList.add('text-error');
  } else if (ok === true) {
    el.classList.add('pf-ok');
    el.classList.add('text-secondary');
  }
}

function pfSaveTotpSecret(username, secret) {
  try {
    const m = JSON.parse(localStorage.getItem(PF_TOTP_KEY) || '{}');
    m[username] = secret;
    localStorage.setItem(PF_TOTP_KEY, JSON.stringify(m));
  } catch (e) { /* ignore */ }
}

function pfGetTotpSecret(username) {
  try {
    const m = JSON.parse(localStorage.getItem(PF_TOTP_KEY) || '{}');
    return m[username] || null;
  } catch (e) { return null; }
}

function timeAgo(ts) {
  const s = Math.floor(Date.now() / 1000) - ts;
  if (s < 60) return 'just now';
  if (s < 3600) return Math.floor(s / 60) + ' min ago';
  if (s < 86400) return Math.floor(s / 3600) + ' hr ago';
  return Math.floor(s / 86400) + ' days ago';
}

/* ---- comments ----------------------------------------------------------- */

const pfComments = (postId) => pfFetch(`/api/posts/${postId}/comments`);
const pfAddComment = (postId, content) => pfFetch(`/api/posts/${postId}/comments`, 'POST', { content });
const pfDeleteComment = (id) => pfFetch(`/api/comments/${id}`, 'DELETE');

/* ---- messaging ---------------------------------------------------------- */

const pfUsers = () => pfFetch('/api/users');
const pfSendMessage = (recipient_id, content) => pfFetch('/api/messages', 'POST', { recipient_id, content });
const pfInbox = () => pfFetch('/api/messages/inbox');
const pfSent = () => pfFetch('/api/messages/sent');
const pfMarkRead = (id) => pfFetch(`/api/messages/${id}/read`, 'POST', {});

/* ---- account / settings ------------------------------------------------- */

const pfChangePassword = (current_password, new_password) =>
  pfFetch('/api/auth/change-password', 'POST', { current_password, new_password });
const pfProfileGet = () => pfFetch('/api/profile');
const pfProfileUpdate = (email, name, contact) => pfFetch('/api/profile', 'PUT', { email, name, contact });

/* ---- admin governance --------------------------------------------------- */

const pfAdminUsers = () => pfFetch('/api/admin/users');
const pfAdminSuspend = (id) => pfFetch(`/api/admin/users/${id}/suspend`, 'POST', {});
const pfAdminRestore = (id) => pfFetch(`/api/admin/users/${id}/restore`, 'POST', {});
const pfAdminElevate = (id) => pfFetch(`/api/admin/users/${id}/elevate`, 'POST', {});
const pfAdminReset2FA = (id) => pfFetch(`/api/admin/users/${id}/reset-2fa`, 'POST', {});
const pfAdminResetPassword = (id) => pfFetch(`/api/admin/users/${id}/reset-password`, 'POST', {});
const pfAdminRotate = () => pfFetch('/api/admin/rotate-keys', 'POST', {});
const pfAdminIntegrity = (limit = 100) => pfFetch(`/api/admin/integrity-log?limit=${limit}`);
const pfAdminKeys = () => pfFetch('/api/admin/key-summary');
const pfAdminPosts = () => pfFetch('/api/admin/posts');
const pfAdminDeletePost = (id) => pfFetch(`/api/admin/posts/${id}`, 'DELETE');

/* ---- shared nav injection ----------------------------------------------- */
/* Feed / Messages / Settings / Admin are now hard-coded in the header. This
 * helper only: fills the username + avatar, reveals Admin for admins, and
 * adds a Sign out link. */
function pfInjectNav(me) {
  const uname = (me && me.username) || 'user';
  const uEl = document.getElementById('nav-username');
  if (uEl) uEl.textContent = '@' + uname;
  const aEl = document.getElementById('nav-avatar');
  if (aEl) aEl.textContent = uname.slice(0, 2).toUpperCase();

  if (me && me.role === 'admin') {
    const adminLink = document.getElementById('nav-admin');
    if (adminLink) adminLink.classList.remove('hidden');
  }

  const acc = [...document.querySelectorAll('a')].find(a => a.getAttribute('title') === 'Settings / Profile');
  const wrap = acc ? acc.parentElement : null;
  if (!wrap || document.getElementById('pf-nav-menu')) return;

  const signout = document.createElement('a');
  signout.href = '#';
  signout.id = 'pf-nav-menu';
  signout.textContent = 'Sign out';
  signout.className = 'ml-2 px-2 py-1 rounded border border-outline-variant hover:bg-surface-container hover:text-error text-[11px] font-mono text-on-surface-variant transition-colors';
  signout.onclick = async (e) => {
    e.preventDefault();
    try { await pfLogoutAPI(); } catch (_) {}
    pfClearSession();
    location.href = '/login/';
  };
  wrap.appendChild(signout);
}

/* Expose on window for inline handlers */
window.pfFetch = pfFetch;
window.pfGetSession = pfGetSession;
window.pfSetSession = pfSetSession;
window.pfClearSession = pfClearSession;
window.pfRequireAuth = pfRequireAuth;
window.pfLogin = pfLogin;
window.pfLogin2FA = pfLogin2FA;
window.pfRegister = pfRegister;
window.pfLogoutAPI = pfLogoutAPI;
window.pfMe = pfMe;
window.pfFeed = pfFeed;
window.pfCreatePost = pfCreatePost;
window.pfDeletePost = pfDeletePost;
window.pfGetPost = pfGetPost;
window.pfDevTotp = pfDevTotp;
window.pfStatus = pfStatus;
window.pfSaveTotpSecret = pfSaveTotpSecret;
window.pfGetTotpSecret = pfGetTotpSecret;
window.timeAgo = timeAgo;
window.pfComments = pfComments;
window.pfAddComment = pfAddComment;
window.pfDeleteComment = pfDeleteComment;
window.pfUsers = pfUsers;
window.pfSendMessage = pfSendMessage;
window.pfInbox = pfInbox;
window.pfSent = pfSent;
window.pfMarkRead = pfMarkRead;
window.pfChangePassword = pfChangePassword;
window.pfProfileGet = pfProfileGet;
window.pfProfileUpdate = pfProfileUpdate;
window.pfAdminUsers = pfAdminUsers;
window.pfAdminSuspend = pfAdminSuspend;
window.pfAdminRestore = pfAdminRestore;
window.pfAdminElevate = pfAdminElevate;
window.pfAdminReset2FA = pfAdminReset2FA;
window.pfAdminResetPassword = pfAdminResetPassword;
window.pfAdminRotate = pfAdminRotate;
window.pfAdminIntegrity = pfAdminIntegrity;
window.pfAdminKeys = pfAdminKeys;
window.pfAdminPosts = pfAdminPosts;
window.pfAdminDeletePost = pfAdminDeletePost;
window.pfInjectNav = pfInjectNav;
window.esc = (s) => String(s || '').replace(/[&<>"']/g,
  c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));