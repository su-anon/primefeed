/* CipherDeck settings page — encrypted profile edit + password change. */

(function () {
  if (!pfRequireAuth()) return;

  function status(elId, msg, ok) {
    const el = document.getElementById(elId);
    el.classList.remove('hidden', 'text-secondary', 'text-error');
    el.textContent = msg;
    el.classList.add(ok === false ? 'text-error' : 'text-secondary');
  }

  async function loadProfile() {
    try {
      const r = await pfProfileGet();
      const p = r.profile;
      document.getElementById('pf-email').value = p.email || '';
      document.getElementById('pf-name').value = p.name || '';
      document.getElementById('pf-contact').value = p.contact || '';
    } catch (err) {
      status('pf-prof-status', err.message, false);
    }
  }

  function bindSave() {
    document.getElementById('pf-prof-save').onclick = async () => {
      const email = document.getElementById('pf-email').value.trim();
      const name = document.getElementById('pf-name').value.trim();
      const contact = document.getElementById('pf-contact').value.trim();
      if (!email) { status('pf-prof-status', 'Email is required.', false); return; }
      try {
        await pfProfileUpdate(email, name, contact);
        status('pf-prof-status', 'Profile re-encrypted (RSA-3072) and saved.', true);
      } catch (err) {
        status('pf-prof-status', err.message, false);
      }
    };
  }

  function bindPwd() {
    document.getElementById('pf-pwd-change').onclick = async () => {
      const cur = document.getElementById('pf-pwd-cur').value;
      const nw = document.getElementById('pf-pwd-new').value;
      const cf = document.getElementById('pf-pwd-confirm').value;
      if (nw.length < 8) { status('pf-pwd-status', 'New password must be at least 8 characters.', false); return; }
      if (nw !== cf) { status('pf-pwd-status', 'Passwords do not match.', false); return; }
      try {
        await pfChangePassword(cur, nw);
        status('pf-pwd-status', 'Password changed. All sessions revoked — signing you out…', true);
        pfClearSession();
        setTimeout(() => { location.href = '/login/'; }, 1400);
      } catch (err) {
        status('pf-pwd-status', err.message, false);
      }
    };
  }

  async function init() {
    let me;
    try { me = await pfMe(); } catch (_) { pfClearSession(); location.href = '/login/'; return; }
    pfInjectNav(me);
    bindSave();
    bindPwd();
    await loadProfile();
  }
  init();
})();