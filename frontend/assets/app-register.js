/* CipherDeck register page integration.
 * Collects handle + encrypted-field email + passphrases, calls /api/auth/register,
 * then reveals the returned TOTP secret and links to login.
 */

function pfEnsureStatusR() {
  if (document.getElementById('pf-msg')) return;
  const d = document.createElement('div');
  d.id = 'pf-msg';
  d.className = 'mt-3 px-3 py-2 border border-outline-variant bg-surface-container-lowest text-xs font-mono';
  d.textContent = '';
  const form = [...document.querySelectorAll('form')].find(f => f.querySelector('#handle'));
  if (form) form.prepend(d);
}

(function () {
  const form = [...document.querySelectorAll('form')].find(f => f.querySelector('#handle'));
  if (!form) return;

  form.onsubmit = async (e) => {
    e.preventDefault();
    try {
      pfEnsureStatusR();
      const handle = document.getElementById('handle').value.trim();
      const email = document.getElementById('contact').value.trim();
      const pass = document.getElementById('passphrase').value;
      const confirm = document.getElementById('confirm-passphrase').value;

      if (!handle || !email || !pass) { pfStatus('pf-msg', 'Handle, contact and passphrase are required.', false); return; }
      if (pass !== confirm) { pfStatus('pf-msg', 'Passphrases do not match.', false); return; }

      // The backend generates RSA-3072 + ElGamal keypairs on registration. With
      // production key sizes this is the one-way cost of the pure-Python engine
      // (~2 min). In dev run with small keys (see README) for instant feedback.
      pfStatus('pf-msg', 'Provisioning keypairs (RSA-3072 / ElGamal 2048)… this can take up to ~2 min on first register.', true);

      const r = await pfRegister({
        username: handle,
        password: pass,
        email: email,
        name: handle,
        contact: '',
      });
      pfSaveTotpSecret(handle, r.totp_secret);   // remember for the dev auto-fill on login
      showResult(handle, r.totp_secret);
    } catch (err) {
      pfStatus('pf-msg', (err && err.message) || String(err), false);
    }
  };

  function showResult(handle, secret) {
    const old = document.getElementById('reg-result');
    if (old) old.remove();

    const box = document.createElement('div');
    box.id = 'reg-result';
    box.className = 'mt-4 border border-secondary bg-surface-container-low p-5';
    box.innerHTML =
      '<div class="flex items-center gap-2 text-secondary font-label-code text-label-code uppercase tracking-wider">' +
      '  <span class="material-symbols-outlined text-base">key</span><span>Identity Vault Provisioned</span>' +
      '</div>' +
      '<p class="text-sm text-on-surface-variant mt-2 leading-relaxed">Your RSA-3072 + ElGamal keypairs and RFC 6238 TOTP secret are ready. Add this secret to an authenticator app (Google Authenticator / Aegis), or use the <em>DEV auto-fill</em> helper on the login screen.</p>' +
      '<div class="mt-3 font-label-code text-label-code text-outline uppercase text-xs">TOTP Shared Secret</div>' +
      '<code class="block mt-1 px-3 py-2 bg-surface-container-highest border border-outline-variant font-label-code text-label-code text-primary break-all">' + secret + '</code>' +
      '<a href="/login/" class="mt-3 inline-flex items-center gap-2 bg-primary-container text-on-primary-fixed hover:bg-primary font-label-code text-label-code uppercase font-bold py-2.5 px-4 transition-colors duration-150">' +
      '  <span class="material-symbols-outlined text-sm">arrow_forward</span><span>Continue to Sign In</span>' +
      '</a>';
    form.after(box);
    pfStatus('pf-msg', ('Registered @' + handle + '. Add the TOTP secret, then sign in.'), true);
  }
})();