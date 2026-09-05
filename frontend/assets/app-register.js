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
      showResult(handle, r.totp_secret, r.totp_qr, r.totp_uri);
    } catch (err) {
      pfStatus('pf-msg', (err && err.message) || String(err), false);
    }
  };

  function showResult(handle, secret, qr, uri) {
    const old = document.getElementById('reg-result');
    if (old) old.remove();

    const box = document.createElement('div');
    box.id = 'reg-result';
    box.className = 'mt-4 border border-secondary bg-surface-container-low p-5';

    let qrHtml = '';
    if (qr) {
      qrHtml =
        '<div class="mt-4 flex flex-col sm:flex-row items-center gap-5 p-4 bg-surface-container-lowest border border-outline-variant">' +
        '  <div class="p-2 bg-white rounded border border-outline-variant flex-shrink-0 shadow-md">' +
        '    <img src="' + qr + '" alt="TOTP QR Code" class="w-40 h-40 block" />' +
        '  </div>' +
        '  <div class="flex-1 min-w-0 text-left">' +
        '    <div class="font-label-code text-label-code text-secondary font-bold uppercase text-xs flex items-center gap-1.5">' +
        '      <span class="material-symbols-outlined text-sm">qr_code_scanner</span>' +
        '      <span>Scan with Authenticator App</span>' +
        '    </div>' +
        '    <p class="text-xs text-on-surface-variant mt-1.5 leading-relaxed">' +
        '      Open Google Authenticator, Aegis, 1Password, or any RFC 6238 authenticator app and scan this QR code to enroll your second factor.' +
        '    </p>' +
        (uri ? '    <a href="' + uri + '" class="mt-2 inline-flex items-center gap-1 text-xs text-primary hover:underline font-label-code uppercase"><span class="material-symbols-outlined text-xs">open_in_new</span><span>Open in Authenticator app</span></a>' : '') +
        '    <div class="mt-3 font-label-code text-label-code text-outline uppercase text-[11px]">Manual Entry Key</div>' +
        '    <code class="block mt-1 px-2.5 py-1.5 bg-surface-container-highest border border-outline-variant font-label-code text-xs text-primary break-all select-all">' + secret + '</code>' +
        '  </div>' +
        '</div>';
    } else {
      qrHtml =
        '<div class="mt-3 font-label-code text-label-code text-outline uppercase text-xs">TOTP Shared Secret</div>' +
        '<code class="block mt-1 px-3 py-2 bg-surface-container-highest border border-outline-variant font-label-code text-label-code text-primary break-all">' + secret + '</code>';
    }

    box.innerHTML =
      '<div class="flex items-center gap-2 text-secondary font-label-code text-label-code uppercase tracking-wider">' +
      '  <span class="material-symbols-outlined text-base">key</span><span>Identity Vault Provisioned</span>' +
      '</div>' +
      '<p class="text-sm text-on-surface-variant mt-2 leading-relaxed">Your RSA-3072 + ElGamal keypairs and RFC 6238 TOTP credentials have been generated and secured.</p>' +
      qrHtml +
      '<div class="mt-4 pt-2 border-t border-outline-variant flex items-center justify-between">' +
      '  <a href="/login/" class="inline-flex items-center gap-2 bg-primary-container text-on-primary-fixed hover:bg-primary font-label-code text-label-code uppercase font-bold py-2.5 px-4 transition-colors duration-150">' +
      '    <span class="material-symbols-outlined text-sm">arrow_forward</span><span>Continue to Sign In</span>' +
      '  </a>' +
      '  <span class="font-telemetry-micro text-telemetry-micro text-outline uppercase">2FA_ENROLL_READY</span>' +
      '</div>';
    form.after(box);
    pfStatus('pf-msg', ('Registered @' + handle + '. Scan the QR code or add the secret, then sign in.'), true);
  }
})();