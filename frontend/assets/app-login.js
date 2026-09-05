/* CipherDeck login page integration.
 * Flow: Sign In (handle+password) -> backend returns 2FA ticket -> TOTP verify -> session.
 */

window.pfTicket = null;   // pending 2FA ticket
window.pfUsername = null; // handle used at sign-in (for the dev TOTP helper)

function pfEnsureStatus() {
  if (document.getElementById('pf-msg')) return;
  const d = document.createElement('div');
  d.id = 'pf-msg';
  d.className = 'mt-3 px-3 py-2 border border-outline-variant bg-surface-container-lowest text-xs font-mono';
  d.textContent = '';
  const main = document.querySelector('main');
  if (main) main.prepend(d);
}

/* ---- Sign In form -------------------------------------------------------- */
(function () {
  const form = [...document.querySelectorAll('form')].find(f => f.querySelector('#signin-handle'));
  if (!form) return;
  form.onsubmit = async (e) => {
    e.preventDefault();
    try {
      pfEnsureStatus();
      const uname = document.getElementById('signin-handle').value.trim();
      const pwd = document.getElementById('signin-pwd').value;
      window.pfUsername = uname;
      pfStatus('pf-msg', 'Authenticating credentials (PBKDF2-HMAC-SHA256)…');
      const r = await pfLogin(uname, pwd);
      window.pfTicket = r.ticket;
      switchStage('totp');
      pfStatus('pf-msg', 'Credentials valid. Enter your RFC 6238 TOTP code.', true);
    } catch (err) {
      pfStatus('pf-msg', (err && err.message) || String(err), false);
    }
  };
})();

/* ---- TOTP panel --------------------------------------------------------- */
(function () {
  const panel = document.getElementById('panel-totp');
  if (!panel) return;
  const inputs = [...panel.querySelectorAll('input[maxlength="1"]')];
  inputs.forEach((inp, k) => {
    inp.id = 'totp-' + (k + 1);
    inp.setAttribute('inputmode', 'numeric');
    inp.setAttribute('pattern', '[0-9]*');
    inp.setAttribute('autocomplete', 'one-time-code');

    // Auto-select text on focus so replacing is fast
    inp.addEventListener('focus', () => {
      inp.select();
    });

    // Auto-advance on digit input
    inp.addEventListener('input', (e) => {
      const val = inp.value.replace(/\D/g, '');
      if (val.length > 1) {
        // Multi-character input (e.g. mobile auto-fill)
        const digits = val.split('');
        digits.forEach((d, i) => {
          if (k + i < inputs.length) {
            inputs[k + i].value = d;
          }
        });
        const nextIdx = Math.min(inputs.length - 1, k + digits.length);
        inputs[nextIdx].focus();
        return;
      }

      if (val.length === 1) {
        inp.value = val;
        if (k < inputs.length - 1) {
          inputs[k + 1].focus();
          inputs[k + 1].select();
        }
      } else {
        inp.value = '';
      }
    });

    // Auto-retreat on Backspace, arrow navigation, enter key submit
    inp.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace') {
        if (!inp.value && k > 0) {
          e.preventDefault();
          inputs[k - 1].value = '';
          inputs[k - 1].focus();
        } else if (inp.value) {
          inp.value = '';
          e.preventDefault();
        }
      } else if (e.key === 'ArrowLeft' && k > 0) {
        e.preventDefault();
        inputs[k - 1].focus();
        inputs[k - 1].select();
      } else if (e.key === 'ArrowRight' && k < inputs.length - 1) {
        e.preventDefault();
        inputs[k + 1].focus();
        inputs[k + 1].select();
      } else if (e.key === 'Enter') {
        e.preventDefault();
        if (verify) verify.click();
      }
    });

    // Auto-distribute pasted 6-digit code
    inp.addEventListener('paste', (e) => {
      e.preventDefault();
      const pasted = (e.clipboardData || window.clipboardData)?.getData('text') || '';
      const digits = pasted.replace(/\D/g, '');
      if (!digits) return;
      const start = (digits.length === 6) ? 0 : k;
      digits.split('').slice(0, inputs.length - start).forEach((d, i) => {
        if (inputs[start + i]) inputs[start + i].value = d;
      });
      const nextIdx = Math.min(inputs.length - 1, start + digits.length);
      inputs[nextIdx].focus();
      if (digits.length >= 6 && verify) {
        setTimeout(() => verify.click(), 100);
      }
    });
  });

  // Hook switchStage to automatically focus the first TOTP box when panel appears
  const origSwitchStage = window.switchStage;
  if (typeof origSwitchStage === 'function') {
    window.switchStage = function (stage) {
      origSwitchStage(stage);
      if (stage === 'totp') {
        setTimeout(() => { inputs[0]?.focus(); }, 60);
      }
    };
  }

  // Verify & Decrypt Session
  const verify = [...panel.querySelectorAll('button')].find(b => b.textContent.includes('Verify & Decrypt Session'));
  if (verify) verify.onclick = async () => {
    pfEnsureStatus();
    if (!window.pfTicket) { pfStatus('pf-msg', 'Sign in first.', false); switchStage('signin'); return; }
    const code = [1, 2, 3, 4, 5, 6].map(i => (document.getElementById('totp-' + i)?.value || '')).join('');
    if (code.length !== 6) { pfStatus('pf-msg', 'Enter the 6-digit code.', false); return; }
    pfStatus('pf-msg', 'Verifying TOTP ticket…');
    try {
      const r = await pfLogin2FA(window.pfTicket, code);
      pfSetSession(r.session_token);
      location.href = '/home/';
    } catch (err) {
      pfStatus('pf-msg', err.message, false);
    }
  };

  // Dev helper: fill the code from the backend (dev-only endpoint).
  const dev = document.createElement('button');
  dev.type = 'button';
  dev.className = 'w-full mt-2 border border-outline-variant hover:border-outline text-outline hover:text-on-surface font-label-code text-body-sm uppercase py-2 px-4 flex items-center justify-center gap-2 transition-colors duration-150';
  dev.innerHTML = '<span class="material-symbols-outlined text-sm">developer_mode</span><span>DEV: auto-fill current code</span><span class="text-outline-variant">(dev helper)</span>';
  dev.onclick = async () => {
    pfEnsureStatus();
    if (!window.pfUsername) { pfStatus('pf-msg', 'Sign in with a handle first.', false); switchStage('signin'); return; }
    try {
      const r = await pfDevTotp(window.pfUsername);
      const code = r.code.padStart(6, '0');
      code.split('').forEach((c, i) => { const el = document.getElementById('totp-' + (i + 1)); if (el) el.value = c; });
      pfStatus('pf-msg', 'DEV code filled for @' + r.username + ' — hit Verify & Decrypt.', true);
    } catch (err) {
      pfStatus('pf-msg', err.message, false);
    }
  };
  const wrap = panel.querySelector('.space-y-space-sm');
  if (wrap) wrap.appendChild(dev);
})();

/* Register tab inside login -> forward to the dedicated page */
(function () {
  const form = [...document.querySelectorAll('form')].find(f => f.querySelector('#reg-handle'));
  if (form) form.onsubmit = (e) => { e.preventDefault(); location.href = '/register/'; };
})();