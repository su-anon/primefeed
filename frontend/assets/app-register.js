/* CipherDeck register page integration.
 * Dynamic password entropy, real match validation, eye toggle,
 * animated key provisioning steps with real execution timing,
 * and TOTP 2FA onboarding.
 */

function pfEnsureStatusR() {
  if (document.getElementById('pf-msg')) return;
  const d = document.createElement('div');
  d.id = 'pf-msg';
  d.className = 'mt-3 px-3 py-2 border border-outline-variant bg-surface-container-lowest text-xs font-mono transition-all';
  d.textContent = '';
  const form = [...document.querySelectorAll('form')].find(f => f.querySelector('#handle'));
  if (form) form.prepend(d);
}

(function () {
  const form = [...document.querySelectorAll('form')].find(f => f.querySelector('#handle'));
  if (!form) return;

  const passInput = document.getElementById('passphrase');
  const confirmInput = document.getElementById('confirm-passphrase');
  const entropyLabel = document.getElementById('passphrase-entropy');
  const matchBadge = document.getElementById('confirm-match-badge');
  const confirmWrap = document.getElementById('confirm-input-wrap');
  const confirmIconBox = document.getElementById('confirm-icon-box');
  const confirmIcon = document.getElementById('confirm-icon');
  const toggleBtn = document.getElementById('toggle-passphrase');
  const eyeIcon = document.getElementById('eye-icon');

  const execTimeLabel = document.getElementById('key-exec-time');
  const stepRsaStatus = document.getElementById('step-rsa-status');
  const stepElgamalStatus = document.getElementById('step-elgamal-status');
  const stepTotpStatus = document.getElementById('step-totp-status');

  // 1. Password Entropy & Strength Calculation
  function calculateEntropy(pass) {
    if (!pass) return { score: 0, label: '[STRENGTH: ENTER PASSWORD]', bits: 0 };
    let pool = 0;
    if (/[a-z]/.test(pass)) pool += 26;
    if (/[A-Z]/.test(pass)) pool += 26;
    if (/[0-9]/.test(pass)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(pass)) pool += 32;
    const bits = Math.round(pass.length * Math.log2(pool || 1));
    let score = 1;
    let label = '[STRENGTH: WEAK]';
    if (bits >= 96) {
      score = 4;
      label = '[STRENGTH: VERY STRONG]';
    } else if (bits >= 64) {
      score = 3;
      label = '[STRENGTH: STRONG]';
    } else if (bits >= 40) {
      score = 2;
      label = '[STRENGTH: MODERATE]';
    }
    return { score, label, bits };
  }

  function updateEntropyUI() {
    if (!passInput || !entropyLabel) return;
    const val = passInput.value;
    const { score, label } = calculateEntropy(val);

    entropyLabel.textContent = label;
    if (score === 0) {
      entropyLabel.className = 'font-telemetry-micro text-telemetry-micro text-outline font-normal';
    } else if (score === 1) {
      entropyLabel.className = 'font-telemetry-micro text-telemetry-micro text-error font-bold';
    } else if (score === 2) {
      entropyLabel.className = 'font-telemetry-micro text-telemetry-micro text-amber-400 font-bold';
    } else if (score === 3) {
      entropyLabel.className = 'font-telemetry-micro text-telemetry-micro text-primary font-bold';
    } else {
      entropyLabel.className = 'font-telemetry-micro text-telemetry-micro text-secondary font-bold';
    }

    const barColors = {
      0: ['bg-outline-variant/30', 'bg-outline-variant/30', 'bg-outline-variant/30', 'bg-outline-variant/30'],
      1: ['bg-error', 'bg-outline-variant/30', 'bg-outline-variant/30', 'bg-outline-variant/30'],
      2: ['bg-amber-400', 'bg-amber-400', 'bg-outline-variant/30', 'bg-outline-variant/30'],
      3: ['bg-primary', 'bg-primary', 'bg-primary', 'bg-outline-variant/30'],
      4: ['bg-secondary', 'bg-secondary', 'bg-secondary', 'bg-secondary']
    };

    const colors = barColors[score];
    for (let i = 1; i <= 4; i++) {
      const b = document.getElementById('ebar-' + i);
      if (b) {
        b.className = 'h-1 rounded-full transition-colors duration-200 ' + colors[i - 1];
      }
    }
    updateMatchUI();
  }

  // 2. Real-time Password Match Verification
  function updateMatchUI() {
    if (!confirmInput || !matchBadge || !confirmWrap) return;
    const p = passInput ? passInput.value : '';
    const c = confirmInput.value;

    if (!c) {
      matchBadge.innerHTML = '[ENTER TO CONFIRM]';
      matchBadge.className = 'font-telemetry-micro text-telemetry-micro text-outline flex items-center gap-1 font-normal';
      confirmWrap.className = 'flex items-stretch bg-surface-container-lowest border border-outline-variant focus-within:border-primary transition-colors';
      if (confirmIconBox) confirmIconBox.className = 'flex items-center px-space-md border-l border-outline-variant bg-surface-container-high text-outline transition-colors';
      if (confirmIcon) confirmIcon.textContent = 'lock';
      return;
    }

    if (p !== c) {
      matchBadge.innerHTML = '<span class="material-symbols-outlined text-[13px]">cancel</span> Passwords do not match';
      matchBadge.className = 'font-telemetry-micro text-telemetry-micro text-error flex items-center gap-1 font-bold';
      confirmWrap.className = 'flex items-stretch bg-surface-container-lowest border border-error focus-within:border-error transition-colors';
      if (confirmIconBox) confirmIconBox.className = 'flex items-center px-space-md border-l border-error bg-surface-container-high text-error transition-colors';
      if (confirmIcon) confirmIcon.textContent = 'cancel';
    } else {
      matchBadge.innerHTML = '<span class="material-symbols-outlined text-[13px]">check_circle</span> Passwords match';
      matchBadge.className = 'font-telemetry-micro text-telemetry-micro text-secondary flex items-center gap-1 font-bold';
      confirmWrap.className = 'flex items-stretch bg-surface-container-lowest border border-secondary focus-within:border-secondary transition-colors';
      if (confirmIconBox) confirmIconBox.className = 'flex items-center px-space-md border-l border-secondary bg-surface-container-high text-secondary transition-colors';
      if (confirmIcon) confirmIcon.textContent = 'verified_user';
    }
  }

  if (passInput) passInput.addEventListener('input', updateEntropyUI);
  if (confirmInput) confirmInput.addEventListener('input', updateMatchUI);

  // 3. Password Visibility Toggle
  if (toggleBtn && eyeIcon) {
    toggleBtn.addEventListener('click', () => {
      const isPass = passInput.type === 'password';
      passInput.type = isPass ? 'text' : 'password';
      if (confirmInput) confirmInput.type = isPass ? 'text' : 'password';
      eyeIcon.textContent = isPass ? 'visibility_off' : 'visibility';
      toggleBtn.classList.toggle('text-primary', isPass);
    });
  }

  // 4. Form Submit with Real Key Provisioning Timing & Progress
  form.onsubmit = async (e) => {
    e.preventDefault();
    try {
      pfEnsureStatusR();
      const handle = document.getElementById('handle').value.trim();
      const email = document.getElementById('contact').value.trim();
      const pass = passInput ? passInput.value : '';
      const confirm = confirmInput ? confirmInput.value : '';

      if (!handle || !email || !pass) {
        pfStatus('pf-msg', 'Username, email and password are required.', false);
        return;
      }
      if (pass !== confirm) {
        pfStatus('pf-msg', 'Passwords do not match. Please verify.', false);
        return;
      }

      const startTime = performance.now();
      if (execTimeLabel) {
        execTimeLabel.textContent = 'STATUS: GENERATING ENCRYPTION KEYS...';
        execTimeLabel.className = 'font-telemetry-micro text-telemetry-micro text-primary font-bold animate-pulse';
      }

      // Step animations
      if (stepRsaStatus) {
        stepRsaStatus.textContent = '[·]';
        stepRsaStatus.className = 'text-primary font-bold animate-pulse';
      }

      const anim1 = setTimeout(() => {
        if (stepRsaStatus) {
          stepRsaStatus.textContent = '[✔]';
          stepRsaStatus.className = 'text-secondary font-bold';
        }
        if (stepElgamalStatus) {
          stepElgamalStatus.textContent = '[·]';
          stepElgamalStatus.className = 'text-primary font-bold animate-pulse';
        }
      }, 350);

      const anim2 = setTimeout(() => {
        if (stepElgamalStatus) {
          stepElgamalStatus.textContent = '[✔]';
          stepElgamalStatus.className = 'text-secondary font-bold';
        }
        if (stepTotpStatus) {
          stepTotpStatus.textContent = '[·]';
          stepTotpStatus.className = 'text-primary font-bold animate-pulse';
        }
      }, 700);

      pfStatus('pf-msg', 'Generating encryption keys and two-factor code…', true);

      const r = await pfRegister({
        username: handle,
        password: pass,
        email: email,
        name: handle,
        contact: '',
      });

      clearTimeout(anim1);
      clearTimeout(anim2);

      const elapsed = Math.round(performance.now() - startTime);
      const timeStr = elapsed > 1000 ? (elapsed / 1000).toFixed(2) + 'S' : elapsed + 'MS';

      if (execTimeLabel) {
        execTimeLabel.textContent = 'SETUP COMPLETE (' + timeStr + ')';
        execTimeLabel.className = 'font-telemetry-micro text-telemetry-micro text-secondary font-bold';
      }

      if (stepRsaStatus) {
        stepRsaStatus.textContent = '[✔]';
        stepRsaStatus.className = 'text-secondary font-bold';
      }
      if (stepElgamalStatus) {
        stepElgamalStatus.textContent = '[✔]';
        stepElgamalStatus.className = 'text-secondary font-bold';
      }
      if (stepTotpStatus) {
        stepTotpStatus.textContent = '[✔]';
        stepTotpStatus.className = 'text-secondary font-bold';
      }

      pfSaveTotpSecret(handle, r.totp_secret);   // remember for dev auto-fill on login
      showResult(handle, r.totp_secret, r.totp_qr, r.totp_uri, timeStr, r.ticket);
    } catch (err) {
      if (execTimeLabel) {
        execTimeLabel.textContent = 'STATUS: REGISTRATION FAILED';
        execTimeLabel.className = 'font-telemetry-micro text-telemetry-micro text-error font-bold';
      }
      pfStatus('pf-msg', (err && err.message) || String(err), false);
    }
  };

  function showResult(handle, secret, qr, uri, timeStr, ticket) {
    const old = document.getElementById('reg-result');
    if (old) old.remove();

    const box = document.createElement('div');
    box.id = 'reg-result';
    box.className = 'mt-4 border border-secondary bg-surface-container-low p-5 shadow-lg';

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
        '      Open Google Authenticator, Aegis, 1Password, or Authy and scan this QR code to complete two-factor authentication setup.' +
        '    </p>' +
        (uri ? '    <a href="' + uri + '" class="mt-2 inline-flex items-center gap-1 text-xs text-primary hover:underline font-label-code uppercase"><span class="material-symbols-outlined text-xs">open_in_new</span><span>Open in Authenticator app</span></a>' : '') +
        '    <div class="mt-3 font-label-code text-label-code text-outline uppercase text-[11px]">Manual Entry Key</div>' +
        '    <code class="block mt-1 px-2.5 py-1.5 bg-surface-container-highest border border-outline-variant font-label-code text-xs text-primary break-all select-all font-mono">' + secret + '</code>' +
        '  </div>' +
        '</div>';
    } else {
      qrHtml =
        '<div class="mt-3 font-label-code text-label-code text-outline uppercase text-xs">Two-Factor Secret Key</div>' +
        '<code class="block mt-1 px-3 py-2 bg-surface-container-highest border border-outline-variant font-label-code text-label-code text-primary break-all font-mono">' + secret + '</code>';
    }

    const verifySectionHtml = ticket ?
      '<div class="mt-4 p-4 bg-surface-container-lowest border border-outline-variant">' +
      '  <div class="font-label-code text-xs text-primary uppercase font-bold flex items-center gap-1.5 mb-1">' +
      '    <span class="material-symbols-outlined text-sm">lock_clock</span>' +
      '    <span>Enter 6-Digit Authenticator Code to Finish</span>' +
      '  </div>' +
      '  <p class="text-xs text-on-surface-variant mb-3">' +
      '    Enter the 6-digit code shown in your authenticator app to verify setup and log in directly:' +
      '  </p>' +
      '  <div class="flex items-center justify-center gap-2 mb-3 font-mono text-lg">' +
      '    <input class="reg-totp-digit w-10 h-12 text-center bg-surface-dim border border-primary text-primary focus:border-tertiary focus:outline-none" maxlength="1" type="text" id="reg-t-1" inputmode="numeric" pattern="[0-9]*" />' +
      '    <input class="reg-totp-digit w-10 h-12 text-center bg-surface-dim border border-primary text-primary focus:border-tertiary focus:outline-none" maxlength="1" type="text" id="reg-t-2" inputmode="numeric" pattern="[0-9]*" />' +
      '    <input class="reg-totp-digit w-10 h-12 text-center bg-surface-dim border border-primary text-primary focus:border-tertiary focus:outline-none" maxlength="1" type="text" id="reg-t-3" inputmode="numeric" pattern="[0-9]*" />' +
      '    <span class="text-outline font-bold px-1 select-none">-</span>' +
      '    <input class="reg-totp-digit w-10 h-12 text-center bg-surface-dim border border-outline-variant text-on-surface focus:border-primary focus:outline-none" maxlength="1" type="text" id="reg-t-4" inputmode="numeric" pattern="[0-9]*" />' +
      '    <input class="reg-totp-digit w-10 h-12 text-center bg-surface-dim border border-outline-variant text-on-surface focus:border-primary focus:outline-none" maxlength="1" type="text" id="reg-t-5" inputmode="numeric" pattern="[0-9]*" />' +
      '    <input class="reg-totp-digit w-10 h-12 text-center bg-surface-dim border border-outline-variant text-on-surface focus:border-primary focus:outline-none" maxlength="1" type="text" id="reg-t-6" inputmode="numeric" pattern="[0-9]*" />' +
      '  </div>' +
      '  <button id="btn-reg-verify" type="button" class="w-full bg-primary-container text-surface-container-lowest hover:bg-primary font-label-code text-xs uppercase font-bold py-2.5 px-4 flex items-center justify-center gap-2 transition-colors duration-150 cursor-pointer">' +
      '    <span class="material-symbols-outlined text-sm">login</span>' +
      '    <span>Verify Code &amp; Enter PrimeFeed</span>' +
      '  </button>' +
      '  <button id="btn-reg-dev" type="button" class="w-full mt-2 border border-outline-variant hover:border-outline text-outline hover:text-on-surface font-label-code text-[11px] uppercase py-1.5 px-3 flex items-center justify-center gap-1.5 transition-colors cursor-pointer">' +
      '    <span class="material-symbols-outlined text-xs">developer_mode</span>' +
      '    <span>DEV: auto-fill 2FA code</span>' +
      '  </button>' +
      '</div>' : '';

    box.innerHTML =
      '<div class="flex items-center justify-between">' +
      '  <div class="flex items-center gap-2 text-secondary font-label-code text-label-code uppercase tracking-wider font-bold">' +
      '    <span class="material-symbols-outlined text-base">verified</span><span>Account Created &amp; Keys Ready</span>' +
      '  </div>' +
      '  <span class="font-telemetry-micro text-telemetry-micro text-outline">TIME: ' + (timeStr || '~200ms') + '</span>' +
      '</div>' +
      '<p class="text-sm text-on-surface-variant mt-2 leading-relaxed">Your account encryption keys and two-factor authentication credentials have been generated. Scan the code below to finish setup.</p>' +
      qrHtml +
      verifySectionHtml +
      '<div class="mt-4 pt-3 border-t border-outline-variant flex items-center justify-between">' +
      '  <a href="/login/" class="inline-flex items-center gap-1.5 text-xs text-outline hover:text-primary font-label-code uppercase transition-colors">' +
      '    <span>Or go to Sign In screen</span><span class="material-symbols-outlined text-xs">arrow_forward</span>' +
      '  </a>' +
      '  <span class="font-telemetry-micro text-telemetry-micro text-secondary uppercase font-bold">[READY]</span>' +
      '</div>';

    form.after(box);
    pfStatus('pf-msg', ('Account created for @' + handle + '. Scan the QR code, enter your 6-digit code below, and you are all set!'), true);

    // Wire interactive 2FA verification if ticket is available
    if (ticket) {
      const inputs = [1, 2, 3, 4, 5, 6].map(i => document.getElementById('reg-t-' + i));
      const verifyBtn = document.getElementById('btn-reg-verify');
      const devBtn = document.getElementById('btn-reg-dev');

      inputs.forEach((inp, k) => {
        if (!inp) return;
        inp.addEventListener('focus', () => inp.select());
        inp.addEventListener('input', () => {
          const val = inp.value.replace(/\D/g, '');
          if (val.length > 1) {
            val.split('').forEach((d, i) => { if (inputs[k + i]) inputs[k + i].value = d; });
            const next = Math.min(inputs.length - 1, k + val.length);
            inputs[next]?.focus();
            return;
          }
          inp.value = val;
          if (val && k < inputs.length - 1) {
            inputs[k + 1]?.focus();
            inputs[k + 1]?.select();
          }
        });
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
          } else if (e.key === 'Enter' && verifyBtn) {
            e.preventDefault();
            verifyBtn.click();
          }
        });
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
          inputs[nextIdx]?.focus();
          if (digits.length >= 6 && verifyBtn) {
            setTimeout(() => verifyBtn.click(), 100);
          }
        });
      });

      // Auto-focus digit 1
      setTimeout(() => inputs[0]?.focus(), 100);

      // Verify button action
      if (verifyBtn) {
        verifyBtn.onclick = async () => {
          pfEnsureStatusR();
          const code = inputs.map(i => i?.value || '').join('');
          if (code.length !== 6) {
            pfStatus('pf-msg', 'Please enter all 6 digits of your authenticator code.', false);
            return;
          }
          pfStatus('pf-msg', 'Verifying two-factor code…');
          try {
            const res = await pfLogin2FA(ticket, code);
            pfSetSession(res.session_token);
            pfStatus('pf-msg', 'Authenticated! Redirecting to feed…', true);
            setTimeout(() => { location.href = '/home/'; }, 400);
          } catch (err) {
            pfStatus('pf-msg', (err && err.message) || String(err), false);
          }
        };
      }

      // Dev button action
      if (devBtn) {
        devBtn.onclick = async () => {
          try {
            const r = await pfDevTotp(handle);
            const code = r.code.padStart(6, '0');
            code.split('').forEach((c, i) => { if (inputs[i]) inputs[i].value = c; });
            pfStatus('pf-msg', 'Demo 2FA code auto-filled. Click Verify & Enter PrimeFeed.', true);
          } catch (err) {
            pfStatus('pf-msg', err.message, false);
          }
        };
      }
    }
  }
})();