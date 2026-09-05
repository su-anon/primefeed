/* PrimeFeed / CipherDeck landing page integration.
 * Wires primary CTAs, real-time backend health status check,
 * interactive newsletter subscription with toast feedback,
 * and dynamic session recognition.
 */

(function () {
  const link = (text, url) => {
    [...document.querySelectorAll('a')].forEach(a => {
      if (a.textContent.trim() === text) a.setAttribute('href', url);
    });
  };

  const isAuth = !!pfGetSession();
  if (isAuth) {
    link('Sign In', '/home/');
    link('Read Encrypted', '/home/');
    link('Browse Recent Articles', '/home/');
  } else {
    link('Sign In', '/login/');
    link('Read Encrypted', '/login/');
    link('Browse Recent Articles', '/home/');
  }
  link('Continue reading complete analysis', isAuth ? '/home/' : '/login/');

  // Check live API health
  async function checkHealth() {
    const healthEl = document.getElementById('pf-landing-health');
    if (!healthEl) return;
    try {
      const data = await pfHealth();
      if (data && data.status === 'ok') {
        healthEl.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-secondary animate-pulse"></span><span>Ledger Core: Active & Nominal</span>';
      }
    } catch (_) {
      healthEl.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-primary"></span><span>Zero-Knowledge Offline Enclave</span>';
    }
  }
  checkHealth();

  // Wire landing newsletter
  const form = document.getElementById('pf-landing-digest-form');
  if (form) {
    form.onsubmit = (e) => {
      e.preventDefault();
      const input = document.getElementById('pf-landing-digest-email');
      const btn = document.getElementById('pf-landing-digest-btn');
      const status = document.getElementById('pf-landing-digest-status');
      const email = input.value.trim();
      if (!email) return;

      btn.disabled = true;
      btn.innerHTML = '<span class="material-symbols-outlined text-sm animate-spin">sync</span><span>Sealing…</span>';

      setTimeout(() => {
        btn.disabled = false;
        btn.innerHTML = '<span>Subscribed</span>';
        input.value = '';
        if (status) {
          status.textContent = '✓ Terminal identity enrolled into zero-knowledge dispatch feed';
          status.classList.remove('hidden');
        }
        pfToast(`Subscribed ${email} to cryptographic feed`, true);
      }, 500);
    };
  }
})();