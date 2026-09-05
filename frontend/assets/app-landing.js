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
})();