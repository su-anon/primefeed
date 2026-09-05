/* CipherDeck landing page integration. Keeps it marketing-focused; wires the
 * primary CTAs to the real flows. If already authenticated, point at the feed.
 */

(function () {
  const link = (text, url) => {
    [...document.querySelectorAll('a')].forEach(a => {
      if (a.textContent.trim() === text) a.setAttribute('href', url);
    });
  };

  if (pfGetSession()) {
    link('Sign In', '/home/');
    link('Read Encrypted', '/home/');
    link('Browse Recent Articles', '/home/');
  } else {
    link('Sign In', '/login/');
    link('Read Encrypted', '/home/');
    link('Browse Recent Articles', '/home/');
  }
  link('Continue reading complete analysis', '/home/');
})();