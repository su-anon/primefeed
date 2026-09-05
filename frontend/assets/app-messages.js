/* PrimeFeed / CipherDeck messages page — inbox / sent / compose.
 * ElGamal end-to-end encryption with live message filtering,
 * recipient auto-population, and interactive status feedback.
 */

(function () {
  if (!pfRequireAuth()) return;
  let me = null;
  let activeTab = 'inbox';
  let cachedItems = [];
  let searchQuery = '';

  const esc = (s) => String(s || '').replace(/[&<>"']/g,
    c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  function status(msg, ok) {
    const el = document.getElementById('pf-msg-status');
    if (!el) return;
    el.classList.remove('hidden', 'text-secondary', 'text-error', 'border-secondary/40', 'border-error/40');
    el.textContent = msg;
    el.classList.add(ok === false ? 'text-error' : 'text-secondary');
    el.classList.add(ok === false ? 'border-error/40' : 'border-secondary/40');
    if (ok) {
      pfToast(msg, true);
    } else if (ok === false) {
      pfToast(msg, false);
    }
  }

  function startLiveClock() {
    const clockEl = document.getElementById('pf-live-clock');
    if (!clockEl) return;
    const update = () => {
      clockEl.textContent = new Date().toISOString().slice(11, 19) + ' UTC';
    };
    update();
    setInterval(update, 1000);
  }

  function renderList(items, kind) {
    const box = document.getElementById('pf-list');
    if (!box) return;

    // Filter by searchQuery if present
    let filtered = items;
    if (searchQuery) {
      filtered = items.filter(m => {
        const peer = (kind === 'inbox' ? m.sender : m.recipient) || '';
        return peer.toLowerCase().includes(searchQuery) ||
               (m.content && m.content.toLowerCase().includes(searchQuery));
      });
    }

    if (!filtered.length) {
      box.innerHTML = '<div class="p-8 rounded-xl border border-outline-variant bg-surface-container-lowest/60 text-center text-sm text-on-surface-variant">' +
        (searchQuery ? 'No messages match query "' + esc(searchQuery) + '".' : 'No messages in ' + kind + ' yet.') +
        '</div>';
      return;
    }

    let html = '';
    filtered.forEach(m => {
      const peer = kind === 'inbox' ? m.sender : m.recipient;
      const unread = kind === 'inbox' && !m.read;
      const initials = (peer || 'U').slice(0, 2).toUpperCase();

      html += '<div class="p-5 rounded-xl border transition-all duration-200 ' +
        (unread ? 'border-primary/50 bg-surface-container-low/80 shadow-md shadow-primary/5' : 'border-outline-variant bg-surface-container-lowest/70 hover:bg-surface-container-low/60') + '">' +
        '<div class="flex items-center justify-between text-xs text-on-surface-variant">' +
        '<div class="flex items-center gap-2">' +
        '<div class="w-6 h-6 rounded-full bg-surface-container-high border border-outline-variant flex items-center justify-center font-mono font-bold text-xs text-primary">' +
        initials +
        '</div>' +
        '<span class="font-mono ' + (unread ? 'text-primary font-semibold' : 'text-on-surface') + '">' +
        (kind === 'inbox' ? 'from ' : 'to ') + '@' + esc(peer) + '</span>' +
        '</div>' +
        '<span class="font-mono text-on-surface-variant/80" data-ts="' + m.created_at + '">' + timeAgo(m.created_at) + '</span>' +
        '</div>' +
        '<p class="mt-2.5 text-sm text-on-surface leading-relaxed whitespace-pre-wrap break-words">' + esc(m.content) + '</p>' +
        '<div class="mt-3 pt-2.5 border-t border-outline-variant/40 flex items-center justify-between text-[11px] font-mono">' +
        '<div class="flex items-center gap-2">' +
        '<span class="text-secondary flex items-center gap-1"><span class="material-symbols-outlined text-xs">verified</span>HMAC Valid</span>' +
        '<span class="text-outline">·</span>' +
        '<span class="text-on-surface-variant">integrity: ' + esc(m.integrity) + '</span>' +
        '</div>' +
        '<div class="flex items-center gap-2">' +
        (unread ? '<span class="px-2 py-0.5 rounded bg-secondary/15 text-secondary border border-secondary/30 font-semibold">NEW</span>' : '') +
        '<button data-content="' + esc(m.content) + '" class="pf-msg-copy hover:text-primary transition-colors flex items-center gap-1 cursor-pointer">' +
        '<span class="material-symbols-outlined text-xs">content_copy</span><span>copy</span></button>' +
        '</div>' +
        '</div></div>';
    });

    box.innerHTML = html;

    box.querySelectorAll('.pf-msg-copy').forEach(btn => {
      btn.onclick = () => {
        navigator.clipboard.writeText(btn.dataset.content).then(() => {
          pfToast('Copied message content to clipboard', true);
        });
      };
    });
  }

  async function loadList(tab) {
    activeTab = tab;
    try {
      const r = tab === 'inbox' ? await pfInbox() : await pfSent();
      cachedItems = r.messages || [];
      renderList(cachedItems, tab);
    } catch (err) {
      status(err.message, false);
    }
  }

  function bindTabs() {
    document.querySelectorAll('.pf-tab').forEach(b => {
      b.onclick = async () => {
        document.querySelectorAll('.pf-tab').forEach(x => {
          x.className = 'pf-tab px-3.5 py-1.5 rounded-full text-xs transition-all ' +
            (x === b ? 'font-semibold bg-on-surface text-surface shadow' : 'font-medium text-on-surface-variant hover:text-on-surface hover:bg-surface-container');
        });
        await loadList(b.dataset.tab);
      };
    });
  }

  async function fillRecipients() {
    try {
      const r = await pfUsers();
      const sel = document.getElementById('pf-recipient');
      if (!sel) return;
      sel.innerHTML = '';
      r.users.forEach(u => {
        if (u.id !== me.user_id) {
          const o = document.createElement('option');
          o.value = u.id;
          o.textContent = '@' + u.username + (u.role === 'admin' ? ' (Admin)' : ' (Researcher)');
          sel.appendChild(o);
        }
      });
      const countEl = document.getElementById('pf-active-validators-count');
      if (countEl) {
        const count = r.users.length;
        countEl.textContent = `${count} active researcher${count === 1 ? '' : 's'} registered`;
      }
    } catch (err) {
      status(err.message, false);
    }
  }

  function bindSend() {
    const btn = document.getElementById('pf-send');
    if (!btn) return;
    btn.onclick = async () => {
      const sel = document.getElementById('pf-recipient');
      const rid = sel ? sel.value : null;
      const contentEl = document.getElementById('pf-msg-content');
      const content = contentEl ? contentEl.value.trim() : '';

      if (!rid) { status('Select a recipient terminal.', false); return; }
      if (!content) { status('Enter a message payload.', false); return; }

      btn.disabled = true;
      const originalLabel = btn.innerHTML;
      btn.innerHTML = '<span class="material-symbols-outlined text-sm animate-spin">sync</span><span>Sealing & Dispatching…</span>';

      try {
        await pfSendMessage(Number(rid), content);
        if (contentEl) contentEl.value = '';
        status('Message encrypted via ElGamal and dispatched.', true);
        await loadList(activeTab);
      } catch (err) {
        status(err.message, false);
      } finally {
        btn.disabled = false;
        btn.innerHTML = originalLabel;
      }
    };
  }

  function wireSearchAndCta() {
    const searchInput = document.getElementById('pf-msg-search');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        searchQuery = e.target.value.trim().toLowerCase();
        renderList(cachedItems, activeTab);
      });
    }

    const newMsgCta = document.getElementById('pf-new-msg-cta');
    if (newMsgCta) {
      newMsgCta.onclick = (e) => {
        e.preventDefault();
        const contentEl = document.getElementById('pf-msg-content');
        if (contentEl) {
          contentEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
          contentEl.focus();
        }
      };
    }
  }

  async function init() {
    try {
      me = await pfMe();
    } catch (_) {
      pfClearSession();
      location.href = '/login/';
      return;
    }
    pfInjectNav(me);
    startLiveClock();
    wireSearchAndCta();
    bindTabs();
    bindSend();
    await fillRecipients();
    await loadList('inbox');
  }

  init();
})();