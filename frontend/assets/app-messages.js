/* CipherDeck messages page — inbox / sent / compose.
 * Messages are ElGamal end-to-end encrypted to the recipient's public key.
 */

(function () {
  if (!pfRequireAuth()) return;
  let me = null;
  let activeTab = 'inbox';

  const esc = (s) => String(s || '').replace(/[&<>"']/g,
    c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  function status(msg, ok) {
    const el = document.getElementById('pf-msg-status');
    el.classList.remove('hidden', 'text-secondary', 'text-error');
    el.textContent = msg;
    el.classList.add(ok === false ? 'text-error' : 'text-secondary');
  }

  function renderList(items, kind) {
    const box = document.getElementById('pf-list');
    if (!items.length) {
      box.innerHTML = '<div class="p-6 rounded-xl border border-outline-variant bg-surface-container-lowest/60 text-sm text-on-surface-variant">No messages yet.</div>';
      return;
    }
    let html = '';
    items.forEach(m => {
      const peer = kind === 'inbox' ? m.sender : m.recipient;
      const unread = kind === 'inbox' && !m.read;
      html += '<div class="p-4 rounded-xl border ' + (unread ? 'border-primary/50 bg-surface-container-low/60' : 'border-outline-variant bg-surface-container-lowest/60') + '">' +
        '<div class="flex items-center justify-between text-xs text-on-surface-variant">' +
        '<span class="font-mono ' + (unread ? 'text-secondary' : 'text-on-surface') + '">' + (kind === 'inbox' ? 'from ' : 'to ') + '@' + esc(peer) + '</span>' +
        '<span class="font-mono text-on-surface-variant/80">' + timeAgo(m.created_at) + '</span></div>' +
        '<p class="mt-1.5 text-sm text-on-surface-variant leading-relaxed whitespace-pre-wrap break-words">' + esc(m.content) + '</p>' +
        '<div class="mt-2 flex items-center gap-2 text-[11px] font-mono">' +
        '<span class="text-secondary">HMAC valid</span><span class="text-outline">·</span><span class="text-on-surface-variant">integrity: ' + esc(m.integrity) + '</span>' +
        (unread ? '<span class="ml-auto px-1.5 py-0.5 rounded bg-secondary/10 text-secondary">new</span>' : '') +
        '</div></div>';
    });
    box.innerHTML = html;
  }

  async function loadList(tab) {
    activeTab = tab;
    try {
      const r = tab === 'inbox' ? await pfInbox() : await pfSent();
      renderList(r.messages, tab);
      status('Loaded ' + tab + ' (' + r.count + ').', true);
    } catch (err) {
      status(err.message, false);
    }
  }

  function bindTabs() {
    document.querySelectorAll('.pf-tab').forEach(b => {
      b.onclick = async () => {
        document.querySelectorAll('.pf-tab').forEach(x => {
          x.className = 'pf-tab px-3.5 py-1.5 rounded-full text-xs ' +
            (x === b ? 'font-semibold bg-on-surface text-surface' : 'font-medium text-on-surface-variant hover:text-on-surface hover:bg-surface-container');
        });
        await loadList(b.dataset.tab);
      };
    });
  }

  async function fillRecipients() {
    try {
      const r = await pfUsers();
      const sel = document.getElementById('pf-recipient');
      sel.innerHTML = '';
      r.users.forEach(u => {
        if (u.id !== me.user_id) {
          const o = document.createElement('option');
          o.value = u.id;
          o.textContent = '@' + u.username + (u.role === 'admin' ? ' (admin)' : '');
          sel.appendChild(o);
        }
      });
    } catch (err) {
      status(err.message, false);
    }
  }

  function bindSend() {
    const btn = document.getElementById('pf-send');
    btn.onclick = async () => {
      const rid = document.getElementById('pf-recipient').value;
      const content = document.getElementById('pf-msg-content').value.trim();
      if (!rid) { status('Select a recipient.', false); return; }
      if (!content) { status('Write a message.', false); return; }
      btn.disabled = true;
      try {
        await pfSendMessage(Number(rid), content);
        document.getElementById('pf-msg-content').value = '';
        status('Message encrypted and sent.', true);
        await loadList(activeTab === 'sent' ? 'sent' : 'inbox');
      } catch (err) {
        status(err.message, false);
      } finally {
        btn.disabled = false;
      }
    };
  }

  async function init() {
    try { me = await pfMe(); } catch (_) { pfClearSession(); location.href = '/login/'; return; }
    pfInjectNav(me);
    bindTabs();
    bindSend();
    await fillRecipients();
    await loadList('inbox');
  }
  init();
})();