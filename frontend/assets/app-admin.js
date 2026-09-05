/* CipherDeck admin console — users, key rotation, integrity audit, moderation. */

(function () {
  if (!pfRequireAuth()) return;

  const esc = (s) => String(s || '').replace(/[&<>"']/g,
    c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  function status(msg, ok) {
    const el = document.getElementById('pf-admin-status');
    el.classList.remove('hidden', 'text-secondary', 'text-error');
    el.textContent = msg;
    el.classList.add(ok === false ? 'text-error' : 'text-secondary');
  }

  function bindTabs() {
    document.querySelectorAll('.pf-tab').forEach(b => {
      b.onclick = () => {
        document.querySelectorAll('.pf-tab').forEach(x => {
          x.className = 'pf-tab px-3.5 py-1.5 rounded-full text-xs ' +
            (x === b ? 'font-semibold bg-on-surface text-surface' : 'font-medium text-on-surface-variant hover:text-on-surface hover:bg-surface-container');
        });
        const tab = b.dataset.tab;
        ['users', 'keys', 'integrity', 'posts'].forEach(t => {
          document.getElementById('pf-a-' + t).classList.toggle('hidden', t !== tab);
        });
      };
    });
  }

  /* ---- Users ---- */
  async function loadUsers() {
    try {
      const r = await pfAdminUsers();
      let html = '<div class="overflow-x-auto rounded-xl border border-outline-variant bg-surface-container-lowest">' +
        '<table class="w-full text-left text-sm"><thead><tr class="border-b border-outline-variant bg-surface-container/60 text-xs font-mono text-on-surface-variant uppercase tracking-wider">' +
        '<th class="py-2.5 px-4">User</th><th class="py-2.5 px-4">Role</th><th class="py-2.5 px-4">Status</th><th class="py-2.5 px-4 text-right">Actions</th></tr></thead><tbody>';
      r.users.forEach(u => {
        const suspended = u.is_suspended === 1;
        html += '<tr class="border-b border-outline-variant/40 hover:bg-surface-container/30">' +
          '<td class="py-2.5 px-4 font-mono text-on-surface">@' + esc(u.username) + ' <span class="text-on-surface-variant/70">#' + u.id + '</span></td>' +
          '<td class="py-2.5 px-4"><span class="px-2 py-0.5 rounded text-[11px] font-mono ' + (u.role === 'admin' ? 'bg-primary/10 text-primary' : 'bg-surface-container text-on-surface-variant') + '">' + esc(u.role) + '</span></td>' +
          '<td class="py-2.5 px-4"><span class="text-[11px] font-mono ' + (suspended ? 'text-error' : 'text-secondary') + '">' + (suspended ? 'SUSPENDED' : 'ACTIVE') + '</span></td>' +
          '<td class="py-2.5 px-4 text-right flex flex-wrap gap-1.5">' +
          (suspended
            ? '<button data-act="restore" data-id="' + u.id + '" data-u="' + esc(u.username) + '" class="pf-ua px-2 py-1 rounded text-[11px] font-mono text-secondary border border-secondary/30 hover:bg-secondary/10">Restore</button>'
            : '<button data-act="suspend" data-id="' + u.id + '" data-u="' + esc(u.username) + '" class="pf-ua px-2 py-1 rounded text-[11px] font-mono text-error border border-error/30 hover:bg-error/10">Suspend</button>') +
          '<button data-act="elevate" data-id="' + u.id + '" data-u="' + esc(u.username) + '" class="pf-ua px-2 py-1 rounded text-[11px] font-mono text-on-surface-variant border border-outline-variant hover:text-primary">Make Admin</button>' +
          '<button data-act="reset2fa" data-id="' + u.id + '" data-u="' + esc(u.username) + '" class="pf-ua px-2 py-1 rounded text-[11px] font-mono text-on-surface-variant border border-outline-variant hover:text-primary">Reset 2FA</button>' +
          '<button data-act="resetpwd" data-id="' + u.id + '" data-u="' + esc(u.username) + '" class="pf-ua px-2 py-1 rounded text-[11px] font-mono text-on-surface-variant border border-outline-variant hover:text-primary">Reset Pwd</button>' +
          '</td></tr>';
      });
      html += '</tbody></table></div>';
      document.getElementById('pf-a-users').innerHTML = html;
      wireUserActions();
    } catch (err) { status(err.message, false); }
  }

  function wireUserActions() {
    document.querySelectorAll('.pf-ua').forEach(b => {
      b.onclick = async () => {
        const act = b.dataset.act, id = Number(b.dataset.id), u = b.dataset.u;
        try {
          if (act === 'suspend' && !confirm('Suspend @' + u + '? This destroys their keys and revokes sessions.')) return;
          const result = act === 'suspend' ? await pfAdminSuspend(id)
            : act === 'restore' ? await pfAdminRestore(id)
            : act === 'elevate' ? await pfAdminElevate(id)
            : act === 'reset2fa' ? await pfAdminReset2FA(id)
            : await pfAdminResetPassword(id);
          if (act === 'reset2fa' || act === 'resetpwd') {
            const secret = act === 'reset2fa' ? result.totp_secret : result.temporary_password;
            status((act === 'reset2fa' ? 'New TOTP secret for @' + u + ':\n' : 'Temporary password for @' + u + ':\n ') + secret, true);
            alert((act === 'reset2fa' ? 'New TOTP secret for @' + u + ' (user must re-enroll in an authenticator app):\n\n' : 'Temporary password for @' + u + ' (user must change it on next login):\n\n') + secret);
          } else {
            status('@' + u + ' updated.', true);
          }
          await loadUsers();
        } catch (err) { status(err.message, false); }
      };
    });
  }

  /* ---- Key rotation ---- */
  async function loadKeys() {
    try {
      const r = await pfAdminKeys();
      let html = '<div class="p-6 rounded-xl border border-primary/40 bg-surface-container-low">' +
        '<div class="flex items-center gap-2 text-primary font-mono text-xs uppercase tracking-wider"><span class="material-symbols-outlined text-sm">key</span>Cryptographic Key Orchestration</div>' +
        '<p class="text-sm text-on-surface-variant mt-2 leading-relaxed">Generate fresh RSA-3072 + ElGamal keypairs for every user, retire the old ones, and refresh the vault. Rotations are instantaneous; existing ciphertext stays readable under the prior keys.</p>' +
        '<button id="pf-rotate" class="mt-3 w-full py-2.5 rounded-lg bg-primary text-on-primary text-xs font-semibold hover:bg-primary/90 transition-all shadow"><span class="material-symbols-outlined text-sm">sync_lock</span>Trigger Key Rotation</button></div>' +
        '<div class="p-4 rounded-xl border border-outline-variant bg-surface-container-lowest"><div class="text-xs font-mono uppercase tracking-wider text-on-surface-variant mb-2">Key Lifecycle</div>' +
        '<table class="w-full text-left text-sm"><thead><tr class="text-xs font-mono text-on-surface-variant"><th class="py-1.5 px-3">Algorithm</th><th class="py-1.5 px-3">Status</th><th class="py-1.5 px-3 text-right">Count</th></tr></thead><tbody>';
      r.keys.forEach(k => {
        html += '<tr class="border-b border-outline-variant/40"><td class="py-1.5 px-3 font-mono">' + esc(k['algorithm']) + '</td>' +
          '<td class="py-1.5 px-3 font-mono">' + esc(k['status']) + '</td><td class="py-1.5 px-3 text-right font-mono">' + k['COUNT(*)'] + '</td></tr>';
      });
      html += '</tbody></table></div>';
      document.getElementById('pf-a-keys').innerHTML = html;
      document.getElementById('pf-rotate').onclick = async () => {
        if (!confirm('Rotate ALL cryptographic keys for every user now?')) return;
        try {
          document.getElementById('pf-rotate').disabled = true;
          const res = await pfAdminRotate();
          status('Global rotation complete: ' + res.rotated_users + ' users rotated.', true);
          await loadKeys();
        } catch (err) { status(err.message, false); }
        finally { document.getElementById('pf-rotate').disabled = false; }
      };
    } catch (err) { status(err.message, false); }
  }

  /* ---- Integrity log ---- */
  async function loadIntegrity() {
    try {
      const r = await pfAdminIntegrity();
      let html = '<div class="overflow-x-auto rounded-xl border border-outline-variant bg-surface-container-lowest">';
      if (!r.entries.length) {
        html += '<div class="p-5 text-sm text-secondary">No integrity failures — the ledger is clean (all HMAC badges valid).</div>';
      } else {
        html += '<table class="w-full text-left text-sm"><thead><tr class="border-b border-outline-variant bg-surface-container/60 text-xs font-mono text-on-surface-variant uppercase tracking-wider">' +
          '<th class="py-2.5 px-4">Record</th><th class="py-2.5 px-4">ID</th><th class="py-2.5 px-4">Reason</th><th class="py-2.5 px-4 text-right">Time</th></tr></thead><tbody>';
        r.entries.forEach(e => {
          html += '<tr class="border-b border-outline-variant/40 hover:bg-surface-container/30">' +
            '<td class="py-2.5 px-4 font-mono text-error">' + esc(e['record_type']) + '</td>' +
            '<td class="py-2.5 px-4 font-mono">#' + e['record_id'] + '</td>' +
            '<td class="py-2.5 px-4 font-mono text-on-surface-variant">' + esc(e['reason']) + '</td>' +
            '<td class="py-2.5 px-4 text-right font-mono">' + timeAgo(e['created_at']) + '</td></tr>';
        });
        html += '</tbody></table>';
      }
      html += '</div>';
      document.getElementById('pf-a-integrity').innerHTML = html;
    } catch (err) { status(err.message, false); }
  }

  /* ---- Feed moderation ---- */
  async function loadPosts() {
    try {
      const r = await pfAdminPosts();
      let html = '';
      if (!r.posts.length) html = '<div class="p-6 rounded-xl border border-outline-variant bg-surface-container-lowest/60 text-sm text-on-surface-variant">No posts to moderate.</div>';
      r.posts.forEach(p => {
        html += '<div class="p-5 rounded-xl border ' + (p.integrity === 'verified' ? 'border-outline-variant bg-surface-container-lowest/60' : 'border-error/50 bg-surface-container-lowest') + '">' +
          '<div class="flex items-center justify-between text-xs text-on-surface-variant">' +
          '<span class="font-mono">@' + esc(p.author) + ' <span class="text-on-surface-variant/70">· ' + timeAgo(p.created_at) + '</span> <span class="text-outline">·</span> <span class="text-on-surface-variant/70">' + (p.comment_count || 0) + ' comments</span></span>' +
          '<span class="px-2 py-0.5 rounded text-[11px] font-mono ' + (p.integrity === 'verified' ? 'bg-secondary/10 text-secondary' : 'bg-error/10 text-error') + '">' + esc(p.integrity) + '</span></div>' +
          '<p class="mt-1.5 text-sm text-on-surface-variant whitespace-pre-wrap break-words">' + (p.content ? esc(p.content) : '<em class="text-error">UNDECRYPTABLE / TAMPERED</em>') + '</p>' +
          '<button data-id="' + p.id + '" class="pf-mod-del mt-2 px-3 py-1.5 rounded-lg border border-error/40 text-error hover:bg-error/10 text-xs font-mono"><span class="material-symbols-outlined text-sm">delete</span> Suppress / Delete</button></div>';
      });
      document.getElementById('pf-a-posts').innerHTML = html;
      document.querySelectorAll('.pf-mod-del').forEach(b => {
        b.onclick = async () => {
          if (!confirm('Suppress this dispatch and its comments (moderation)?')) return;
          try { await pfAdminDeletePost(Number(b.dataset.id)); status('Post suppressed.', true); await loadPosts(); }
          catch (err) { status(err.message, false); }
        };
      });
    } catch (err) { status(err.message, false); }
  }

  async function init() {
    let me;
    try { me = await pfMe(); } catch (_) { pfClearSession(); location.href = '/login/'; return; }
    if (me.role !== 'admin') { location.href = '/home/'; return; }
    pfInjectNav(me);
    bindTabs();
    await loadUsers();
    await loadKeys();
    await loadIntegrity();
    await loadPosts();
  }
  init();
})();