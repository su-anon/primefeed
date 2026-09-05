/* CipherDeck home page integration.
 * Requires an active session. Loads the dynamic ElGamal-encrypted feed,
 * renders it into the designed card style, provides a publish composer,
 * per-post comments, delete-own-post, and feed/messages/profile/admin nav.
 */

(function () {
  if (!pfRequireAuth()) return;

  const PAGE = 10;
  let offset = 0;
  let myId = null;

  const esc = (s) => String(s || '').replace(/[&<>"']/g,
    c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  function pfEnsureStatus() {
    if (document.getElementById('pf-msg')) return;
    const d = document.createElement('div');
    d.id = 'pf-msg';
    d.className = 'mb-4 px-3 py-2 border border-outline-variant bg-surface-container-lowest text-xs font-mono';
    d.textContent = '';
    const sec = streamSection();
    if (sec) sec.prepend(d);
  }
  function pfMsg(msg, ok) {
    pfEnsureStatus();
    const el = document.getElementById('pf-msg');
    el.textContent = msg;
    el.classList.remove('text-secondary', 'text-error');
    el.classList.add(ok === false ? 'text-error' : 'text-secondary');
  }

  function streamSection() {
    return [...document.querySelectorAll('section')].find(s => String(s.className).includes('col-span-8'));
  }

  function updateHeader(me) {
    pfInjectNav(me);   // fills username + avatar, reveals Admin, adds Sign out

    // "Write Dispatch" scrolls to the composer.
    const write = [...document.querySelectorAll('a')].find(a => a.textContent.includes('Write Dispatch'));
    if (write) write.href = '#';
    if (write) write.onclick = (e) => {
      e.preventDefault();
      document.getElementById('pf-content')?.focus();
    };
  }

  /* ---- comments ---- */
  function commentPanelHtml(p) {
    return '<div class="mt-2 hidden" id="pf-cc-' + p.id + '">' +
      '<div id="pf-cl-' + p.id + '" class="space-y-2 text-xs"></div>' +
      '<div class="flex items-center gap-2 mt-2">' +
      '<input id="pf-ci-' + p.id + '" maxlength="500" placeholder="Comment on this dispatch…" class="flex-1 px-3 py-1.5 rounded-lg bg-surface-container border border-outline-variant text-xs text-on-surface placeholder:text-on-surface-variant/60 focus:outline-none focus:border-primary"/>' +
      '<button data-pid="' + p.id + '" class="pf-c-add px-3 py-1.5 rounded-lg bg-primary/80 hover:bg-primary text-surface text-xs font-semibold">Post</button>' +
      '</div></div>';
  }

  function renderFeed(posts) {
    const sec = streamSection();
    if (!sec) return;

    let html = '';
    // Publish composer
    html += '<div class="p-4 rounded-xl border border-primary/40 bg-surface-container-lowest text-left">' +
      '<div class="flex items-center gap-2 text-primary font-mono text-xs uppercase tracking-wider">' +
      '<span class="material-symbols-outlined text-sm">add_circle</span><span>New Dispatch · ElGamal-encrypted at rest</span></div>' +
      '<textarea id="pf-content" rows="3" maxlength="500" placeholder="Publish an IoC, CVE note or short analysis (≤500 chars)…"' +
      ' class="mt-2 w-full px-3 py-2 rounded-lg bg-surface-container border border-outline-variant text-sm text-on-surface placeholder:text-on-surface-variant/60 focus:outline-none focus:border-primary"></textarea>' +
      '<button id="pf-publish" class="mt-2 w-full py-2.5 rounded-lg bg-primary text-on-primary text-xs font-semibold hover:bg-primary/90 transition-all shadow">' +
      '<span class="material-symbols-outlined text-sm">shield_lock</span><span>Publish Dispatch</span></button></div>';

    html += '<div class="flex items-center gap-1.5 pb-3 border-b border-outline-variant/80">' +
      '<button class="px-3.5 py-1.5 rounded-full text-xs font-semibold bg-on-surface text-surface">Latest</button>' +
      '<span class="text-xs text-on-surface-variant font-mono hidden sm:inline">HMAC-verified · zero plaintext at rest</span></div>';

    if (!posts.length) {
      html += '<div class="p-6 rounded-xl border border-outline-variant bg-surface-container-lowest/60 text-sm text-on-surface-variant">' +
        'No dispatches yet. Publish the first IoC or analysis above.</div>';
    }

    for (const p of posts) {
      const mine = myId != null && p.author_id === myId;
      html += '<article class="p-6 rounded-xl border border-outline-variant bg-surface-container-lowest/60 hover:bg-surface-container-low/80 hover:border-outline transition-all flex flex-col gap-3">' +
        '<div class="flex items-center justify-between text-xs text-on-surface-variant">' +
        '<div class="flex items-center gap-2">' +
        '<span class="font-medium text-on-surface">@' + esc(p.author) + '</span>' +
        '<span class="text-outline">·</span>' +
        '<span class="font-mono text-on-surface-variant/80">' + timeAgo(p.created_at) + '</span>' +
        '</div>' +
        '<span class="inline-flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded-full bg-secondary/10 text-secondary border border-secondary/20">' +
        '<span class="material-symbols-outlined text-xs">check_circle</span>' + esc(p.integrity) + '</span>' +
        '</div>' +
        '<p class="text-on-surface-variant text-sm leading-relaxed whitespace-pre-wrap break-words">' + esc(p.content) + '</p>' +
        '<div class="pt-3 border-t border-outline-variant/40 flex items-center justify-between text-xs text-on-surface-variant">' +
        '<div class="flex items-center gap-3">' +
        '<span class="px-2 py-0.5 rounded bg-surface-container text-on-surface-variant font-mono text-[11px]">dispatch#' + p.id + '</span>' +
        '<button data-pid="' + p.id + '" class="pf-c-toggle flex items-center gap-1 hover:text-primary transition-colors">' +
        '<span class="material-symbols-outlined text-sm">chat_bubble_outline</span><span>comments</span></button>' +
        (mine ? '<button data-pid="' + p.id + '" class="pf-post-del flex items-center gap-1 hover:text-error transition-colors">' +
        '<span class="material-symbols-outlined text-sm">delete</span><span>delete</span></button>' : '') +
        '</div>' +
        '</div>' +
        commentPanelHtml(p) +
        '</article>';
    }

    html += '<button id="pf-more" class="w-full py-3.5 rounded-xl border border-outline-variant bg-surface-container-lowest hover:bg-surface-container hover:text-primary hover:border-primary/50 text-sm font-semibold text-on-surface transition-all flex items-center justify-center gap-2">' +
      '<span class="material-symbols-outlined text-base">arrow_downward</span><span>Load More Dispatches</span></button>';

    sec.innerHTML = html;
    wireComposer();
    wirePostActions();
  }

  function wirePostActions() {
    document.querySelectorAll('.pf-c-toggle').forEach(b => {
      b.onclick = () => toggleComments(Number(b.dataset.pid));
    });
    document.querySelectorAll('.pf-c-add').forEach(b => {
      b.onclick = () => addComment(Number(b.dataset.pid));
    });
    document.querySelectorAll('.pf-post-del').forEach(b => {
      b.onclick = () => deletePost(Number(b.dataset.pid));
    });
  }

  async function toggleComments(postId) {
    const panel = document.getElementById('pf-cc-' + postId);
    if (!panel) return;
    const first = !panel.classList.contains('block');
    if (first || document.getElementById('pf-cl-' + postId).innerHTML === '') {
      try {
        const r = await pfComments(postId);
        let html = '';
        if (!r.comments.length) html = '<div class="text-on-surface-variant/70">No comments yet.</div>';
        r.comments.forEach(c => {
          html += '<div class="border border-outline-variant/40 rounded-lg px-2 py-1.5 bg-surface-container/40">' +
            '<div class="flex items-center justify-between text-[11px]">' +
            '<span class="font-mono text-primary">@' + esc(c.author) + ' <span class="text-on-surface-variant/70">· ' + timeAgo(c.created_at) + '</span></span>' +
            '</div>' +
            '<p class="text-on-surface-variant leading-snug mt-0.5">' + esc(c.content) + '</p></div>';
        });
        document.getElementById('pf-cl-' + postId).innerHTML = html;
      } catch (err) {
        pfMsg(err.message, false);
      }
    }
    panel.classList.toggle('block');
    panel.classList.toggle('hidden');
  }

  async function addComment(postId) {
    const input = document.getElementById('pf-ci-' + postId);
    const content = input.value.trim();
    if (!content) return;
    try {
      await pfAddComment(postId, content);
      input.value = '';
      await toggleComments(postId);
    } catch (err) {
      pfMsg(err.message, false);
    }
  }

  async function deletePost(postId) {
    if (!confirm('Delete this dispatch permanently?')) return;
    try {
      await pfDeletePost(postId);
      pfMsg('Dispatch deleted.', true);
      offset = 0;
      await loadFeed(false);
    } catch (err) {
      pfMsg(err.message, false);
    }
  }

  function wireComposer() {
    const btn = document.getElementById('pf-publish');
    if (!btn) return;
    btn.onclick = async () => {
      const c = document.getElementById('pf-content').value.trim();
      if (!c) { pfMsg('Enter a dispatch payload.', false); return; }
      btn.disabled = true;
      const label = btn.innerHTML;
      btn.innerHTML = '<span class="material-symbols-outlined text-sm">timer</span><span>Encrypting via ElGamal…</span>';
      try {
        await pfCreatePost(c);
        document.getElementById('pf-content').value = '';
        pfMsg('Dispatch published and HMAC-badged.', true);
        offset = 0;
        await loadFeed(false);
      } catch (err) {
        pfMsg(err.message, false);
      } finally {
        btn.disabled = false;
        btn.innerHTML = label;
      }
    };
    const more = document.getElementById('pf-more');
    if (more) more.onclick = () => loadFeed(false);
  }

  async function loadFeed(_reset) {
    try {
      const r = await pfFeed(PAGE, offset);
      offset += r.posts.length;
      renderFeed(r.posts);
    } catch (err) {
      pfMsg(err.message, false);
    }
  }

  async function init() {
    let me;
    try { me = await pfMe(); }
    catch (_) { pfClearSession(); location.href = '/login/'; return; }
    window.pfMe = () => Promise.resolve(me);
    myId = me.user_id;
    updateHeader(me);
    await loadFeed(false);
  }
  init();
})();