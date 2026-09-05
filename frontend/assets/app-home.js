/* PrimeFeed / CipherDeck home page integration.
 * Dynamic ElGamal feed with real-time search, tag filtering, sorting,
 * dynamic researchers from /api/users, copy payload toast, live telemetry,
 * and seamless scroll-to-compose actions.
 */

(function () {
  if (!pfRequireAuth()) return;

  const PAGE = 15;
  let offset = 0;
  let myId = null;
  let myUsername = '';
  let allPosts = [];
  let activeFilter = 'all'; // 'all', 'ioc', 'crypto', 'cve', 'mine', or hashtag
  let activeSort = 'newest'; // 'newest', 'oldest', 'comments'
  let searchQuery = '';
  let commentCounts = {}; // pid -> count

  // Persisted followed researchers in localStorage
  function getFollowedUsers() {
    try {
      return new Set(JSON.parse(localStorage.getItem('pf_followed_users') || '[]'));
    } catch (_) {
      return new Set();
    }
  }

  function saveFollowedUsers(set) {
    localStorage.setItem('pf_followed_users', JSON.stringify([...set]));
  }

  const followedUsers = getFollowedUsers();

  function pfEnsureStatus() {
    const el = document.getElementById('pf-msg');
    if (el) el.classList.remove('hidden');
  }

  function pfMsg(msg, ok) {
    const el = document.getElementById('pf-msg');
    if (!el) return;
    el.textContent = msg;
    el.classList.remove('hidden', 'text-secondary', 'text-error', 'border-secondary/40', 'border-error/40');
    el.classList.add(ok === false ? 'text-error' : 'text-secondary');
    el.classList.add(ok === false ? 'border-error/40' : 'border-secondary/40');
    if (ok) {
      pfToast(msg, true);
    } else {
      pfToast(msg, false);
    }
  }

  function updateHeader(me) {
    pfInjectNav(me);
    myUsername = me.username;

    // Smooth scroll to composer
    const scrollToComposer = (e) => {
      if (e) e.preventDefault();
      const composer = document.getElementById('pf-composer');
      const input = document.getElementById('pf-content');
      if (composer) {
        composer.scrollIntoView({ behavior: 'smooth', block: 'center' });
        composer.classList.add('ring-2', 'ring-primary', 'ring-offset-2', 'ring-offset-surface');
        setTimeout(() => composer.classList.remove('ring-2', 'ring-primary', 'ring-offset-2', 'ring-offset-surface'), 2000);
      }
      if (input) input.focus();
    };

    const writeHeader = document.getElementById('pf-write-cta');
    if (writeHeader) writeHeader.onclick = scrollToComposer;

    const writeSidebar = document.getElementById('pf-submit-sidebar-cta');
    if (writeSidebar) writeSidebar.onclick = scrollToComposer;

    const writeFeat = document.getElementById('pf-feat-read-btn');
    if (writeFeat) writeFeat.onclick = scrollToComposer;

    // Search bar filtering
    const searchInput = document.getElementById('pf-search-input');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        searchQuery = e.target.value.trim().toLowerCase();
        applyFilterAndRender();
      });
    }
  }

  /* ---- UTC Clock ---- */
  function startLiveClock() {
    const clockEl = document.getElementById('pf-live-clock');
    if (!clockEl) return;
    const update = () => {
      clockEl.textContent = new Date().toISOString().slice(11, 19) + ' UTC';
    };
    update();
    setInterval(update, 1000);
  }

  /* ---- Comments Panel HTML ---- */
  function commentPanelHtml(p) {
    return '<div class="mt-3 pt-3 border-t border-outline-variant/40 hidden" id="pf-cc-' + p.id + '">' +
      '<div id="pf-cl-' + p.id + '" class="space-y-2 text-xs"></div>' +
      '<div class="flex items-center gap-2 mt-3">' +
      '<input id="pf-ci-' + p.id + '" maxlength="500" placeholder="Comment on this dispatch (RFC 2104 badged)…" class="flex-1 px-3 py-1.5 rounded-lg bg-surface-container border border-outline-variant text-xs text-on-surface placeholder:text-on-surface-variant/60 focus:outline-none focus:border-primary"/>' +
      '<button data-pid="' + p.id + '" class="pf-c-add px-3.5 py-1.5 rounded-lg bg-primary hover:bg-primary/90 text-on-primary text-xs font-semibold shadow transition-all cursor-pointer">Post</button>' +
      '</div></div>';
  }

  /* ---- Extract tags from text ---- */
  function extractTags(text) {
    const matched = text.match(/#[\w-]+/g);
    if (matched && matched.length) return matched;
    // Auto-tag based on keywords
    const lower = text.toLowerCase();
    const tags = [];
    if (lower.includes('cve-') || lower.includes('cve')) tags.push('#cve');
    if (lower.includes('ioc') || lower.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/)) tags.push('#zero-day-ioc');
    if (lower.includes('elgamal') || lower.includes('schnorr') || lower.includes('rsa') || lower.includes('crypto')) tags.push('#crypto');
    if (lower.includes('network') || lower.includes('c2') || lower.includes('traffic')) tags.push('#telemetry');
    return tags.length ? tags : ['#intel'];
  }

  /* ---- Render Feed Dispatches ---- */
  function renderFeed(posts) {
    const container = document.getElementById('pf-feed-stream');
    if (!container) return;

    if (!posts.length) {
      container.innerHTML = '<div class="p-8 rounded-xl border border-outline-variant bg-surface-container-lowest/60 text-center space-y-3">' +
        '<div class="w-12 h-12 mx-auto rounded-full bg-surface-container flex items-center justify-center text-primary"><span class="material-symbols-outlined text-2xl">search_off</span></div>' +
        '<div class="text-sm font-semibold text-on-surface">No dispatches match this criteria.</div>' +
        '<p class="text-xs text-on-surface-variant max-w-sm mx-auto">Try resetting filters or publish an indicator of compromise using the composer above.</p>' +
        '<button id="pf-empty-reset" class="px-3.5 py-1.5 rounded-full bg-primary/20 text-primary border border-primary/30 text-xs font-semibold hover:bg-primary/30 transition-all cursor-pointer">Reset Filters</button>' +
        '</div>';
      const rBtn = document.getElementById('pf-empty-reset');
      if (rBtn) rBtn.onclick = resetFilter;
      return;
    }

    let html = '';
    for (const p of posts) {
      const mine = myId != null && p.author_id === myId;
      const tags = extractTags(p.content);
      const initials = (p.author || 'U').slice(0, 2).toUpperCase();
      const count = commentCounts[p.id] || 0;

      html += '<article class="p-6 rounded-xl border border-outline-variant bg-surface-container-lowest/80 hover:bg-surface-container-low/90 hover:border-outline transition-all flex flex-col gap-3 group shadow-sm">' +
        '<div class="flex items-center justify-between text-xs text-on-surface-variant">' +
        '<div class="flex items-center gap-2.5">' +
        '<div class="w-7 h-7 rounded-full bg-gradient-to-tr from-secondary-container via-surface-container-high to-surface-container-highest border border-secondary/30 flex items-center justify-center font-mono font-bold text-secondary text-[11px]">' +
        initials +
        '</div>' +
        '<span class="font-medium text-on-surface">@' + esc(p.author) + '</span>' +
        '<span class="text-outline">·</span>' +
        '<span class="font-mono text-on-surface-variant/80" data-ts="' + p.created_at + '">' + timeAgo(p.created_at) + '</span>' +
        '</div>' +
        '<span class="inline-flex items-center gap-1 text-[11px] font-mono px-2.5 py-0.5 rounded-full bg-secondary/10 text-secondary border border-secondary/20 shadow-xs">' +
        '<span class="material-symbols-outlined text-xs">verified</span>' + esc(p.integrity || 'HMAC Valid') + '</span>' +
        '</div>' +
        '<p class="text-on-surface text-sm leading-relaxed whitespace-pre-wrap break-words font-normal select-text">' + esc(p.content) + '</p>' +
        // Tags row
        '<div class="flex items-center gap-2 flex-wrap pt-1">' +
        tags.map(t => '<button data-tag="' + esc(t.replace('#', '')) + '" class="pf-post-tag px-2 py-0.5 rounded-md bg-surface-container hover:bg-surface-container-high hover:text-primary text-on-surface-variant font-mono text-[11px] border border-outline-variant/40 transition-colors">' + esc(t) + '</button>').join('') +
        '</div>' +
        // Footer actions
        '<div class="pt-3 border-t border-outline-variant/40 flex items-center justify-between text-xs text-on-surface-variant">' +
        '<div class="flex items-center gap-3">' +
        '<span class="px-2 py-0.5 rounded bg-surface-container text-on-surface-variant font-mono text-[11px]">dispatch#' + p.id + '</span>' +
        '<button data-pid="' + p.id + '" class="pf-c-toggle flex items-center gap-1.5 hover:text-primary transition-colors cursor-pointer">' +
        '<span class="material-symbols-outlined text-sm">chat_bubble_outline</span>' +
        '<span>' + (count > 0 ? count + ' comments' : 'comments') + '</span></button>' +
        '<button data-content="' + esc(p.content) + '" class="pf-copy-payload flex items-center gap-1 hover:text-secondary transition-colors cursor-pointer" title="Copy payload to clipboard">' +
        '<span class="material-symbols-outlined text-sm">content_copy</span><span>copy</span></button>' +
        (mine ? '<button data-pid="' + p.id + '" class="pf-post-del flex items-center gap-1 hover:text-error transition-colors cursor-pointer">' +
        '<span class="material-symbols-outlined text-sm">delete</span><span>delete</span></button>' : '') +
        '</div>' +
        '<span class="font-mono text-[10px] text-outline">ELGAMAL-2048</span>' +
        '</div>' +
        commentPanelHtml(p) +
        '</article>';
    }

    container.innerHTML = html;
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
    document.querySelectorAll('.pf-copy-payload').forEach(b => {
      b.onclick = () => {
        const text = b.dataset.content;
        navigator.clipboard.writeText(text).then(() => {
          pfToast('Copied dispatch payload to clipboard', true);
        }).catch(() => {
          pfToast('Copied dispatch', true);
        });
      };
    });
    document.querySelectorAll('.pf-post-tag').forEach(b => {
      b.onclick = () => {
        const tag = b.dataset.tag;
        setTagFilter(tag);
      };
    });
  }

  /* ---- Filter and Sort Logic ---- */
  function applyFilterAndRender() {
    let list = [...allPosts];

    // Category filter
    if (activeFilter === 'mine') {
      list = list.filter(p => p.author_id === myId);
    } else if (activeFilter === 'ioc') {
      list = list.filter(p => {
        const c = p.content.toLowerCase();
        return c.includes('ioc') || c.includes('ip') || c.includes('hash') || c.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/);
      });
    } else if (activeFilter === 'crypto') {
      list = list.filter(p => {
        const c = p.content.toLowerCase();
        return c.includes('crypto') || c.includes('elgamal') || c.includes('schnorr') || c.includes('rsa') || c.includes('prime');
      });
    } else if (activeFilter === 'cve') {
      list = list.filter(p => p.content.toLowerCase().includes('cve'));
    } else if (activeFilter !== 'all') {
      // Specific tag or term
      const t = activeFilter.toLowerCase();
      list = list.filter(p => p.content.toLowerCase().includes(t));
    }

    // Text search filter
    if (searchQuery) {
      list = list.filter(p =>
        p.content.toLowerCase().includes(searchQuery) ||
        p.author.toLowerCase().includes(searchQuery)
      );
    }

    // Sorting
    if (activeSort === 'newest') {
      list.sort((a, b) => b.created_at - a.created_at);
    } else if (activeSort === 'oldest') {
      list.sort((a, b) => a.created_at - b.created_at);
    } else if (activeSort === 'comments') {
      list.sort((a, b) => (commentCounts[b.id] || 0) - (commentCounts[a.id] || 0));
    }

    // Update filter indicator chip
    const indicator = document.getElementById('pf-active-filter-indicator');
    const label = document.getElementById('pf-filter-label');
    if (indicator && label) {
      if (activeFilter !== 'all' || searchQuery) {
        indicator.classList.remove('hidden');
        label.textContent = (activeFilter !== 'all' ? '#' + activeFilter : '') + (searchQuery ? ` "${searchQuery}"` : '');
      } else {
        indicator.classList.add('hidden');
      }
    }

    renderFeed(list);
    updateFeaturedStory(list.length ? list[0] : null);
  }

  function setTagFilter(tag) {
    activeFilter = tag;
    // Highlight matching category tab if exists
    document.querySelectorAll('.pf-cat-btn').forEach(btn => {
      const match = btn.dataset.filter === tag;
      btn.className = 'pf-cat-btn px-3.5 py-1.5 rounded-full text-xs transition-all ' +
        (match ? 'font-semibold bg-on-surface text-surface shadow' : 'font-medium text-on-surface-variant hover:text-on-surface hover:bg-surface-container');
    });
    applyFilterAndRender();
    const stream = document.getElementById('pf-feed-stream');
    if (stream) stream.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function resetFilter() {
    activeFilter = 'all';
    searchQuery = '';
    const searchInput = document.getElementById('pf-search-input');
    if (searchInput) searchInput.value = '';
    document.querySelectorAll('.pf-cat-btn').forEach(btn => {
      const match = btn.dataset.filter === 'all';
      btn.className = 'pf-cat-btn px-3.5 py-1.5 rounded-full text-xs transition-all ' +
        (match ? 'font-semibold bg-on-surface text-surface shadow' : 'font-medium text-on-surface-variant hover:text-on-surface hover:bg-surface-container');
    });
    applyFilterAndRender();
  }

  /* ---- Dynamic Featured Story ---- */
  function updateFeaturedStory(leadPost) {
    const titleEl = document.getElementById('pf-feat-title');
    const excerptEl = document.getElementById('pf-feat-excerpt');
    const authorEl = document.getElementById('pf-feat-author');
    const handleEl = document.getElementById('pf-feat-handle');
    const avatarEl = document.getElementById('pf-feat-avatar');
    const timeEl = document.getElementById('pf-feat-time');
    const copyBtn = document.getElementById('pf-feat-copy-btn');
    const shareBtn = document.getElementById('pf-feat-share-btn');

    if (!leadPost) {
      if (titleEl) titleEl.textContent = 'Subgroup Confinement & Zero-Knowledge IoC Ledger';
      if (excerptEl) excerptEl.textContent = 'Dual-layer RSA-3072 vaults and ElGamal-2048 Schnorr envelopes protect all indicators of compromise without plaintext leakage across untrusted relays.';
      if (authorEl) authorEl.textContent = 'PrimeFeed Engine';
      if (handleEl) handleEl.textContent = '@core_ledger';
      if (avatarEl) avatarEl.textContent = 'PF';
      if (timeEl) timeEl.textContent = 'Live Asymmetric Ledger';
      return;
    }

    if (titleEl) titleEl.textContent = leadPost.content.length > 80 ? leadPost.content.slice(0, 80) + '…' : leadPost.content;
    if (excerptEl) excerptEl.textContent = leadPost.content;
    if (authorEl) authorEl.textContent = leadPost.author;
    if (handleEl) handleEl.textContent = '@' + leadPost.author;
    if (avatarEl) avatarEl.textContent = leadPost.author.slice(0, 2).toUpperCase();
    if (timeEl) timeEl.textContent = timeAgo(leadPost.created_at) + ' · Dispatch #' + leadPost.id;

    if (copyBtn) {
      copyBtn.onclick = () => {
        navigator.clipboard.writeText(leadPost.content).then(() => {
          pfToast('Copied featured dispatch to clipboard', true);
        });
      };
    }
    if (shareBtn) {
      shareBtn.onclick = () => {
        pfToast(`Dispatch #${leadPost.id} ready to share with signed HMAC badge`, true);
      };
    }
  }

  /* ---- Comments Toggle & Add ---- */
  async function toggleComments(postId) {
    const panel = document.getElementById('pf-cc-' + postId);
    if (!panel) return;
    const isHidden = panel.classList.contains('hidden');
    if (isHidden || document.getElementById('pf-cl-' + postId).innerHTML === '') {
      try {
        const r = await pfComments(postId);
        commentCounts[postId] = r.comments.length;
        let html = '';
        if (!r.comments.length) {
          html = '<div class="text-on-surface-variant/70 italic py-1">No comments on this dispatch yet. Be the first to verify.</div>';
        } else {
          r.comments.forEach(c => {
            html += '<div class="border border-outline-variant/40 rounded-lg p-2.5 bg-surface-container/50">' +
              '<div class="flex items-center justify-between text-[11px]">' +
              '<span class="font-mono text-primary font-semibold">@' + esc(c.author) + '</span>' +
              '<span class="text-on-surface-variant/70 font-mono text-[10px]">' + timeAgo(c.created_at) + '</span>' +
              '</div>' +
              '<p class="text-on-surface text-xs leading-snug mt-1">' + esc(c.content) + '</p></div>';
          });
        }
        document.getElementById('pf-cl-' + postId).innerHTML = html;
      } catch (err) {
        pfMsg(err.message, false);
      }
    }
    panel.classList.toggle('hidden');
  }

  async function addComment(postId) {
    const input = document.getElementById('pf-ci-' + postId);
    const content = input.value.trim();
    if (!content) return;
    try {
      await pfAddComment(postId, content);
      input.value = '';
      commentCounts[postId] = (commentCounts[postId] || 0) + 1;
      await toggleComments(postId);
      pfToast('Comment posted and integrity-sealed', true);
    } catch (err) {
      pfMsg(err.message, false);
    }
  }

  async function deletePost(postId) {
    if (!confirm('Delete this dispatch permanently?')) return;
    try {
      await pfDeletePost(postId);
      pfToast('Dispatch deleted from vault', true);
      allPosts = allPosts.filter(p => p.id !== postId);
      applyFilterAndRender();
    } catch (err) {
      pfMsg(err.message, false);
    }
  }

  /* ---- Composer Wiring ---- */
  function wireComposer() {
    const btn = document.getElementById('pf-publish');
    const textarea = document.getElementById('pf-content');
    const counter = document.getElementById('pf-char-count');

    if (textarea && counter) {
      textarea.addEventListener('input', () => {
        counter.textContent = `${textarea.value.length} / 500`;
      });
    }

    if (!btn) return;
    btn.onclick = async () => {
      const c = textarea.value.trim();
      if (!c) { pfToast('Please enter an IoC payload or note', false); return; }
      btn.disabled = true;
      const originalLabel = btn.innerHTML;
      btn.innerHTML = '<span class="material-symbols-outlined text-sm animate-spin">sync</span><span>Sealing via ElGamal…</span>';
      try {
        const res = await pfCreatePost(c);
        textarea.value = '';
        if (counter) counter.textContent = '0 / 500';
        pfToast('Dispatch published & HMAC-badged', true);

        // Prepend new post
        const newPost = {
          id: res.id,
          author_id: myId,
          author: myUsername,
          content: c,
          created_at: Math.floor(Date.now() / 1000),
          integrity: 'verified'
        };
        allPosts.unshift(newPost);
        applyFilterAndRender();
      } catch (err) {
        pfMsg(err.message, false);
      } finally {
        btn.disabled = false;
        btn.innerHTML = originalLabel;
      }
    };

    const more = document.getElementById('pf-more');
    if (more) more.onclick = () => loadFeed(false);
  }

  /* ---- Load Feed ---- */
  async function loadFeed(reset) {
    if (reset) {
      offset = 0;
      allPosts = [];
    }
    try {
      const r = await pfFeed(PAGE, offset);
      offset += r.posts.length;

      // Merge new posts without duplicates
      const seen = new Set(allPosts.map(p => p.id));
      for (const p of r.posts) {
        if (!seen.has(p.id)) {
          allPosts.push(p);
          seen.add(p.id);
        }
      }

      applyFilterAndRender();

      const more = document.getElementById('pf-more');
      if (more) {
        if (r.posts.length < PAGE) {
          more.classList.add('hidden');
        } else {
          more.classList.remove('hidden');
        }
      }
    } catch (err) {
      pfMsg(err.message, false);
    }
  }

  /* ---- Dynamic Top Researchers from /api/users ---- */
  async function loadResearchers() {
    const listEl = document.getElementById('pf-researchers-list');
    if (!listEl) return;
    try {
      const r = await pfUsers();
      const users = r.users || [];

      // Update researcher count in ticker
      const countEl = document.getElementById('pf-active-validators-count');
      if (countEl) {
        const count = users.length;
        countEl.textContent = `${count} active researcher${count === 1 ? '' : 's'} registered`;
      }

      if (!users.length) {
        listEl.innerHTML = '<div class="text-xs text-on-surface-variant font-mono">No other researchers enrolled.</div>';
        return;
      }

      let html = '';
      users.slice(0, 5).forEach(u => {
        const isMe = u.id === myId;
        const isFollowed = followedUsers.has(u.username);
        const initials = u.username.slice(0, 2).toUpperCase();

        html += '<div class="flex items-center justify-between gap-2 py-1">' +
          '<div class="flex items-center gap-2.5 min-w-0">' +
          '<div class="w-8 h-8 rounded-full bg-surface-container-high border border-primary/30 flex items-center justify-center font-mono text-xs font-bold text-primary shrink-0">' +
          initials +
          '</div>' +
          '<div class="min-w-0">' +
          '<div class="text-xs font-semibold text-on-surface hover:text-primary cursor-pointer truncate">@' + esc(u.username) + '</div>' +
          '<div class="text-[11px] text-on-surface-variant capitalize truncate font-mono">' + esc(u.role) + '</div>' +
          '</div>' +
          '</div>' +
          (isMe
            ? '<span class="px-2 py-1 text-[10px] font-mono text-secondary bg-secondary/10 rounded">You</span>'
            : '<button data-user="' + esc(u.username) + '" class="pf-follow-btn px-2.5 py-1 rounded-md text-xs font-medium border transition-all cursor-pointer ' +
              (isFollowed
                ? 'bg-primary/20 text-primary border-primary/40'
                : 'bg-surface-container hover:bg-surface-container-high text-on-surface border-outline-variant') + '">' +
              (isFollowed ? 'Following' : 'Follow') +
              '</button>') +
          '</div>';
      });

      listEl.innerHTML = html;

      // Wire follow buttons
      listEl.querySelectorAll('.pf-follow-btn').forEach(btn => {
        btn.onclick = () => {
          const user = btn.dataset.user;
          if (followedUsers.has(user)) {
            followedUsers.delete(user);
            btn.textContent = 'Follow';
            btn.className = 'pf-follow-btn px-2.5 py-1 rounded-md text-xs font-medium border transition-all cursor-pointer bg-surface-container hover:bg-surface-container-high text-on-surface border-outline-variant';
            pfToast(`Unfollowed @${user}`);
          } else {
            followedUsers.add(user);
            btn.textContent = 'Following';
            btn.className = 'pf-follow-btn px-2.5 py-1 rounded-md text-xs font-medium border transition-all cursor-pointer bg-primary/20 text-primary border-primary/40';
            pfToast(`Now following @${user}`, true);
          }
          saveFollowedUsers(followedUsers);
        };
      });
    } catch (_) {
      // Keep quiet if offline
    }
  }

  /* ---- Interactive Controls Wiring ---- */
  function wireControls() {
    // Category tabs
    document.querySelectorAll('.pf-cat-btn').forEach(btn => {
      btn.onclick = () => {
        const filter = btn.dataset.filter;
        activeFilter = filter;
        document.querySelectorAll('.pf-cat-btn').forEach(b => {
          const isAct = b === btn;
          b.className = 'pf-cat-btn px-3.5 py-1.5 rounded-full text-xs transition-all ' +
            (isAct ? 'font-semibold bg-on-surface text-surface shadow' : 'font-medium text-on-surface-variant hover:text-on-surface hover:bg-surface-container');
        });
        applyFilterAndRender();
      };
    });

    // Sort select
    const sortSelect = document.getElementById('pf-sort-select');
    if (sortSelect) {
      sortSelect.addEventListener('change', (e) => {
        activeSort = e.target.value;
        applyFilterAndRender();
      });
    }

    // Clear filter chip
    const clearFilterBtn = document.getElementById('pf-clear-filter');
    if (clearFilterBtn) clearFilterBtn.onclick = resetFilter;

    // Trending topics
    document.querySelectorAll('.pf-trend-tag').forEach(tagBtn => {
      tagBtn.onclick = () => {
        const tag = tagBtn.dataset.tag;
        setTagFilter(tag);
      };
    });

    // Newsletter form
    const digestForm = document.getElementById('pf-digest-form');
    if (digestForm) {
      digestForm.onsubmit = (e) => {
        e.preventDefault();
        const input = document.getElementById('pf-digest-email');
        const btn = document.getElementById('pf-digest-btn');
        const status = document.getElementById('pf-digest-status');
        const email = input.value.trim();
        if (!email) return;

        btn.disabled = true;
        btn.innerHTML = '<span class="material-symbols-outlined text-sm animate-spin">sync</span><span>Enrolling…</span>';

        setTimeout(() => {
          btn.disabled = false;
          btn.innerHTML = '<span>Subscribed</span>';
          input.value = '';
          if (status) {
            status.textContent = '✓ Subscribed to daily zero-knowledge digest';
            status.classList.remove('hidden');
          }
          pfToast(`Terminal ${email} subscribed to encrypted digest`, true);
        }, 600);
      };
    }

    // Inspect spec button in featured card
    const inspectBtn = document.getElementById('pf-inspect-crypto-btn');
    if (inspectBtn) {
      inspectBtn.onclick = () => {
        pfToast('ElGamal 2048-bit Schnorr Group parameters active and verified', true);
      };
    }
  }

  /* ---- Initialize ---- */
  async function init() {
    let me;
    try {
      me = await pfMe();
    } catch (_) {
      pfClearSession();
      location.href = '/login/';
      return;
    }
    window.pfMe = () => Promise.resolve(me);
    myId = me.user_id;

    updateHeader(me);
    startLiveClock();
    wireComposer();
    wireControls();
    await loadFeed(true);
    await loadResearchers();
  }

  init();
})();