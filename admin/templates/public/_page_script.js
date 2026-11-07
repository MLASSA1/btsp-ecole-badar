    // ---- Old one-page links ----
    // The site used to be a single page with #anchors. Links already shared
    // or indexed (/#formations, /en/#pro-contact, /#cat=state) now forward to
    // the page that holds that content.
    (function () {
      const body = document.body;
      if (!body.classList.contains('page-home') || !location.hash) return;
      const lp = {{ lp|tojson }};
      const moved = {
        '#services': '/services', '#catalogue': '/catalogue', '#references': '/references',
        '#formations': '/formations', '#poles': '/formations', '#admission': '/formations',
        '#en-ligne': '/en-ligne', '#certificats': '/certificats', '#apropos': '/a-propos',
        '#galerie': '/a-propos', '#contact': '/contact', '#pro-contact': '/devis'
      };
      if (moved[location.hash]) { location.replace(lp + moved[location.hash]); return; }
      const cat = location.hash.match(/^#cat=([a-z]+)$/);
      if (cat) location.replace(lp + '/formations' + location.hash);
    })();

    // ---- Programme category filter ----
    const tabs = [...document.querySelectorAll('.formation-tabs .tab')];
    const cards = [...document.querySelectorAll('.formation-card')];
    const grid = document.querySelector('.formations-grid');

    // A live count, and a message when a filter matches nothing, so the grid is
    // never just silently empty.
    let countEl = null, emptyEl = null;
    if (grid) {
      countEl = document.createElement('p');
      countEl.className = 'formations-count';
      countEl.setAttribute('aria-live', 'polite');
      grid.parentNode.insertBefore(countEl, grid);

      emptyEl = document.createElement('p');
      emptyEl.className = 'formations-empty';
      emptyEl.hidden = true;
      emptyEl.textContent = {{ t.formations_empty|tojson }};
      grid.parentNode.insertBefore(emptyEl, grid.nextSibling);
    }

    function applyFilter(cat, push) {
      tabs.forEach(t => {
        const on = t.dataset.cat === cat;
        t.classList.toggle('active', on);
        t.setAttribute('aria-selected', String(on));
        t.tabIndex = on ? 0 : -1;
      });
      let shown = 0;
      cards.forEach(card => {
        const visible = cat === 'all' || card.dataset.category === cat
          || (cat === 'state' && card.dataset.state === '1');
        card.hidden = !visible;
        if (visible) shown++;
      });
      if (countEl) countEl.textContent = shown + ' ' + (shown > 1 ? {{ t.formations_count_plural|tojson }} : {{ t.formations_count_one|tojson }});
      if (emptyEl) emptyEl.hidden = shown !== 0;
      // Remember the choice so reload and the back button keep it.
      if (push) history.replaceState(null, '', cat === 'all' ? location.pathname + '#formations' : location.pathname + '#cat=' + cat);
    }

    tabs.forEach(tab => tab.addEventListener('click', () => applyFilter(tab.dataset.cat, true)));

    // Arrow keys move between tabs, as a tablist should.
    tabs.forEach((tab, i) => tab.addEventListener('keydown', e => {
      const dir = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
      if (!dir) return;
      e.preventDefault();
      const next = tabs[(i + dir + tabs.length) % tabs.length];
      next.focus();
      applyFilter(next.dataset.cat, true);
    }));

    // Restore a category from the URL (#cat=health) on load.
    const fromHash = (location.hash.match(/^#cat=([a-z]+)$/) || [])[1];
    applyFilter(fromHash && tabs.some(t => t.dataset.cat === fromHash) ? fromHash : 'all', false);
    if (fromHash) document.getElementById('formations')?.scrollIntoView({ behavior: 'auto', block: 'start' });

    // ---- Jump from a pôle card straight to its filtered programmes ----
    document.querySelectorAll('.pillar-card[data-goto] .link-arrow').forEach(link => {
      link.addEventListener('click', () => applyFilter(link.closest('.pillar-card').dataset.goto, true));
    });

    // ---- Professional enquiry form switcher ----
    const proTabs = [...document.querySelectorAll('.pro-tab')];
    function showPane(name) {
      proTabs.forEach(t => {
        const on = t.dataset.form === name;
        t.classList.toggle('active', on);
        t.setAttribute('aria-selected', String(on));
        t.tabIndex = on ? 0 : -1;
      });
      document.querySelectorAll('[id^="pane-"]').forEach(p => { p.hidden = p.id !== 'pane-' + name; });
    }
    proTabs.forEach((tab, i) => {
      tab.addEventListener('click', () => showPane(tab.dataset.form));
      tab.addEventListener('keydown', e => {
        const dir = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
        if (!dir) return;
        e.preventDefault();
        const next = proTabs[(i + dir + proTabs.length) % proTabs.length];
        next.focus();
        showPane(next.dataset.form);
      });
    });

    handleFormSubmit(document.getElementById('contactForm'), '/api/inscription', T.form_submit);
    handleFormSubmit(document.getElementById('corporateForm'), '/api/inscription', T.form_corporate_submit);
    handleFormSubmit(document.getElementById('proposalForm'), '/api/proposal', T.proposal_submit);

    // ---- Animated stat counters ----
    // requestAnimationFrame with easing rather than a fixed-step interval, so
    // the count lands exactly on the real figure at the same moment on any
    // device, and is skipped entirely for reduced-motion users.
    if ('IntersectionObserver' in window && !reduceMotion) {
      const counterObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
          if (!entry.isIntersecting) return;
          const el = entry.target;
          counterObserver.unobserve(el);
          const template = el.textContent;
          const match = template.match(/(\d+)/);
          if (!match) return;
          const target = parseInt(match[1], 10);
          const started = performance.now();
          const DURATION = 1100;
          (function step(now) {
            const p = Math.min((now - started) / DURATION, 1);
            const eased = 1 - Math.pow(1 - p, 3);          // ease-out cubic
            el.textContent = template.replace(match[1], String(Math.round(target * eased)));
            if (p < 1) requestAnimationFrame(step);
            else el.textContent = template;                 // land on the exact value
          })(started);
          // If rAF is throttled (backgrounded tab, reduced power mode) the count
          // can stall on a number that is simply wrong. Snap it back to the truth.
          setTimeout(() => { el.textContent = template; }, DURATION + 600);
        });
      }, { threshold: 0.6 });
      document.querySelectorAll('.stat-number').forEach(el => counterObserver.observe(el));
    }
