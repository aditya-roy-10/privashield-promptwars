/* =====================================================================
   PRIVASHIELD — router.js (Stage 5B). Landing page, hash router
      (#/ landing · #/app workspace), workspace sidebar, scroll-spy,
      reveal animations, mobile menu and theme sync.
      Privacy: switching views only toggles element visibility — nothing
      is copied, persisted, or transmitted.
   ===================================================================== */

import { restartFlash } from './session.js';

export function initRouter({ onDemoLoad }) {
  document.documentElement.classList.add('js');
  const nav = document.getElementById('landingNav');
  const landing = document.getElementById('landingView');
  const app = document.getElementById('appView');
  const menu = document.getElementById('mobileMenu');
  const btnMenu = document.getElementById('btnMenu');
  let inApp = false;

  function setHash(h) {
    if (location.hash !== h) {
      try {
        history.pushState(null, '', h);
      } catch {
        location.hash = h;
      }
    }
  }

  function flashTarget(el) {
    if (!el) return;
    el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    restartFlash(el);
  }

  function markSide(id) {
    document.querySelectorAll('#appSidebar .side-item[data-go]').forEach((b) => {
      b.classList.toggle('active', b.getAttribute('data-go') === id);
    });
  }

  function closeMenu() {
    if (menu) menu.classList.remove('open');
    if (btnMenu) btnMenu.setAttribute('aria-expanded', 'false');
  }

  function showApp(target) {
    inApp = true;
    nav.hidden = true;
    landing.hidden = true;
    app.hidden = false;
    setHash('#/app');
    closeMenu();
    if (target) {
      const el = document.getElementById(target);
      if (el) {
        if (target === 'privacyPanel' && !el.classList.contains('show')) {
          el.classList.add('show');
          const bp = document.getElementById('btnPrivacy');
          if (bp) bp.setAttribute('aria-expanded', 'true');
        }
        markSide(target);
        setTimeout(() => flashTarget(el), 60);
        return;
      }
    }
    window.scrollTo(0, 0);
  }

  function showLanding(anchor) {
    inApp = false;
    app.hidden = true;
    nav.hidden = false;
    landing.hidden = false;
    setHash(anchor ? `#${anchor}` : '#/');
    if (anchor) {
      const el = document.getElementById(anchor);
      if (el) setTimeout(() => el.scrollIntoView({ behavior: 'smooth', block: 'start' }), 60);
    } else {
      window.scrollTo(0, 0);
    }
  }

  document.querySelectorAll('[data-app-link]').forEach((el) => {
    el.addEventListener('click', (e) => {
      if (el.tagName === 'A') e.preventDefault();
      showApp(el.getAttribute('data-app-target') || null);
    });
  });

  document.querySelectorAll('[data-demo-link]').forEach((el) => {
    el.addEventListener('click', (e) => {
      if (el.tagName === 'A') e.preventDefault();
      showApp('sec-workspace');
      if (onDemoLoad) onDemoLoad();
    });
  });

  document.querySelectorAll('[data-navlink]').forEach((el) => {
    el.addEventListener('click', (e) => {
      const id = el.getAttribute('data-navlink');
      closeMenu();
      if (inApp) {
        e.preventDefault();
        showLanding(id === 'home' ? null : id);
      }
    });
  });

  if (btnMenu) {
    btnMenu.addEventListener('click', function () {
      const open = menu.classList.toggle('open');
      this.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
  }

  document.querySelectorAll('#appSidebar .side-item[data-go]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const id = btn.getAttribute('data-go');
      markSide(id);
      flashTarget(document.getElementById(id));
    });
  });

  const sidePrivacy = document.getElementById('sidePrivacy');
  if (sidePrivacy) {
    sidePrivacy.addEventListener('click', () => {
      const panel = document.getElementById('privacyPanel');
      const btn = document.getElementById('btnPrivacy');
      if (panel && !panel.classList.contains('show')) {
        panel.classList.add('show');
        if (btn) btn.setAttribute('aria-expanded', 'true');
      }
      if (panel) flashTarget(panel);
    });
  }

  const sideHome = document.getElementById('sideHome');
  if (sideHome) sideHome.addEventListener('click', () => showLanding(null));

  function syncThemeUI() {
    const light = document.documentElement.getAttribute('data-theme') === 'light';
    [
      ['btnTheme', 'themeLabel', 'themeIconSun', 'themeIconMoon'],
      ['btnThemeL', null, null, null]
    ].forEach((cfg) => {
      const b = document.getElementById(cfg[0]);
      if (!b) return;
      b.setAttribute('aria-pressed', light ? 'true' : 'false');
      if (cfg[1]) document.getElementById(cfg[1]).textContent = light ? 'Light' : 'Dark';
      const sun = cfg[2] ? document.getElementById(cfg[2]) : b.querySelector('.ic-sun');
      const moon = cfg[3] ? document.getElementById(cfg[3]) : b.querySelector('.ic-moon');
      if (sun) sun.style.display = light ? 'none' : '';
      if (moon) moon.style.display = light ? '' : 'none';
      const lbl = b.querySelector('.theme-lbl');
      if (lbl) lbl.textContent = light ? 'Light' : 'Dark';
    });
  }

  const btnThemeL = document.getElementById('btnThemeL');
  if (btnThemeL) {
    btnThemeL.addEventListener('click', () => {
      const light = document.documentElement.getAttribute('data-theme') !== 'light';
      if (light) document.documentElement.setAttribute('data-theme', 'light');
      else document.documentElement.removeAttribute('data-theme');
    });
  }
  new MutationObserver(syncThemeUI).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
  syncThemeUI();

  const spyLinks = {};
  document.querySelectorAll('[data-navlink]').forEach((a) => {
    const k = a.getAttribute('data-navlink');
    (spyLinks[k] = spyLinks[k] || []).push(a);
  });

  function setActiveNav(id) {
    Object.keys(spyLinks).forEach((k) => {
      spyLinks[k].forEach((a) => a.classList.toggle('active', k === id));
    });
  }

  if (window.IntersectionObserver) {
    const spy = new IntersectionObserver((entries) => {
      entries.forEach((en) => {
        if (en.isIntersecting) setActiveNav(en.target.id === 'home' ? 'home' : en.target.id);
      });
    }, { rootMargin: '-38% 0px -55% 0px' });
    ['home', 'features', 'how', 'use-cases', 'privacy', 'about'].forEach((id) => {
      const s = document.getElementById(id);
      if (s) spy.observe(s);
    });

    const rev = new IntersectionObserver((entries) => {
      entries.forEach((en) => {
        if (en.isIntersecting) {
          en.target.classList.add('in');
          rev.unobserve(en.target);
        }
      });
    }, { threshold: 0.12 });
    document.querySelectorAll('.reveal').forEach((el) => rev.observe(el));
  } else {
    document.querySelectorAll('.reveal').forEach((el) => el.classList.add('in'));
  }

  function routeFromHash() {
    const h = location.hash || '';
    if (h.startsWith('#/app')) {
      if (!inApp) showApp(null);
    } else if (h === '#/' || h === '' || h === '#') {
      if (inApp) showLanding(null);
    } else if (inApp) {
      showLanding(h.slice(1));
    }
  }

  window.addEventListener('hashchange', routeFromHash);
  if ((location.hash || '').startsWith('#/app')) showApp(null);
}
