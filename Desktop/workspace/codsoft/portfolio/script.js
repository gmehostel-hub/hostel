// Mobile nav toggle
const nav = document.querySelector('[data-nav]');
const navToggle = document.querySelector('[data-nav-toggle]');
navToggle?.addEventListener('click', () => nav?.classList.toggle('open'));

// Close nav on link click (mobile)
nav?.querySelectorAll('a').forEach(a => a.addEventListener('click', () => nav.classList.remove('open')));

// Sticky header active state on scroll
const header = document.querySelector('[data-header]');
let lastY = 0;
window.addEventListener('scroll', () => {
  const y = window.scrollY;
  header?.classList.toggle('scrolled', y > 6);
  lastY = y;
});

// Reveal on scroll
const revealEls = Array.from(document.querySelectorAll('.section, .card, .project, .skills-grid, .about-grid'));
const io = new IntersectionObserver((entries) => {
  entries.forEach(e => {
    if (e.isIntersecting) {
      e.target.classList.add('show');
      io.unobserve(e.target);
    }
  });
}, { threshold: 0.12 });
revealEls.forEach(el => { el.classList.add('reveal'); io.observe(el); });

// Smooth scroll for internal anchors (improves Safari behavior)
const isLocal = (a) => a.hash && a.pathname === location.pathname;
Array.from(document.querySelectorAll('a[href^="#"]')).filter(isLocal).forEach(a => {
  a.addEventListener('click', (e) => {
    const id = a.getAttribute('href')?.slice(1);
    if (!id) return;
    const target = document.getElementById(id);
    if (!target) return;
    e.preventDefault();
    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    history.pushState(null, '', `#${id}`);
  });
});

// Contact form (demo only)
const form = document.querySelector('[data-contact]');
const status = document.querySelector('[data-status]');
form?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const data = Object.fromEntries(new FormData(form).entries());
  status.textContent = 'Sending…';
  // Demo: simulate network request
  await new Promise(r => setTimeout(r, 800));
  status.textContent = 'Thanks! I will get back to you shortly.';
  form.reset();
});

// Footer year
const y = document.getElementById('year');
if (y) y.textContent = new Date().getFullYear();
