/**
 * CyberRecon Landing Page Scroll Animations & Progressive Enhancement
 * High-performance 60fps animations: transform & opacity only.
 * Full graceful degradation: content remains 100% visible if JS is unavailable.
 * Respects prefers-reduced-motion: instant reveals, flat transforms, no parallax.
 */

(function () {
    'use strict';

    var isReducedMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (isReducedMotion) {
        document.documentElement.classList.add('reduced-motion');
    }
    // Mark progressive enhancement active
    document.documentElement.classList.add('js-ready');

    document.addEventListener('DOMContentLoaded', function () {
        var progressBar = document.getElementById('scroll-progress-bar');
        var navbar = document.querySelector('.navbar');
        var aurora = document.getElementById('hero-spotlight');
        var heroHeadlines = document.querySelectorAll('.landing-h1, .landing-subhead, .hero-form-wrapper');
        var shotWrap = document.getElementById('product-shot-wrap');
        var shotWindow = document.getElementById('product-shot-window');
        var howSection = document.getElementById('how-it-works-section');
        var lineFill = document.getElementById('steps-line-fill');
        var circle1 = document.getElementById('step-circle-1');
        var circle2 = document.getElementById('step-circle-2');
        var circle3 = document.getElementById('step-circle-3');
        var ctaCard = document.getElementById('final-cta-card');
        var targetInput = document.getElementById('target');
        var form = document.getElementById('hero-target-form');
        var errorMsg = document.getElementById('hero-error-msg');
        var errorText = document.getElementById('hero-error-text');
        var scrollBtn = document.getElementById('btn-scroll-hero');

        var shotInnerAnimated = false;
        var ticking = false;

        // 1. Initial State: If reduced motion, set --p to 1 immediately so shot is flat
        if (isReducedMotion && shotWindow) {
            shotWindow.style.setProperty('--p', '1');
            shotWindow.style.setProperty('--parallax-y', '0deg');
            shotWindow.classList.add('shot-revealed');
        }

        // 2. Numbers Counter Animation
        function animateCounter(el, target, duration, suffix) {
            if (!el) return;
            suffix = suffix || '';
            if (isReducedMotion) {
                el.textContent = target + suffix;
                return;
            }
            var start = 0;
            var startTime = null;
            function step(timestamp) {
                if (!startTime) startTime = timestamp;
                var progress = Math.min((timestamp - startTime) / duration, 1);
                var current = Math.floor(progress * (target - start) + start);
                el.textContent = current + suffix;
                if (progress < 1) {
                    window.requestAnimationFrame(step);
                } else {
                    el.textContent = target + suffix;
                }
            }
            window.requestAnimationFrame(step);
        }

        // 3. Trigger Product Shot Inner Dashboard Animation
        function playShotInnerAnimation() {
            if (shotInnerAnimated || !shotWindow) return;
            shotInnerAnimated = true;
            shotWindow.classList.add('shot-revealed');

            // Animate posture ring fill
            var ringFill = document.getElementById('mini-ring-fill');
            if (ringFill) {
                ringFill.style.transition = 'stroke-dashoffset 1s cubic-bezier(0.16, 1, 0.3, 1)';
                ringFill.style.strokeDashoffset = '42'; // 85% score
            }

            // Animate counters
            animateCounter(document.getElementById('mini-stat-score'), 85, 1000, '/100');
            animateCounter(document.getElementById('mini-stat-assessments'), 14, 800);
            animateCounter(document.getElementById('mini-stat-findings'), 3, 700);
            animateCounter(document.getElementById('mini-stat-targets'), 4, 700);
        }

        // 4. Scroll Engine (Throttled via requestAnimationFrame)
        function onScrollUpdate() {
            var scrollY = window.scrollY || window.pageYOffset;
            var vh = window.innerHeight || 800;
            var docHeight = document.documentElement.scrollHeight - vh;

            // A. Fixed Mint Scroll Progress Bar
            if (progressBar && docHeight > 0) {
                var progress = (scrollY / docHeight) * 100;
                progressBar.style.width = Math.min(100, Math.max(0, progress)) + '%';
            }

            // B. Header Sticky State
            if (navbar) {
                if (scrollY > 24) {
                    navbar.classList.add('scrolled');
                } else {
                    navbar.classList.remove('scrolled');
                }
            }

            // C. Hero Parallax & Fade (Desktop only)
            if (!isReducedMotion && window.innerWidth > 768 && scrollY < 700) {
                if (aurora) {
                    aurora.style.setProperty('--aurora-y', (scrollY * 0.25) + 'px');
                }
                var heroFadeY = (-scrollY * 0.12) + 'px';
                var heroOpacity = Math.max(0, 1 - (scrollY / 450));
                heroHeadlines.forEach(function (el) {
                    el.style.setProperty('--hero-fade-y', heroFadeY);
                    el.style.setProperty('--hero-opacity', heroOpacity);
                });
            }

            // D. Product Shot Scroll-Linked Flattening (Flattens as user scrolls from 0 to center)
            if (shotWrap && shotWindow) {
                if (isReducedMotion) {
                    shotWindow.style.setProperty('--p', '1');
                    playShotInnerAnimation();
                } else {
                    var shotTop = shotWrap.getBoundingClientRect().top + scrollY;
                    var centerScrollY = shotTop - (vh - shotWrap.offsetHeight) / 2;
                    var p = 0;
                    if (centerScrollY > 10) {
                        p = scrollY / centerScrollY;
                    } else {
                        p = 1;
                    }
                    p = Math.max(0, Math.min(1, p));
                    shotWindow.style.setProperty('--p', p.toFixed(4));

                    if (p >= 0.85) {
                        playShotInnerAnimation();
                    }
                }
            }

            // E. "How it Works" Signal Line Scrub
            if (howSection && lineFill) {
                var howRect = howSection.getBoundingClientRect();
                var howProgress = (vh - howRect.top) / (vh + howRect.height * 0.4);
                howProgress = Math.max(0, Math.min(1, howProgress));
                howSection.style.setProperty('--line-progress', howProgress.toFixed(4));

                if (circle1) circle1.classList.toggle('active', howProgress >= 0.2);
                if (circle2) circle2.classList.toggle('active', howProgress >= 0.5);
                if (circle3) circle3.classList.toggle('active', howProgress >= 0.8);
            }

            // F. Final CTA Glow
            if (ctaCard) {
                var ctaRect = ctaCard.getBoundingClientRect();
                var ctaProgress = (vh - ctaRect.top) / vh;
                ctaProgress = Math.max(0, Math.min(1, ctaProgress));
                ctaCard.style.setProperty('--cta-glow', ctaProgress.toFixed(2));
            }

            ticking = false;
        }

        window.addEventListener('scroll', function () {
            onScrollUpdate();
        }, { passive: true });

        // Initial scroll calculation
        onScrollUpdate();

        // 5. Mouse Parallax on Product Shot (Desktop only, max +/-2deg, resets smoothly)
        if (shotWrap && shotWindow && !isReducedMotion) {
            shotWrap.addEventListener('mousemove', function (e) {
                if (window.innerWidth <= 1024) return;
                var rect = shotWrap.getBoundingClientRect();
                var y = ((e.clientY - rect.top) / rect.height) - 0.5;
                // Only delta on X axis tilt (no rotateY, no rotateZ, no skew)
                var deltaDeg = Math.max(-2, Math.min(2, -y * 4));
                shotWindow.style.setProperty('--parallax-y', deltaDeg.toFixed(2) + 'deg');
            }, { passive: true });

            shotWrap.addEventListener('mouseleave', function () {
                shotWindow.style.setProperty('--parallax-y', '0deg');
            }, { passive: true });
        }

        // 6. Section Reveals via IntersectionObserver
        if ('IntersectionObserver' in window) {
            var observer = new IntersectionObserver(function (entries) {
                entries.forEach(function (entry) {
                    if (entry.isIntersecting) {
                        entry.target.classList.add('is-revealed');
                        observer.unobserve(entry.target);
                    }
                });
            }, {
                threshold: 0.12,
                rootMargin: '0px 0px -40px 0px'
            });

            document.querySelectorAll('.reveal-on-scroll').forEach(function (el) {
                if (isReducedMotion) {
                    el.classList.add('is-revealed');
                } else {
                    observer.observe(el);
                }
            });
        } else {
            // Fallback for older browsers
            document.querySelectorAll('.reveal-on-scroll').forEach(function (el) {
                el.classList.add('is-revealed');
            });
        }

        // 7. Hero Target Input Validation
        var hasInteracted = false;
        function validateInput(val) {
            if (!val || !val.trim()) {
                return 'Please enter a valid public hostname or HTTP/HTTPS URL.';
            }
            var clean = val.trim();
            if (/^(ftp|file|gopher|javascript|data):/i.test(clean)) {
                return 'Only HTTP and HTTPS targets are supported.';
            }
            if (/localhost|127\.0\.0\.1|169\.254\.|10\.|192\.168\./i.test(clean)) {
                return 'Private, loopback, and metadata endpoints are blocked for safety.';
            }
            return null;
        }

        function showError(msg) {
            if (!errorMsg || !errorText) return;
            errorText.textContent = msg;
            errorMsg.style.display = 'inline-flex';
        }

        function hideError() {
            if (!errorMsg) return;
            errorMsg.style.display = 'none';
        }

        if (targetInput) {
            targetInput.addEventListener('input', function () {
                hasInteracted = true;
                var err = validateInput(this.value);
                if (err) showError(err); else hideError();
            });

            targetInput.addEventListener('blur', function () {
                if (hasInteracted && this.value) {
                    var err = validateInput(this.value);
                    if (err) showError(err); else hideError();
                }
            });
        }

        if (form) {
            form.addEventListener('submit', function (e) {
                hasInteracted = true;
                var val = targetInput ? targetInput.value : '';
                var err = validateInput(val);
                if (err) {
                    e.preventDefault();
                    showError(err);
                    if (targetInput) targetInput.focus();
                }
            });
        }

        if (scrollBtn && targetInput) {
            scrollBtn.addEventListener('click', function () {
                window.scrollTo({ top: 0, behavior: 'smooth' });
                setTimeout(function () { targetInput.focus(); }, 400);
            });
        }
    });
})();
