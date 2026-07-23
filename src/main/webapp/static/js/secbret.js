/**
 * secbret.js — SecBret custom helpers (Phase 6 — Part V §1.1–§1.5, §2.3–§2.5)
 *
 * CSP is strict 'self' (ADR-0004). No external fetches, no eval.
 * Loaded via <script src="/static/js/secbret.js" nonce="${cspNonce}"> in default.jsp.
 */

(function (global) {
    'use strict';

    /* =========================================================================
     * 1. HTMX global configuration (Part V §1.4)
     * ========================================================================= */

    /* Set a global request timeout so hung requests surface htmx:timeout
     * rather than spinning forever. 30 s is long enough for deep scans. */
    document.addEventListener('htmx:configRequest', function () {
        if (!htmx.config.timeout) {
            htmx.config.timeout = 30000;
        }
    });

    /* =========================================================================
     * 2. Global HTMX error routing (Part V §1.4)
     * ========================================================================= */

    document.body.addEventListener('htmx:responseError', function (e) {
        var xhr = e.detail.xhr;
        var status = xhr ? xhr.status : 0;
        var body = xhr ? xhr.responseText : '';
        showErrorFromEnvelope(status, _safeParse(body));
    });

    document.body.addEventListener('htmx:sendError', function () {
        showToast('Unable to reach the server. Check your connection and retry.', 'error');
    });

    document.body.addEventListener('htmx:timeout', function () {
        showToast('The request timed out. Please retry.', 'error');
    });

    /* =========================================================================
     * 2b. Polling stop signal (Part II §3 / Part V §1.2)
     *
     * Terminal fragments arrive with the response header HX-Trigger: stopPolling.
     * This global listener replaces the former inline hx-on::after-request
     * handlers: inline hx-on requires eval(), which the strict CSP
     * (script-src 'self' 'nonce-…', ADR-0004) blocks — the handlers never ran
     * and htmx's eval failure surfaced as the window.onerror toast.
     * ========================================================================= */

    document.body.addEventListener('htmx:afterRequest', function (e) {
        var xhr = e.detail && e.detail.xhr;
        if (!xhr || xhr.getResponseHeader('HX-Trigger') !== 'stopPolling') { return; }
        var polling = e.detail.elt;
        if (!polling || !polling.isConnected) { return; }
        var liveRegion = polling.closest('[aria-busy]');
        if (liveRegion) { liveRegion.setAttribute('aria-busy', 'false'); }
        /* Unwrap rather than remove: the terminal fragment was swapped INTO this
           element, so removal would delete the result the user is reading.
           Detaching the hx-get element stops the htmx polling interval. */
        while (polling.firstChild) {
            polling.parentNode.insertBefore(polling.firstChild, polling);
        }
        polling.parentNode.removeChild(polling);
    });

    /* =========================================================================
     * 3. Server-driven toasts via HX-Trigger: {"showToast": {level, message}}
     *    (Part V §1.3)
     * ========================================================================= */

    document.body.addEventListener('showToast', function (e) {
        var detail = e.detail || {};
        showToast(String(detail.message || ''), String(detail.level || 'info'));
    });

    /* =========================================================================
     * 4. Focus management after HTMX swaps (Part V §2.4)
     *    After a context-changing swap, move focus into the updated region.
     * ========================================================================= */

    document.body.addEventListener('htmx:afterSettle', function (e) {
        var target = e.detail.target;
        if (!target) { return; }

        /* If an error summary appeared in the swapped region, focus it. */
        var errorSummary = target.querySelector('[data-a11y-focus]');
        if (errorSummary) {
            errorSummary.setAttribute('tabindex', '-1');
            errorSummary.focus();
            return;
        }

        /* If the polling region just became aria-busy=false (terminal),
         * move focus into it so the completion is announced. */
        if (target.getAttribute('aria-busy') === 'false' &&
                target.getAttribute('aria-live')) {
            target.setAttribute('tabindex', '-1');
            target.focus();
        }
    });

    /* =========================================================================
     * 5. 429 Rate-limit countdown banner (Part V §1.1)
     *    Usage: show429Banner(retryAfterSeconds)
     * ========================================================================= */

    function show429Banner(retryAfterSeconds) {
        /* Remove any existing banner */
        var existing = document.getElementById('rate-limit-banner');
        if (existing) { existing.parentNode.removeChild(existing); }

        var seconds = parseInt(retryAfterSeconds, 10) || 60;

        var banner = document.createElement('div');
        banner.id = 'rate-limit-banner';
        banner.setAttribute('role', 'alert');
        banner.setAttribute('aria-live', 'assertive');
        banner.className = 'rate-limit-banner';

        var msg = document.createElement('span');
        msg.id = 'rate-limit-msg';
        banner.appendChild(msg);
        document.body.insertBefore(banner, document.body.firstChild);

        /* Disable the form control that triggered the 429, if identifiable */
        var lastFocused = document.activeElement;
        if (lastFocused && (lastFocused.tagName === 'BUTTON' || lastFocused.tagName === 'INPUT')) {
            lastFocused.disabled = true;
            lastFocused.dataset.rateLimitDisabled = 'true';
        }

        var remaining = seconds;
        function tick() {
            msg.textContent = 'Too many requests. Please wait ' + remaining + ' second' +
                (remaining !== 1 ? 's' : '') + ' before retrying.';
            if (remaining <= 0) {
                banner.parentNode.removeChild(banner);
                /* Re-enable the disabled control */
                var el = document.querySelector('[data-rate-limit-disabled="true"]');
                if (el) {
                    el.disabled = false;
                    delete el.dataset.rateLimitDisabled;
                }
                return;
            }
            remaining--;
            setTimeout(tick, 1000);
        }
        tick();
    }

    /* =========================================================================
     * 6. showErrorFromEnvelope — routes envelope errors to the right UI treatment
     *    (Part V §1.1 HTTP-status → UI matrix)
     * ========================================================================= */

    function showErrorFromEnvelope(status, envelope) {
        var message = (envelope && envelope.message) ? envelope.message : 'An error occurred.';
        var correlationId = envelope && envelope.correlationId;

        if (status === 401) {
            /* Redirect to login, preserving the current path */
            var next = encodeURIComponent(global.location.pathname + global.location.search);
            global.location.href = '/login?next=' + next;
            return;
        }

        if (status === 429) {
            /* Parse Retry-After from the envelope or default */
            var retryAfter = (envelope && envelope.retryAfterSeconds) ? envelope.retryAfterSeconds : 60;
            show429Banner(retryAfter);
            return;
        }

        if (status === 503) {
            showToast('Service temporarily unavailable. Please try again shortly.', 'error');
            return;
        }

        if (status === 500 && correlationId) {
            /* Show the correlationId with copy affordance (Part V §1.1 / §1.5) */
            var cidMsg = message + ' — Reference ID: ' + correlationId;
            showToast(cidMsg, 'error');
            return;
        }

        showToast(message, (status >= 500) ? 'error' : 'warning');
    }

    /* =========================================================================
     * 7. showToast(message, type) — aria-live toast (Part V §1.3 / §2.5)
     * ========================================================================= */

    function showToast(message, type) {
        var validTypes = ['success', 'error', 'info', 'warning'];
        var toastType = (validTypes.indexOf(type) !== -1) ? type : 'info';

        var livePolite    = document.getElementById('toast-live-polite');
        var liveAssertive = document.getElementById('toast-live-assertive');
        if (!livePolite && !liveAssertive) { return; }

        var bsClass = {
            success: 'alert-success',
            error:   'alert-danger',
            info:    'alert-info',
            warning: 'alert-warning'
        }[toastType];

        var toast = document.createElement('div');
        toast.setAttribute('role', toastType === 'error' ? 'alert' : 'status');
        toast.className = 'alert ' + bsClass + ' alert-dismissible fade show shadow-sm';
        toast.innerHTML =
            '<span class="toast-message">' + _escapeHtml(message) + '</span>' +
            '<button type="button" class="btn-close" data-bs-dismiss="alert" ' +
            'aria-label="Close notification"></button>';

        var targetRegion = (toastType === 'error') ? liveAssertive : livePolite;
        if (targetRegion) {
            targetRegion.appendChild(toast);
        }

        /* Auto-dismiss after 5 s for non-error toasts */
        if (toastType !== 'error') {
            setTimeout(function () {
                if (toast.parentNode) {
                    toast.classList.remove('show');
                    setTimeout(function () {
                        if (toast.parentNode) { toast.parentNode.removeChild(toast); }
                    }, 200);
                }
            }, 5000);
        }
    }

    /* =========================================================================
     * 8. Confirmation modal helper (Part V §1.3 / §2.11)
     *    Destructive actions: delete account, revoke share link, reject incident.
     *
     *    Usage: openConfirmModal({title, body, confirmLabel, onConfirm})
     *    The modal is created once and reused.
     * ========================================================================= */

    function _ensureModal() {
        if (document.getElementById('secbret-confirm-modal')) { return; }

        var html = [
            '<div class="modal fade" id="secbret-confirm-modal" tabindex="-1"',
            '     role="dialog" aria-modal="true" aria-labelledby="secbret-modal-title">',
            '  <div class="modal-dialog modal-dialog-centered">',
            '    <div class="modal-content">',
            '      <div class="modal-header">',
            '        <h5 class="modal-title" id="secbret-modal-title"></h5>',
            '        <button type="button" class="btn-close" data-bs-dismiss="modal"',
            '                aria-label="Close dialog"></button>',
            '      </div>',
            '      <div class="modal-body" id="secbret-modal-body"></div>',
            '      <div class="modal-footer">',
            '        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>',
            '        <button type="button" class="btn btn-danger" id="secbret-modal-confirm">Confirm</button>',
            '      </div>',
            '    </div>',
            '  </div>',
            '</div>'
        ].join('\n');

        var wrapper = document.createElement('div');
        wrapper.innerHTML = html;
        document.body.appendChild(wrapper.firstChild);
    }

    function openConfirmModal(opts) {
        _ensureModal();
        var modalEl = document.getElementById('secbret-confirm-modal');
        document.getElementById('secbret-modal-title').textContent = opts.title || 'Confirm action';
        document.getElementById('secbret-modal-body').textContent  = opts.body  || 'Are you sure?';
        var confirmBtn = document.getElementById('secbret-modal-confirm');
        confirmBtn.textContent = opts.confirmLabel || 'Confirm';

        /* Replace event listener to avoid stacking */
        var fresh = confirmBtn.cloneNode(true);
        confirmBtn.parentNode.replaceChild(fresh, confirmBtn);
        fresh.addEventListener('click', function () {
            var bsModal = bootstrap.Modal.getInstance(modalEl);
            if (bsModal) { bsModal.hide(); }
            if (typeof opts.onConfirm === 'function') { opts.onConfirm(); }
        });

        /* Return focus to the trigger on close (Part V §2.4) */
        var trigger = document.activeElement;
        modalEl.addEventListener('hidden.bs.modal', function restoreFocus() {
            modalEl.removeEventListener('hidden.bs.modal', restoreFocus);
            if (trigger && typeof trigger.focus === 'function') { trigger.focus(); }
        });

        var bsModal = bootstrap.Modal.getOrCreateInstance(modalEl);
        bsModal.show();
    }

    /* =========================================================================
     * 9. Revoke share-link confirmation (Part V §1.3 — replaces onsubmit=confirm)
     *    Wires up all .js-revoke-form forms on the page.
     * ========================================================================= */

    function wireRevokeConfirms() {
        document.querySelectorAll('.js-revoke-form').forEach(function (form) {
            form.addEventListener('submit', function (e) {
                e.preventDefault();
                var uuid = form.dataset.uuid || '';
                openConfirmModal({
                    title: 'Revoke share link',
                    body: 'This will permanently revoke the share link' +
                          (uuid ? ' (' + uuid + ')' : '') +
                          '. Anyone with the link will no longer be able to access the report.',
                    confirmLabel: 'Revoke',
                    onConfirm: function () { form.submit(); }
                });
            });
        });
    }

    /* =========================================================================
     * 10. Delete-account confirmation (Part V §1.3)
     *     Wires up #delete-account-form if present on the page.
     * ========================================================================= */

    function wireDeleteAccountConfirm() {
        var form = document.getElementById('delete-account-form');
        if (!form) { return; }
        form.addEventListener('submit', function (e) {
            e.preventDefault();
            openConfirmModal({
                title: 'Delete your account',
                body: 'This will permanently delete your account and all associated data. ' +
                      'This action cannot be undone.',
                confirmLabel: 'Delete my account',
                onConfirm: function () { form.submit(); }
            });
        });
    }

    /* =========================================================================
     * 11. Reject-incident confirmation (Part V §1.3)
     *     Wires up .js-reject-form if present.
     * ========================================================================= */

    function wireRejectConfirm() {
        document.querySelectorAll('.js-reject-confirm').forEach(function (btn) {
            btn.addEventListener('click', function (e) {
                var form = btn.closest('form');
                if (!form) { return; }
                /* Only intercept when REJECT is the chosen action */
                var actionSelect = form.querySelector('[name="action"]');
                if (!actionSelect || actionSelect.value !== 'REJECT') { return; }
                e.preventDefault();
                openConfirmModal({
                    title: 'Reject report',
                    body: 'Rejecting this report will mark it as invalid. ' +
                          'The reporter will see it as REJECTED.',
                    confirmLabel: 'Reject',
                    onConfirm: function () { form.submit(); }
                });
            });
        });
    }

    /* =========================================================================
     * 12. Last-resort window.onerror handler (Part V §1.4)
     * ========================================================================= */

    var _prevOnError = global.onerror;
    global.onerror = function (msg, src, line, col, err) {
        /* Log but never expose internals */
        showToast('An unexpected error occurred. Please refresh and try again.', 'error');
        if (typeof _prevOnError === 'function') {
            return _prevOnError(msg, src, line, col, err);
        }
        return false;
    };

    /* =========================================================================
     * 13. Private helpers
     * ========================================================================= */

    function _escapeHtml(str) {
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function _safeParse(text) {
        try { return JSON.parse(text); } catch (e) { return null; }
    }

    /* =========================================================================
     * 14. Init on DOM-ready
     * ========================================================================= */

    function _init() {
        wireRevokeConfirms();
        wireDeleteAccountConfirm();
        wireRejectConfirm();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', _init);
    } else {
        _init();
    }

    /* =========================================================================
     * 15. Exports
     * ========================================================================= */

    global.showToast            = showToast;
    global.showErrorFromEnvelope = showErrorFromEnvelope;
    global.show429Banner        = show429Banner;
    global.openConfirmModal     = openConfirmModal;

}(typeof self !== 'undefined' ? self : this));
