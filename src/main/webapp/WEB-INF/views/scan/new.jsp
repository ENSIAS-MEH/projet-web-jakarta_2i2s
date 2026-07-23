<%--
  scan/new.jsp — URL submission form (Part III §2 / Part II §3 / Part V §2.6)

  Rendered as the ${contentView} slot of layout/default.jsp.
  The form posts to /scan/submit (Krazo controller).

  HTMX: hx-post submit pattern per Part II §3 spec table:
    hx-post="/scan/submit" hx-target="#result" hx-swap="innerHTML"
  However, since we redirect from the controller after job creation (PRG pattern),
  we use standard form submit + Krazo redirect → no hx-post here to keep the
  implementation simple. The HTMX polling happens on the result/status page.

  Accessibility (Part V §2.6):
  - All controls have <label for>
  - Required fields: required + aria-required="true"
  - autocomplete tokens for usability
--%>
<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>

<h1>Submit URL for Scanning</h1>
<p class="text-muted mb-4">
    Enter a URL to scan for phishing indicators. Results are typically available
    within a few seconds for a QUICK scan.
</p>

<%-- Field-level error is rendered inline next to the URL input (Part V §2.6) --%>
<%-- Form-level / 500 error with correlationId (Part V §1.5) --%>
<c:if test="${not empty formError}">
    <div class="alert alert-danger" role="alert" aria-live="assertive"
         data-a11y-focus tabindex="-1">
        <c:out value="${formError}"/>
        <c:if test="${not empty correlationId}">
            <br><small>Reference ID: <code><c:out value="${correlationId}"/></code></small>
        </c:if>
    </div>
</c:if>

<div class="row justify-content-center">
    <div class="col-lg-7">
        <form method="post" action="/scan/submit" novalidate>
            <%-- CSRF token (Krazo session token, Part II §5) --%>
            <input type="hidden" name="${mvc.csrf.name}" value="${mvc.csrf.token}"/>

            <div class="mb-3">
                <label for="url" class="form-label fw-semibold">
                    URL <span class="text-danger" aria-hidden="true">*</span>
                </label>
                <input
                    type="url"
                    class="form-control<c:if test="${not empty error}"> is-invalid</c:if>"
                    id="url"
                    name="url"
                    value="<c:out value='${formUrl}'/>"
                    placeholder="https://suspicious-site.com/login"
                    maxlength="2048"
                    required
                    aria-required="true"
                    autocomplete="url"
                    aria-describedby="url-hint<c:if test="${not empty error}"> url-error</c:if>">
                <div id="url-hint" class="form-text">
                    Must be a public HTTP(S) URL. Private/reserved IP addresses are blocked.
                </div>
                <c:if test="${not empty error}">
                  <div id="url-error" class="invalid-feedback" role="alert">
                    <c:out value="${error}"/>
                  </div>
                </c:if>
            </div>

            <div class="mb-4">
                <fieldset>
                    <legend class="fw-semibold mb-2">Scan depth</legend>
                    <div class="form-check form-check-inline">
                        <input class="form-check-input" type="radio" name="depth"
                               id="depth-quick" value="QUICK" checked>
                        <label class="form-check-label" for="depth-quick">
                            QUICK — Tier 1 (domain age, SSL, headers, DNS)
                        </label>
                    </div>
                    <div class="form-check form-check-inline">
                        <input class="form-check-input" type="radio" name="depth"
                               id="depth-deep" value="DEEP">
                        <label class="form-check-label" for="depth-deep">
                            DEEP — Tiers 1–3 (includes content analysis)
                        </label>
                    </div>
                </fieldset>
            </div>

            <button type="submit" class="btn btn-primary btn-lg" hx-disabled-elt="this">
                <span aria-hidden="true">&#x1F50D;</span> Scan URL
                <span class="htmx-indicator spinner-border spinner-border-sm ms-1"
                      role="status" aria-hidden="true"></span>
            </button>
        </form>
    </div>
</div>
