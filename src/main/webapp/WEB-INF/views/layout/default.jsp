<%--
  default.jsp — Base layout fragment for SecBret (Task 7)

  INCLUDE CONVENTION:
  This file is NOT a self-contained page. Consumer views include it as a
  header/footer pair using two JSTL-free JSP includes:

    <%@ include file="/WEB-INF/views/layout/default.jsp" %>   ← WRONG (whole file)

  Instead, use the two-part pattern:

    1. Head/open (everything up to the <!-- CONTENT_START --> marker):
         <%@ include file="/WEB-INF/views/layout/_head.jsp" %>
         ... page-specific body content here ...
         <%@ include file="/WEB-INF/views/layout/_foot.jsp" %>

  OR — simpler, and used by Task 6 auth pages — include this entire file and
  override the page title and main content through a request attribute:

    Pattern A  (request attributes, no JSTL needed):
      In the controller: request.setAttribute("pageTitle", "Login | SecBret");
      In this layout: ${pageTitle} renders the title.
      Place the page body via: <jsp:include page="/WEB-INF/views/auth/login.jsp"/>
      inside a Krazo view that extends this layout once Krazo is wired (Task 6).

    Pattern B  (static include, used before Krazo — simplest for Task 6):
      The auth controller forwards to login.jsp directly (RequestDispatcher.forward).
      login.jsp does a jsp:include of this layout file up to the content slot,
      then falls through to its own markup, then closes with the footer include.

  RECOMMENDED APPROACH for Task 6:
    auth/login.jsp and auth/register.jsp include this layout using Pattern B:

      <!-- At the top of login.jsp -->
      <%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
      <%@ taglib prefix="c" uri="jakarta.tags.core" %>
      <%@ include file="/WEB-INF/views/layout/default-open.jspf" %>
        <main id="main">
          ... login form ...
        </main>
      <%@ include file="/WEB-INF/views/layout/default-close.jspf" %>

    For now (Task 7, before Krazo), this single file is the canonical reference.
    Task 6 can split it into default-open.jspf / default-close.jspf if needed,
    or forward directly to this file using pageContext variables.

  ASSETS:
    All assets use root-relative /static/... paths. The WAR is deployed at
    context root "/" (glassfish-web.xml), so /static/ resolves correctly without
    a <c:url> wrapper. If the context root ever changes, update these paths.

  CSP:
    ADR-0004 enforces strict 'self'. No CDN origins, no inline <script> logic.
    Phase 5 will add per-request nonce via a servlet filter; at that point every
    <script src> will gain a nonce attribute. Keep script logic in .js files.
--%>
<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <%-- Viewport: no user-scale restrictions (WCAG 1.4.4, Part V §3.2) --%>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="SecBret — Phishing URL scanner and community reporting tool">

    <title><c:out value="${not empty pageTitle ? pageTitle : 'SecBret'}"/></title>

    <%-- Self-hosted Bootstrap 5.3.3 — no CDN (ADR-0004 / CSP strict 'self') --%>
    <link rel="stylesheet" href="/static/css/bootstrap.min.css">
    <%-- Application-specific overrides (skip link, toast container, etc.) --%>
    <link rel="stylesheet" href="/static/css/secbret.css">
</head>
<body>

    <%--
      Skip link: MUST be the first focusable element on every page.
      Visible on keyboard focus only (secbret.css .skip-link:focus rule).
      Target: <main id="main"> below (Part V §2.2).
    --%>
    <a class="skip-link" href="#main">Skip to main content</a>

    <%--
      Primary site header with collapsing navbar.
      aria-label="Main navigation" on <nav> (Part V §2.2).
      Hamburger button carries aria-expanded + aria-controls (Part V §3.4).
    --%>
    <header>
        <nav class="navbar navbar-expand-lg navbar-dark bg-dark" aria-label="Main navigation">
            <div class="container-fluid">
                <a class="navbar-brand fw-bold" href="/">
                    SecBret
                </a>

                <%-- Hamburger toggle: Bootstrap requires aria-expanded and aria-controls --%>
                <button class="navbar-toggler"
                        type="button"
                        data-bs-toggle="collapse"
                        data-bs-target="#navbarMain"
                        aria-controls="navbarMain"
                        aria-expanded="false"
                        aria-label="Toggle navigation">
                    <span class="navbar-toggler-icon"></span>
                </button>

                <div class="collapse navbar-collapse" id="navbarMain">
                    <ul class="navbar-nav me-auto mb-2 mb-lg-0">
                        <li class="nav-item">
                            <a class="nav-link" href="/dashboard/public">Public Dashboard</a>
                        </li>
                        <%-- Authenticated nav items rendered by the container if principal is set --%>
                        <c:if test="${not empty pageContext.request.userPrincipal}">
                            <li class="nav-item">
                                <a class="nav-link" href="/scan/new">Submit URL</a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link" href="/scan">My Scans</a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link" href="/incident/new">Report Incident</a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link" href="/incident">My Reports</a>
                            </li>
                        </c:if>
                        <%-- Review queue: ANALYST and ADMIN (AdminWebController @RolesAllowed) --%>
                        <c:if test="${pageContext.request.isUserInRole('ANALYST') or pageContext.request.isUserInRole('ADMIN')}">
                            <li class="nav-item">
                                <a class="nav-link" href="/admin/reviews">Review Queue</a>
                            </li>
                        </c:if>
                        <%-- User management: ADMIN only --%>
                        <c:if test="${pageContext.request.isUserInRole('ADMIN')}">
                            <li class="nav-item">
                                <a class="nav-link" href="/admin/users">Users</a>
                            </li>
                        </c:if>
                    </ul>

                    <%-- Auth actions aligned to the right --%>
                    <ul class="navbar-nav ms-auto mb-2 mb-lg-0">
                        <c:choose>
                            <c:when test="${not empty pageContext.request.userPrincipal}">
                                <li class="nav-item">
                                    <a class="nav-link me-2" href="/profile"
                                       aria-label="Your profile">
                                        <c:out value="${pageContext.request.userPrincipal.name}"/>
                                    </a>
                                </li>
                                <li class="nav-item">
                                    <%--
                                      Reconciliation (Task 13): AuthWebController serves /logout
                                      at the root (not /auth/logout). Fixed here from the
                                      Task 6 deviation noted in the Progress Log.
                                    --%>
                                    <form method="post" action="/logout" class="d-inline">
                                        <%-- CSRF token (Krazo session token, Part II §5) --%>
                                        <input type="hidden" name="${mvc.csrf.name}" value="${mvc.csrf.token}"/>
                                        <button type="submit" class="btn btn-outline-light btn-sm">
                                            Sign out
                                        </button>
                                    </form>
                                </li>
                            </c:when>
                            <c:otherwise>
                                <li class="nav-item">
                                    <%--
                                      Reconciliation (Task 13): AuthWebController serves /login
                                      at the root (not /auth/login). Fixed here from the
                                      Task 6 deviation noted in the Progress Log.
                                    --%>
                                    <a class="nav-link" href="/login">Sign in</a>
                                </li>
                                <li class="nav-item">
                                    <a class="btn btn-outline-light btn-sm ms-2" href="/register">
                                        Register
                                    </a>
                                </li>
                            </c:otherwise>
                        </c:choose>
                    </ul>
                </div>
            </div>
        </nav>
    </header>

    <%--
      Main content landmark.
      id="main" is the skip-link target (Part V §2.2).
      Individual views are responsible for their own <h1> (one per page, Part V §2.2).
    --%>
    <main id="main" class="container py-4">

        <%--
          Flash / alert messages from the controller.
          Controllers set request attributes:
            flashMessage (String)  — message text
            flashType    (String)  — success | error | info | warning
          This region is aria-live="polite" for successes; the toast JS handles
          assertive for runtime errors.
        --%>
        <c:if test="${not empty flashMessage}">
            <div class="alert alert-${not empty flashType ? flashType : 'info'} alert-dismissible fade show"
                 role="alert"
                 aria-live="polite"
                 aria-atomic="true">
                <c:out value="${flashMessage}"/>
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close alert"></button>
            </div>
        </c:if>

        <%-- Page-specific content injected here by each view via jsp:include --%>
        <jsp:include page="${contentView}"/>

    </main>

    <footer class="bg-light border-top py-3 mt-5">
        <div class="container-fluid">
            <p class="text-center text-muted mb-0 small">
                &copy; SecBret &mdash; Phishing URL Scanner
            </p>
        </div>
    </footer>

    <%--
      Toast container (Part V §2.5):
      MUST be in the DOM before any JS calls showToast(). Two sub-regions with
      different aria-live polarities:
        - #toast-live-polite   → success / info  (polite announcement)
        - #toast-live-assertive → errors          (assertive; interrupts screen reader)
      The outer #toast-container is position:fixed (secbret.css).
    --%>
    <div id="toast-container" role="region" aria-label="Notifications">
        <div id="toast-live-polite"
             aria-live="polite"
             aria-atomic="false"
             aria-relevant="additions"></div>
        <div id="toast-live-assertive"
             aria-live="assertive"
             aria-atomic="true"
             aria-relevant="additions"></div>
    </div>

    <%-- Self-hosted JS — order: HTMX first, then Bootstrap bundle, then secbret.js --%>
    <%-- nonce added by SecurityHeaderFilter (Part II §5 / ADR-0004 CSP strict 'self') --%>
    <script src="/static/js/htmx.min.js" nonce="${cspNonce}"></script>
    <script src="/static/js/bootstrap.bundle.min.js" nonce="${cspNonce}"></script>
    <script src="/static/js/secbret.js" nonce="${cspNonce}"></script>

</body>
</html>
