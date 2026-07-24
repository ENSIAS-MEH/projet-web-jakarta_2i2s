<%--
  login.jsp — content fragment rendered inside layout/default.jsp <main> slot.
  Model attributes (set by AuthWebController):
    error       (String)  optional generic auth error
    next        (String)  optional post-login redirect target
  Bootstrap classes only; labelled inputs; generic error text (no enumeration).
--%>
<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>

<div class="row justify-content-center">
  <div class="col-12 col-sm-10 col-md-6 col-lg-5">
    <h1 class="h3 mb-4">Sign in</h1>

    <c:if test="${not empty error}">
      <div class="alert alert-danger" role="alert" aria-live="assertive">
        <c:out value="${error}"/>
      </div>
    </c:if>

    <form method="post" action="/login" novalidate>
      <%-- CSRF token (Krazo session token, Part II §5 / Part III §Conventions) --%>
      <input type="hidden" name="${mvc.csrf.name}" value="${mvc.csrf.token}"/>
      <c:if test="${not empty next}">
        <input type="hidden" name="next" value="<c:out value='${next}'/>">
      </c:if>

      <div class="mb-3">
        <label for="username" class="form-label">Username</label>
        <input type="text"
               class="form-control${not empty error ? ' is-invalid' : ''}"
               id="username" name="username"
               autocomplete="username" required autofocus
               aria-required="true"
               ${not empty error ? 'aria-invalid="true"' : ''}>
      </div>

      <div class="mb-3">
        <label for="password" class="form-label">Password</label>
        <input type="password"
               class="form-control${not empty error ? ' is-invalid' : ''}"
               id="password" name="password"
               autocomplete="current-password" required
               aria-required="true"
               ${not empty error ? 'aria-invalid="true"' : ''}>
      </div>

      <%-- Loading indicator visible during form submit (Part V §1.2) --%>
      <button type="submit" class="btn btn-primary w-100"
              hx-disabled-elt="this">
        Sign in
        <span class="htmx-indicator spinner-border spinner-border-sm ms-1"
              role="status" aria-hidden="true"></span>
      </button>
    </form>

    <p class="mt-3 mb-0 text-center">
      No account? <a href="/register">Create one</a>.
    </p>
  </div>
</div>
