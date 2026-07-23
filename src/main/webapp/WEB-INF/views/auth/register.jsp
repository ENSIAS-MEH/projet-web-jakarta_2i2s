<%--
  register.jsp — content fragment rendered inside layout/default.jsp <main> slot.
  Model attributes (set by AuthWebController):
    form        (RegisterForm)       optional prior input to repopulate
    fieldErrors (Map<String,String>) per-field validation messages (Part V §2.6)
    errors      (Set<String>)        flat set of messages (summary list fallback)
    error       (String)             general error (e.g. duplicate username/email)
  Password policy: min 12 chars, NO composition rules (spec §B).
--%>
<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>

<div class="row justify-content-center">
  <div class="col-12 col-sm-10 col-md-6 col-lg-5">
    <h1 class="h3 mb-4">Create account</h1>

    <c:if test="${not empty error}">
      <div class="alert alert-danger" role="alert" aria-live="assertive">
        <c:out value="${error}"/>
      </div>
    </c:if>

    <%--
      Error summary: shown when field errors exist (Part V §1.5 / §2.4).
      data-a11y-focus triggers focus via secbret.js htmx:afterSettle handler.
      Links anchor to each invalid field for keyboard navigation.
    --%>
    <c:if test="${not empty fieldErrors}">
      <div class="alert alert-danger" role="alert" aria-live="assertive"
           data-a11y-focus tabindex="-1">
        <strong>Please correct the following errors:</strong>
        <ul class="mb-0 mt-1">
          <c:if test="${not empty fieldErrors['username']}">
            <li><a href="#username" class="alert-link">Username: <c:out value="${fieldErrors['username']}"/></a></li>
          </c:if>
          <c:if test="${not empty fieldErrors['email']}">
            <li><a href="#email" class="alert-link">Email: <c:out value="${fieldErrors['email']}"/></a></li>
          </c:if>
          <c:if test="${not empty fieldErrors['password']}">
            <li><a href="#password" class="alert-link">Password: <c:out value="${fieldErrors['password']}"/></a></li>
          </c:if>
        </ul>
      </div>
    </c:if>

    <%-- Summary list (shown only when there are errors but no per-field map) --%>
    <c:if test="${not empty errors and empty fieldErrors}">
      <div class="alert alert-danger" role="alert" aria-live="assertive"
           data-a11y-focus tabindex="-1">
        <ul class="mb-0">
          <c:forEach var="msg" items="${errors}">
            <li><c:out value="${msg}"/></li>
          </c:forEach>
        </ul>
      </div>
    </c:if>

    <form method="post" action="/register" novalidate>
      <%-- CSRF token (Krazo session token, Part II §5) --%>
      <input type="hidden" name="${mvc.csrf.name}" value="${mvc.csrf.token}"/>

      <div class="mb-3">
        <label for="username" class="form-label">Username</label>
        <input type="text"
               class="form-control${not empty fieldErrors['username'] ? ' is-invalid' : ''}"
               id="username" name="username"
               value="<c:out value='${form.username}'/>"
               autocomplete="username" minlength="3" maxlength="50" required autofocus
               aria-required="true"
               aria-describedby="username-hint${not empty fieldErrors['username'] ? ' username-error' : ''}">
        <div id="username-hint" class="form-text">3–50 characters: letters, digits, underscores.</div>
        <c:if test="${not empty fieldErrors['username']}">
          <div id="username-error" class="invalid-feedback" role="alert">
            <c:out value="${fieldErrors['username']}"/>
          </div>
        </c:if>
      </div>

      <div class="mb-3">
        <label for="email" class="form-label">Email</label>
        <input type="email"
               class="form-control${not empty fieldErrors['email'] ? ' is-invalid' : ''}"
               id="email" name="email"
               value="<c:out value='${form.email}'/>"
               autocomplete="email" required
               aria-required="true"
               aria-describedby="${not empty fieldErrors['email'] ? 'email-error' : ''}">
        <c:if test="${not empty fieldErrors['email']}">
          <div id="email-error" class="invalid-feedback" role="alert">
            <c:out value="${fieldErrors['email']}"/>
          </div>
        </c:if>
      </div>

      <div class="mb-3">
        <label for="password" class="form-label">Password</label>
        <input type="password"
               class="form-control${not empty fieldErrors['password'] ? ' is-invalid' : ''}"
               id="password" name="password"
               autocomplete="new-password" minlength="12" required
               aria-required="true"
               aria-describedby="password-hint${not empty fieldErrors['password'] ? ' password-error' : ''}">
        <div id="password-hint" class="form-text">At least 12 characters. A passphrase is recommended.</div>
        <c:if test="${not empty fieldErrors['password']}">
          <div id="password-error" class="invalid-feedback" role="alert">
            <c:out value="${fieldErrors['password']}"/>
          </div>
        </c:if>
      </div>

      <button type="submit" class="btn btn-primary w-100" hx-disabled-elt="this">
        Create account
        <span class="htmx-indicator spinner-border spinner-border-sm ms-1"
              role="status" aria-hidden="true"></span>
      </button>
    </form>

    <p class="mt-3 mb-0 text-center">
      Already have an account? <a href="/login">Sign in</a>.
    </p>
  </div>
</div>
