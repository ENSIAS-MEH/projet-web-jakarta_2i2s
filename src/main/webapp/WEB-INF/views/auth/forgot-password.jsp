<%--
  forgot-password.jsp — content fragment rendered inside layout/default.jsp.
  Model attributes:
    flashMessage  (String)  generic confirmation (anti-enumeration: always shown after POST)
    flashType     (String)  "info" | "success"
    error         (String)  optional validation error
--%>
<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>

<div class="row justify-content-center">
  <div class="col-12 col-sm-10 col-md-6 col-lg-5">
    <h1 class="h3 mb-4">Reset your password</h1>

    <c:if test="${not empty flashMessage}">
      <div class="alert alert-<c:out value='${flashType}'/>" role="alert" aria-live="polite">
        <c:out value="${flashMessage}"/>
      </div>
    </c:if>

    <c:if test="${not empty error}">
      <div class="alert alert-danger" role="alert" aria-live="assertive">
        <c:out value="${error}"/>
      </div>
    </c:if>

    <c:if test="${empty flashMessage}">
      <p class="mb-3 text-muted">Enter the email address associated with your account and we'll
        send you a reset link.</p>
      <form method="post" action="/forgot-password" novalidate>
        <%-- CSRF token (Krazo session token, Part II §5 / Part III §Conventions) --%>
        <input type="hidden" name="${mvc.csrf.name}" value="${mvc.csrf.token}"/>
        <div class="mb-3">
          <label for="email" class="form-label">Email address</label>
          <input type="email" class="form-control" id="email" name="email"
                 autocomplete="email" required autofocus>
        </div>
        <button type="submit" class="btn btn-primary w-100">Send reset link</button>
      </form>
    </c:if>

    <p class="mt-3 mb-0 text-center">
      <a href="/login">Back to sign in</a>
    </p>
  </div>
</div>
