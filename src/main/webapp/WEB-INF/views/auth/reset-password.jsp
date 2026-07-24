<%--
  reset-password.jsp — content fragment rendered inside layout/default.jsp.
  Model attributes:
    token   (String)  the plaintext reset token from the URL (pre-filled into a hidden field)
    error   (String)  optional: token invalid/expired/used, or password policy failure
--%>
<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>

<div class="row justify-content-center">
  <div class="col-12 col-sm-10 col-md-6 col-lg-5">
    <h1 class="h3 mb-4">Set new password</h1>

    <c:if test="${not empty error}">
      <div class="alert alert-danger" role="alert" aria-live="assertive">
        <c:out value="${error}"/>
      </div>
    </c:if>

    <c:choose>
      <c:when test="${not empty token}">
        <form method="post" action="/reset-password" novalidate>
          <%-- CSRF token (Krazo session token, Part II §5 / Part III §Conventions) --%>
          <input type="hidden" name="${mvc.csrf.name}" value="${mvc.csrf.token}"/>
          <input type="hidden" name="token" value="<c:out value='${token}'/>">
          <div class="mb-3">
            <label for="newPassword" class="form-label">New password</label>
            <input type="password" class="form-control" id="newPassword" name="newPassword"
                   autocomplete="new-password" minlength="12" required autofocus>
            <div class="form-text">Minimum 12 characters.</div>
          </div>
          <button type="submit" class="btn btn-primary w-100">Set new password</button>
        </form>
      </c:when>
      <c:otherwise>
        <div class="alert alert-warning" role="alert">
          This reset link is invalid or missing. Please request a new one.
        </div>
        <a href="/forgot-password" class="btn btn-secondary">Request new link</a>
      </c:otherwise>
    </c:choose>

    <p class="mt-3 mb-0 text-center">
      <a href="/login">Back to sign in</a>
    </p>
  </div>
</div>
