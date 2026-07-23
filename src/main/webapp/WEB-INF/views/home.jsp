<%--
  home.jsp — authenticated dashboard placeholder (Task 6 / Phase 6 Part V §1.3).
  Model attributes (set by AuthWebController#dashboard):
    username (String)
    role     (String)
--%>
<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>

<div class="row">
  <div class="col">
    <h1 class="h3 mb-3">Dashboard</h1>
    <p class="lead mb-0">
      Welcome <strong><c:out value="${username}"/></strong>,
      role <span class="badge bg-secondary"><c:out value="${role}"/></span>.
    </p>

    <div class="mt-4">
      <a href="/scan/new" class="btn btn-primary me-2">Submit URL</a>
      <a href="/incident/new" class="btn btn-outline-secondary me-2">Report Incident</a>
    </div>

    <%-- Delete account — requires explicit confirmation modal (Part V §1.3) --%>
    <div class="mt-5 pt-4 border-top">
      <h2 class="h5 text-danger">Danger zone</h2>
      <p class="text-muted small">
        Permanently deletes your account and all associated data. This cannot be undone.
      </p>
      <%-- id="delete-account-form" wired by secbret.js wireDeleteAccountConfirm() --%>
      <form id="delete-account-form" method="post" action="/api/v1/auth/me"
            class="d-inline">
        <input type="hidden" name="_method" value="DELETE"/>
        <input type="hidden" name="${mvc.csrf.name}" value="${mvc.csrf.token}"/>
        <%-- Prompt for current password (DELETE /auth/me requires currentPassword) --%>
        <div class="mb-3" style="max-width:20rem">
          <label for="currentPassword" class="form-label">Current password</label>
          <input type="password" class="form-control" id="currentPassword" name="currentPassword"
                 autocomplete="current-password" required
                 aria-required="true"
                 aria-describedby="del-pw-hint">
          <div id="del-pw-hint" class="form-text">Required to confirm account deletion.</div>
        </div>
        <button type="submit" class="btn btn-outline-danger">
          Delete my account
        </button>
      </form>
    </div>
  </div>
</div>
