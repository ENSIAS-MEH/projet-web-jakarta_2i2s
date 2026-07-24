<%-- incident/new.jsp — Submit incident report form (Part III §3)
  Model attributes:
    error        (String)            general form-level error
    fieldErrors  (Map<String,String>) per-field errors from Bean Validation (Part V §2.6)
    formUrl      (String)            repopulate url field on error
    formDesc     (String)            repopulate evidenceDescription on error
--%>
<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>

<h1>Report an Incident</h1>

<c:if test="${not empty error}">
    <div class="alert alert-danger" role="alert" aria-live="assertive"
         data-a11y-focus tabindex="-1">
        <c:out value="${error}"/>
    </div>
</c:if>

<%-- Field-level error summary (Part V §1.5 / §2.4) --%>
<c:if test="${not empty fieldErrors}">
  <div class="alert alert-danger" role="alert" aria-live="assertive"
       data-a11y-focus tabindex="-1">
    <strong>Please correct the following errors:</strong>
    <ul class="mb-0 mt-1">
      <c:if test="${not empty fieldErrors['url']}">
        <li><a href="#url" class="alert-link">URL: <c:out value="${fieldErrors['url']}"/></a></li>
      </c:if>
      <c:if test="${not empty fieldErrors['evidenceDescription']}">
        <li><a href="#evidenceDescription" class="alert-link">Evidence: <c:out value="${fieldErrors['evidenceDescription']}"/></a></li>
      </c:if>
    </ul>
  </div>
</c:if>

<form method="POST" action="/incident/submit" novalidate>
    <%-- CSRF token (Krazo session token, Part II §5) --%>
    <input type="hidden" name="${mvc.csrf.name}" value="${mvc.csrf.token}"/>

    <div class="mb-3">
        <label for="url" class="form-label">Suspicious URL <span aria-hidden="true">*</span></label>
        <input type="url"
               class="form-control<c:if test="${not empty fieldErrors['url']}"> is-invalid</c:if>"
               id="url" name="url" required
               value="<c:out value='${formUrl}'/>"
               placeholder="https://phishing-example.com/login"
               aria-required="true"
               aria-describedby="urlHelp<c:if test="${not empty fieldErrors['url']}"> url-error</c:if>">
        <div id="urlHelp" class="form-text">Must be a valid HTTP or HTTPS URL (max 2048 chars).</div>
        <c:if test="${not empty fieldErrors['url']}">
          <div id="url-error" class="invalid-feedback" role="alert">
            <c:out value="${fieldErrors['url']}"/>
          </div>
        </c:if>
    </div>

    <div class="mb-3">
        <label for="evidenceDescription" class="form-label">Evidence Description <span aria-hidden="true">*</span></label>
        <textarea class="form-control<c:if test="${not empty fieldErrors['evidenceDescription']}"> is-invalid</c:if>"
                  id="evidenceDescription" name="evidenceDescription"
                  rows="5" minlength="10" maxlength="2000" required
                  aria-required="true"
                  aria-describedby="evidenceHelp<c:if test="${not empty fieldErrors['evidenceDescription']}"> desc-error</c:if>"><c:out value="${formDesc}"/></textarea>
        <div id="evidenceHelp" class="form-text">10–2000 characters describing why this URL is suspicious.</div>
        <c:if test="${not empty fieldErrors['evidenceDescription']}">
          <div id="desc-error" class="invalid-feedback" role="alert">
            <c:out value="${fieldErrors['evidenceDescription']}"/>
          </div>
        </c:if>
    </div>

    <div class="mb-3">
        <label for="evidenceUrls" class="form-label">Evidence URLs (optional)</label>
        <input type="text" class="form-control" id="evidenceUrls" name="evidenceUrls"
               placeholder="https://legit.com/ref1,https://archive.org/snapshot"
               aria-describedby="euHelp">
        <div id="euHelp" class="form-text">Comma-separated list of up to 5 reference URLs.</div>
    </div>

    <button type="submit" class="btn btn-primary" hx-disabled-elt="this">
        Submit Report
        <span class="htmx-indicator spinner-border spinner-border-sm ms-1"
              role="status" aria-hidden="true"></span>
    </button>
    <a href="/incident" class="btn btn-secondary ms-2">Cancel</a>
</form>
