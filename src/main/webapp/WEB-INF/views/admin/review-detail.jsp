<%-- admin/review-detail.jsp — Analyst review form (Part III §6 / Part II §3 HTMX) --%>
<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>

<h1>Review Report</h1>

<c:if test="${not empty error}">
    <div class="alert alert-danger" role="alert"><c:out value="${error}"/></div>
</c:if>

<%-- Report info --%>
<div class="card mb-4">
    <div class="card-header">Report Details</div>
    <div class="card-body">
        <dl class="row mb-0">
            <dt class="col-sm-3">Report ID</dt>
            <dd class="col-sm-9 font-monospace small"><c:out value="${report.id}"/></dd>

            <dt class="col-sm-3">URL</dt>
            <dd class="col-sm-9 text-break">
                <c:out value="${report.url != null ? report.url.originalUrl : 'N/A'}"/>
            </dd>

            <dt class="col-sm-3">Evidence</dt>
            <dd class="col-sm-9"><c:out value="${report.evidenceDescription}"/></dd>

            <dt class="col-sm-3">Reported By</dt>
            <dd class="col-sm-9">
                <c:choose>
                    <c:when test="${not empty report.reportedBy}"><c:out value="${report.reportedBy.username}"/></c:when>
                    <c:otherwise>[deleted]</c:otherwise>
                </c:choose>
            </dd>
        </dl>
    </div>
</div>

<%-- SecBret Analysis --%>
<c:if test="${not empty analysis}">
    <div class="card mb-4">
        <div class="card-header">SecBret Analysis</div>
        <div class="card-body">
            <dl class="row mb-0">
                <dt class="col-sm-3">Threat Score</dt>
                <dd class="col-sm-9"><c:out value="${analysis.threatScore}"/></dd>
                <dt class="col-sm-3">Verdict</dt>
                <dd class="col-sm-9"><c:out value="${analysis.verdict}"/></dd>
                <dt class="col-sm-3">Reasoning</dt>
                <dd class="col-sm-9"><c:out value="${analysis.reasoningChain}"/></dd>
                <dt class="col-sm-3">ML Consulted</dt>
                <dd class="col-sm-9"><c:out value="${analysis.mlConsulted}"/></dd>
            </dl>
        </div>
    </div>
</c:if>

<%-- Already reviewed? --%>
<c:choose>
    <c:when test="${not empty existingReview}">
        <div class="alert alert-info" role="alert">
            This report has already been reviewed: <strong><c:out value="${existingReview.status}"/></strong>
            — <c:out value="${existingReview.finalVerdict}"/>
        </div>
    </c:when>
    <c:otherwise>
        <%-- Review form with HTMX inline update (Part II §3) --%>
        <div id="review-form-container">
            <div class="card">
                <div class="card-header">Submit Review</div>
                <div class="card-body">
                    <form method="POST" action="/admin/reviews/<c:out value='${report.id}'/>"
                          hx-post="/admin/reviews/<c:out value='${report.id}'/>"
                          hx-target="#review-form-container"
                          hx-swap="outerHTML"
                          hx-headers='{"X-CSRF-Token": "${mvc.csrf.token}"}'>
                        <%-- CSRF token: hidden input for non-HTMX fallback; hx-headers for HTMX (Part II §5) --%>
                        <input type="hidden" name="${mvc.csrf.name}" value="${mvc.csrf.token}"/>
                        <div class="mb-3">
                            <label for="action" class="form-label">Action <span aria-hidden="true">*</span></label>
                            <select class="form-select" id="action" name="action" required>
                                <option value="">-- Select --</option>
                                <option value="APPROVE">APPROVE (adopt AI verdict)</option>
                                <option value="REJECT">REJECT (invalidate report)</option>
                                <option value="MODIFY">MODIFY (override verdict)</option>
                            </select>
                        </div>

                        <div class="mb-3" id="finalVerdictGroup" style="display:none">
                            <label for="finalVerdict" class="form-label">Final Verdict (required for MODIFY)</label>
                            <select class="form-select" id="finalVerdict" name="finalVerdict">
                                <option value="">-- Select --</option>
                                <option value="VERIFIED_MALICIOUS">VERIFIED_MALICIOUS</option>
                                <option value="VERIFIED_BENIGN">VERIFIED_BENIGN</option>
                            </select>
                        </div>

                        <div class="mb-3">
                            <label for="reviewerNotes" class="form-label">Reviewer Notes</label>
                            <textarea class="form-control" id="reviewerNotes" name="reviewerNotes"
                                      rows="3" maxlength="5000"></textarea>
                        </div>

                        <%-- js-reject-confirm: secbret.js intercepts submit when action=REJECT (Part V §1.3) --%>
                        <button type="submit" class="btn btn-primary js-reject-confirm" hx-disabled-elt="this">
                            Submit Review
                            <span class="htmx-indicator spinner-border spinner-border-sm ms-1"
                                  role="status" aria-hidden="true"></span>
                        </button>
                        <a href="/admin/reviews" class="btn btn-secondary ms-2">Cancel</a>
                    </form>
                </div>
            </div>
        </div>
        <%-- nonce required by CSP strict 'self' + per-request nonce (Part II §5 / ADR-0004) --%>
        <script nonce="${cspNonce}">
            document.getElementById('action').addEventListener('change', function() {
                document.getElementById('finalVerdictGroup').style.display =
                    this.value === 'MODIFY' ? 'block' : 'none';
            });
        </script>
    </c:otherwise>
</c:choose>

<div class="mt-3">
    <a href="/admin/reviews" class="btn btn-secondary">Back to Queue</a>
</div>
