<%--
  report/status.jsp — report job status page with HTMX 3s polling (Part III §4 / Part II §3).

  Layout: uses layout/default.jsp.
  Polling: HTMX polls /report/status/{jobId} every 3s; HX-Trigger:stopPolling on terminal.
  aria-live: polite on the polling container per Part V §2.5.
--%>
<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>

<h1>Report Generation</h1>

<div class="card mb-4">
    <div class="card-body">
        <dl class="row mb-0">
            <dt class="col-sm-3">Job ID</dt>
            <dd class="col-sm-9 font-monospace small"><c:out value="${job.id}"/></dd>

            <dt class="col-sm-3">URL</dt>
            <dd class="col-sm-9 text-break">
                <c:choose>
                    <c:when test="${not empty job.url.originalUrl}">
                        <c:out value="${job.url.originalUrl}"/>
                    </c:when>
                    <c:otherwise>Unknown</c:otherwise>
                </c:choose>
            </dd>

            <dt class="col-sm-3">Requested by</dt>
            <dd class="col-sm-9">
                <c:choose>
                    <c:when test="${not empty job.requestedBy.username}">
                        <c:out value="${job.requestedBy.username}"/>
                    </c:when>
                    <c:otherwise>[deleted]</c:otherwise>
                </c:choose>
            </dd>

            <dt class="col-sm-3">Created</dt>
            <dd class="col-sm-9"><c:out value="${job.createdAt}"/></dd>
        </dl>
    </div>
</div>

<%-- HTMX polling region (Part II §3 / Part V §2.5) --%>
<c:choose>
    <c:when test="${isTerminal}">
        <%-- Already terminal on page load: show result inline, no polling --%>
        <div aria-live="polite" aria-busy="false">
            <c:choose>
                <c:when test="${status == 'COMPLETED'}">
                    <div class="alert alert-success" role="status">
                        <strong>Report generated successfully.</strong>
                    </div>
                    <c:if test="${not empty shareLink}">
                        <div class="card mt-3">
                            <div class="card-body">
                                <h5 class="card-title">Share Link</h5>
                                <p class="mb-1">
                                    <a href="/share/<c:out value='${shareLink.uuidToken}'/>" target="_blank">
                                        View Report: /share/<c:out value="${shareLink.uuidToken}"/>
                                    </a>
                                </p>
                                <p class="mb-0 text-muted small">
                                    Expires: <c:out value="${shareLink.expiresAt}"/>
                                </p>
                                <a href="/api/v1/share/<c:out value='${shareLink.uuidToken}'/>?format=pdf"
                                   class="btn btn-sm btn-outline-primary mt-2"
                                   download="secbret-report-<c:out value='${shareLink.uuidToken}'/>.pdf">
                                    Download PDF
                                </a>
                            </div>
                        </div>
                    </c:if>
                </c:when>
                <c:when test="${status == 'FAILED'}">
                    <div class="alert alert-danger" role="alert">
                        <strong>Report generation failed.</strong>
                        <c:if test="${not empty job.errorMessage}">
                            <span class="ms-1"><c:out value="${job.errorMessage}"/></span>
                        </c:if>
                    </div>
                </c:when>
                <c:otherwise>
                    <p class="text-muted">Status: <c:out value="${status}"/></p>
                </c:otherwise>
            </c:choose>
        </div>
    </c:when>
    <c:otherwise>
        <%-- Non-terminal: HTMX polling container --%>
        <%--
          Polling container pattern (same as scan/result.jsp): the outer div owns
          hx-get and survives every swap; fragments replace only #report-poll-status.
          An outerHTML self-swap would destroy the polling element because the
          fragment does not re-emit the hx-* attributes.
          stopPolling/HX-Refresh handled globally in secbret.js (CSP blocks inline hx-on).
        --%>
        <div aria-live="polite" aria-busy="true"
             hx-get="/report/status/<c:out value='${job.id}'/>"
             hx-trigger="every 3s"
             hx-swap="innerHTML"
             hx-target="#report-poll-status">
            <div id="report-poll-status">
                <div class="d-flex align-items-center gap-3 py-3">
                    <div class="spinner-border text-primary" role="status" aria-hidden="true"></div>
                    <div>
                        <p class="mb-0 fw-semibold">
                            <c:choose>
                                <c:when test="${status == 'PENDING'}">Waiting to start…</c:when>
                                <c:otherwise>Generating PDF…</c:otherwise>
                            </c:choose>
                        </p>
                        <p class="mb-0 text-muted small">Status: <c:out value="${status}"/></p>
                    </div>
                </div>
            </div>
        </div>
    </c:otherwise>
</c:choose>
