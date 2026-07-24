<%-- incident/detail.jsp — Incident report detail with analysis and HTMX polling (Part II §3) --%>
<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>

<h1>Incident Report</h1>

<%-- Report summary card --%>
<div class="card mb-4">
    <div class="card-body">
        <dl class="row mb-0">
            <dt class="col-sm-3">Report ID</dt>
            <dd class="col-sm-9 font-monospace small"><c:out value="${report.id}"/></dd>

            <dt class="col-sm-3">URL</dt>
            <dd class="col-sm-9 text-break">
                <c:out value="${report.url != null ? report.url.originalUrl : 'N/A'}"/>
            </dd>

            <dt class="col-sm-3">Status</dt>
            <dd class="col-sm-9">
                <span class="badge
                    <c:choose>
                        <c:when test='${report.status == "VERIFIED"}'>bg-success</c:when>
                        <c:when test='${report.status == "PENDING_REVIEW"}'>bg-warning text-dark</c:when>
                        <c:when test='${report.status == "FAILED"}'>bg-danger</c:when>
                        <c:when test='${report.status == "REJECTED"}'>bg-secondary</c:when>
                        <c:otherwise>bg-info text-dark</c:otherwise>
                    </c:choose>">
                    <c:out value="${report.status}"/>
                </span>
            </dd>

            <c:if test="${not empty report.verdict}">
                <dt class="col-sm-3">Final Verdict</dt>
                <dd class="col-sm-9"><c:out value="${report.verdict}"/></dd>
            </c:if>

            <dt class="col-sm-3">Submitted</dt>
            <dd class="col-sm-9"><c:out value="${report.createdAt}"/></dd>

            <c:if test="${not empty report.resolvedAt}">
                <dt class="col-sm-3">Resolved</dt>
                <dd class="col-sm-9"><c:out value="${report.resolvedAt}"/></dd>
            </c:if>
        </dl>
    </div>
</div>

<%-- Evidence --%>
<div class="card mb-4">
    <div class="card-header">Evidence</div>
    <div class="card-body">
        <p><c:out value="${report.evidenceDescription}"/></p>
        <c:if test="${not empty evidenceUrls}">
            <ul>
                <c:forEach var="eu" items="${evidenceUrls}">
                    <li><a href="<c:out value='${eu}'/>" rel="noopener noreferrer" target="_blank"><c:out value="${eu}"/></a></li>
                </c:forEach>
            </ul>
        </c:if>
    </div>
</div>

<%-- HTMX polling for PENDING status (Part II §3) --%>
<c:if test="${report.status == 'PENDING'}">
    <%-- Polling container pattern (see scan/result.jsp): fragments swap into the
         inner target so the polling element survives non-terminal updates.
         stopPolling/HX-Refresh handled globally in secbret.js. --%>
    <div id="analysis-poll"
         aria-live="polite"
         aria-busy="true"
         hx-get="/incident/<c:out value='${report.id}'/>/status-fragment"
         hx-trigger="every 3s"
         hx-swap="innerHTML"
         hx-target="#analysis-poll-status">
        <div id="analysis-poll-status">
            <p class="text-muted"><span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>
                Analysis running…</p>
        </div>
    </div>
</c:if>

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

                <dt class="col-sm-3">ML Consulted</dt>
                <dd class="col-sm-9"><c:out value="${analysis.mlConsulted}"/></dd>

                <c:if test="${not empty analysis.mlScore}">
                    <dt class="col-sm-3">ML Score</dt>
                    <dd class="col-sm-9"><c:out value="${analysis.mlScore}"/></dd>
                </c:if>

                <dt class="col-sm-3">Reasoning</dt>
                <dd class="col-sm-9"><c:out value="${analysis.reasoningChain}"/></dd>
            </dl>
        </div>
    </div>
</c:if>

<%-- Security Team Review --%>
<c:if test="${not empty review}">
    <div class="card mb-4">
        <div class="card-header">Security Team Review</div>
        <div class="card-body">
            <dl class="row mb-0">
                <dt class="col-sm-3">Reviewed By</dt>
                <dd class="col-sm-9"><c:out value="${review.reviewedBy != null ? review.reviewedBy.username : '[deleted]'}"/></dd>

                <dt class="col-sm-3">Status</dt>
                <dd class="col-sm-9"><c:out value="${review.status}"/></dd>

                <dt class="col-sm-3">Final Verdict</dt>
                <dd class="col-sm-9"><c:out value="${review.finalVerdict}"/></dd>

                <c:if test="${not empty review.reviewerNotes}">
                    <dt class="col-sm-3">Notes</dt>
                    <dd class="col-sm-9"><c:out value="${review.reviewerNotes}"/></dd>
                </c:if>

                <dt class="col-sm-3">Reviewed At</dt>
                <dd class="col-sm-9"><c:out value="${review.reviewedAt}"/></dd>
            </dl>
        </div>
    </div>
</c:if>

<a href="/incident" class="btn btn-secondary">Back to List</a>
