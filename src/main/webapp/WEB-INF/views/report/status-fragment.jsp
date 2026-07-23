<%--
  report/status-fragment.jsp — HTMX polling fragment for report job status.

  Returned by GET /report/status/{jobId}. Partial HTML swapped into the polling container.
  On terminal state: server sets HX-Trigger: stopPolling (ReportWebController).
--%>
<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>

<c:choose>
    <c:when test="${status == 'PENDING' || status == 'GENERATING'}">
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
    </c:when>

    <c:when test="${status == 'COMPLETED'}">
        <div class="alert alert-success d-flex align-items-center gap-2" role="status">
            <span aria-hidden="true">&#x2713;</span>
            <strong>Report ready.</strong>
            <c:if test="${not empty shareLink}">
                <span class="ms-2">
                    <a href="/share/<c:out value='${shareLink.uuidToken}'/>">View report</a>
                </span>
            </c:if>
        </div>
    </c:when>

    <c:when test="${status == 'FAILED'}">
        <div class="alert alert-danger d-flex align-items-center gap-2" role="alert">
            <span aria-hidden="true">&#x26A0;</span>
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
