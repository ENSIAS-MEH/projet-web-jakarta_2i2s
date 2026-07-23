<%--
  share/view.jsp — anonymous HTML view of a shared report (Part III §5).
--%>
<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>

<h1>SecBret Report</h1>

<div class="card mb-4">
    <div class="card-body">
        <h5 class="card-title">Share Information</h5>
        <dl class="row mb-0">
            <dt class="col-sm-3">Share UUID</dt>
            <dd class="col-sm-9 font-monospace small"><c:out value="${link.uuidToken}"/></dd>

            <dt class="col-sm-3">Expires</dt>
            <dd class="col-sm-9"><c:out value="${link.expiresAt}"/></dd>

            <dt class="col-sm-3">Access Count</dt>
            <dd class="col-sm-9"><c:out value="${link.accessCount}"/></dd>
        </dl>
    </div>
</div>

<c:if test="${not empty job}">
    <div class="card mb-4">
        <div class="card-body">
            <h5 class="card-title">Report Details</h5>
            <dl class="row mb-0">
                <dt class="col-sm-3">Target URL</dt>
                <dd class="col-sm-9 text-break">
                    <c:choose>
                        <c:when test="${not empty job.url.originalUrl}">
                            <c:out value="${job.url.originalUrl}"/>
                        </c:when>
                        <c:otherwise>N/A</c:otherwise>
                    </c:choose>
                </dd>

                <dt class="col-sm-3">Report Status</dt>
                <dd class="col-sm-9"><c:out value="${job.status}"/></dd>

                <dt class="col-sm-3">Generated</dt>
                <dd class="col-sm-9"><c:out value="${job.completedAt}"/></dd>

                <dt class="col-sm-3">File Size</dt>
                <dd class="col-sm-9">
                    <c:choose>
                        <c:when test="${not empty job.fileSizeBytes}">
                            <c:out value="${job.fileSizeBytes}"/> bytes
                        </c:when>
                        <c:otherwise>N/A</c:otherwise>
                    </c:choose>
                </dd>
            </dl>
        </div>
    </div>

    <a href="/api/v1/share/<c:out value='${link.uuidToken}'/>?format=pdf"
       class="btn btn-primary"
       download="secbret-report-<c:out value='${link.uuidToken}'/>.pdf"
       aria-label="Download PDF report">
        Download PDF Report
    </a>
</c:if>
