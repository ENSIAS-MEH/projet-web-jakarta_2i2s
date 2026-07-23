<%--
  scan/status-fragment.jsp — HTMX polling fragment (Part II §3 / Part V §1.2 / §2.5)

  Returned by GET /scan/status/{jobId}. This is a *partial HTML fragment*, NOT a
  full page — it is swapped into the polling container in result.jsp via HTMX.

  When the job is in a terminal state (COMPLETED / FAILED / SUPERSEDED), the
  ScanWebController sets the response header:
      HX-Trigger: stopPolling
  The parent container's hx-on::after-request handler then removes the polling
  element (Part II §3 spec table, Part V §1.2 "Polling stop signal").

  aria-live / aria-busy are set on the *container* in result.jsp (not here), per
  Part V §2.5: "Live regions MUST exist in the DOM before content is injected;
  do not create the live region and populate it in the same swap."
--%>
<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>

<c:choose>
    <%-- ================================================================
         PENDING or RUNNING — show progress affordance
         ================================================================ --%>
    <c:when test="${status == 'PENDING' || status == 'RUNNING'}">
        <div class="d-flex align-items-center gap-3 py-3">
            <div class="spinner-border text-primary"
                 role="status"
                 aria-hidden="true">
            </div>
            <div>
                <p class="mb-0 fw-semibold">
                    <c:choose>
                        <c:when test="${status == 'PENDING'}">Waiting to start…</c:when>
                        <c:otherwise>Scanning in progress…</c:otherwise>
                    </c:choose>
                </p>
                <p class="mb-0 text-muted small">Status: <c:out value="${status}"/></p>
            </div>
        </div>
    </c:when>

    <%-- ================================================================
         COMPLETED — show inline summary (full result is in the outer page)
         ================================================================ --%>
    <c:when test="${status == 'COMPLETED'}">
        <div class="alert alert-success d-flex align-items-center gap-2" role="status">
            <span aria-hidden="true">&#x2713;</span>
            <strong>Scan complete.</strong>
            <span class="ms-1">Loading full results&hellip;</span>
        </div>
        <c:if test="${not empty result}">
            <div class="mt-2">
                <span class="badge bg-secondary me-1">Score</span>
                <c:choose>
                    <c:when test="${not empty result.overallScore}">
                        <c:out value="${result.overallScore}"/>
                    </c:when>
                    <c:otherwise>N/A</c:otherwise>
                </c:choose>
            </div>
        </c:if>
    </c:when>

    <%-- ================================================================
         FAILED — show error
         ================================================================ --%>
    <c:when test="${status == 'FAILED'}">
        <div class="alert alert-danger d-flex align-items-center gap-2" role="alert">
            <span aria-hidden="true">&#x26A0;</span>
            <strong>Scan failed.</strong>
            <c:if test="${not empty job.errorMessage}">
                <span class="ms-1"><c:out value="${job.errorMessage}"/></span>
            </c:if>
        </div>
    </c:when>

    <%-- ================================================================
         SUPERSEDED — replaced by a newer job
         ================================================================ --%>
    <c:when test="${status == 'SUPERSEDED'}">
        <div class="alert alert-warning" role="status">
            This scan was superseded by a newer submission.
            <c:if test="${not empty job.supersededBy}">
                <a href="/scan/<c:out value='${job.supersededBy}'/>">View the newer scan</a>.
            </c:if>
        </div>
    </c:when>

    <%-- Fallback --%>
    <c:otherwise>
        <p class="text-muted">Status: <c:out value="${status}"/></p>
    </c:otherwise>
</c:choose>
