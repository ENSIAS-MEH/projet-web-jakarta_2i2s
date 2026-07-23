<%--
  scan/result.jsp — full scan result page (Part III §2 / Part II §3 / Part V §1.2 §2.5 §2.8)

  Rendered as the ${contentView} slot of layout/default.jsp.

  HTMX polling container (Part II §3 / Part V §1.2):
  - The div#poll-status uses hx-get + hx-trigger="every 3s" to poll /scan/status/{jobId}.
  - When the server returns HX-Trigger: stopPolling (terminal state), the
    hx-on::after-request handler calls htmx.remove(this) to stop polling.
  - The container has aria-live="polite" and aria-busy="true" while polling
    (Part V §2.5: polling regions are aria-live + toggle aria-busy).
  - Once ${isTerminal} is true on initial page load, the polling div is not rendered
    (or the server sends stopPolling on the first fragment load).

  Verdict badge (Part V §2.8):
  - Color is always paired with a text verdict label — never color-only.
--%>
<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>
<%@ taglib prefix="fmt" uri="jakarta.tags.fmt" %>

<h1>Scan Result</h1>

<%-- Job metadata summary --%>
<div class="card mb-4">
    <div class="card-body">
        <dl class="row mb-0">
            <dt class="col-sm-3">URL</dt>
            <dd class="col-sm-9 text-break">
                <c:out value="${job.url.originalUrl}"/>
            </dd>

            <dt class="col-sm-3">Depth</dt>
            <dd class="col-sm-9"><c:out value="${job.scanDepth}"/></dd>

            <dt class="col-sm-3">Job ID</dt>
            <dd class="col-sm-9 font-monospace small"><c:out value="${job.id}"/></dd>

            <dt class="col-sm-3">Submitted</dt>
            <dd class="col-sm-9">
                <c:out value="${job.createdAt}"/>
            </dd>

            <c:if test="${not empty job.completedAt}">
                <dt class="col-sm-3">Completed</dt>
                <dd class="col-sm-9"><c:out value="${job.completedAt}"/></dd>
            </c:if>
        </dl>
    </div>
</div>

<%-- ================================================================
     HTMX polling status region (Part II §3 / Part V §1.2 / §2.5)

     The region is aria-live="polite" so screen readers announce status
     transitions (RUNNING → COMPLETED) without a reload.
     aria-busy="true" while in a non-terminal state; "false" once done.
     ================================================================ --%>
<c:choose>
    <c:when test="${isTerminal}">
        <%-- Already in terminal state on page load: render result/failure inline,
             no polling needed. --%>
        <div aria-live="polite" aria-atomic="false" aria-busy="false">
            <c:choose>
                <c:when test="${job.status == 'COMPLETED'}">
                    <div class="alert alert-success" role="status">
                        <strong>Scan complete.</strong>
                    </div>
                </c:when>
                <c:when test="${job.status == 'FAILED'}">
                    <div class="alert alert-danger" role="alert">
                        <strong>Scan failed.</strong>
                        <c:if test="${not empty job.errorMessage}">
                            <span class="ms-1"><c:out value="${job.errorMessage}"/></span>
                        </c:if>
                    </div>
                </c:when>
                <c:when test="${job.status == 'SUPERSEDED'}">
                    <div class="alert alert-warning" role="status">
                        This scan was superseded by a newer submission.
                        <c:if test="${not empty job.supersededBy}">
                            <a href="/scan/<c:out value='${job.supersededBy}'/>">View the newer scan</a>.
                        </c:if>
                    </div>
                </c:when>
            </c:choose>
        </div>
    </c:when>
    <c:otherwise>
        <%--
          Non-terminal: render the polling container.

          hx-get polls the status fragment every 3 seconds.
          hx-trigger="every 3s" drives the poll.
          hx-swap="innerHTML" replaces this div's content with the fragment.
          hx-on::after-request: when the server sends HX-Trigger: stopPolling,
            this removes the element (stops polling).

          The outer div carries the live region + aria-busy for a11y.
          The inner div is the HTMX polling element (removed on stopPolling).
        --%>
        <div aria-live="polite" aria-atomic="false" aria-busy="true" id="status-live-region">
            <%-- stopPolling handling lives in secbret.js (htmx:afterRequest listener);
                 inline hx-on needs eval() and is blocked by the strict CSP. --%>
            <div id="poll-container"
                 hx-get="/scan/status/<c:out value='${jobId}'/>"
                 hx-trigger="every 3s"
                 hx-swap="innerHTML"
                 hx-target="#poll-status"
                 hx-indicator="#poll-spinner">
                <%-- Poll indicator: shown during each 3s HTMX request (Part V §1.2) --%>
                <span id="poll-spinner"
                      class="htmx-indicator visually-hidden"
                      role="status"
                      aria-label="Refreshing scan status…"></span>
                <div id="poll-status">
                    <div class="d-flex align-items-center gap-3 py-3">
                        <div class="spinner-border text-primary" role="status" aria-hidden="true"></div>
                        <div>
                            <p class="mb-0 fw-semibold">
                                <c:choose>
                                    <c:when test="${job.status == 'PENDING'}">Waiting to start…</c:when>
                                    <c:otherwise>Scanning in progress…</c:otherwise>
                                </c:choose>
                            </p>
                            <p class="mb-0 text-muted small">
                                Status: <c:out value="${job.status}"/>
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </c:otherwise>
</c:choose>

<%-- ================================================================
     COMPLETED result: findings + score + verdict badge
     ================================================================ --%>
<c:if test="${job.status == 'COMPLETED' and not empty result}">
    <div class="mt-4">
        <h2>Scan Findings</h2>

        <%-- Overall score + verdict badge (Part V §2.8: color + text, never color-only) --%>
        <div class="d-flex align-items-center gap-3 mb-3">
            <span class="h4 mb-0">Overall Score:</span>
            <c:choose>
                <c:when test="${not empty result.overallScore}">
                    <c:set var="score" value="${result.overallScore}"/>
                    <%-- Verdict badge: color paired with text label per Part V §2.8 --%>
                    <c:choose>
                        <c:when test="${score >= 0.95}">
                            <span class="badge bg-danger fs-5" title="Score: ${score}">
                                VERIFIED MALICIOUS &mdash; <c:out value="${score}"/>
                            </span>
                        </c:when>
                        <c:when test="${score >= 0.6}">
                            <span class="badge bg-warning text-dark fs-5" title="Score: ${score}">
                                SUSPICIOUS &mdash; <c:out value="${score}"/>
                            </span>
                        </c:when>
                        <c:when test="${score <= 0.05}">
                            <span class="badge bg-success fs-5" title="Score: ${score}">
                                LIKELY BENIGN &mdash; <c:out value="${score}"/>
                            </span>
                        </c:when>
                        <c:otherwise>
                            <span class="badge bg-secondary fs-5" title="Score: ${score}">
                                PENDING REVIEW &mdash; <c:out value="${score}"/>
                            </span>
                        </c:otherwise>
                    </c:choose>
                </c:when>
                <c:otherwise>
                    <span class="badge bg-secondary">Score: N/A</span>
                </c:otherwise>
            </c:choose>
        </div>

        <%-- Findings per tier, flattened to label/value rows by ScanWebController --%>
        <c:forEach var="tier" items="${tierFindings}">
            <div class="card mb-3">
                <div class="card-header">
                    <h3 class="h6 mb-0"><c:out value="${tier.key}"/></h3>
                </div>
                <c:choose>
                    <c:when test="${empty tier.value}">
                        <div class="card-body">
                            <p class="mb-0 text-muted">No findings recorded for this tier.</p>
                        </div>
                    </c:when>
                    <c:otherwise>
                        <div class="table-responsive">
                            <table class="table table-sm table-striped mb-0"
                                   aria-label="${tier.key}">
                                <tbody>
                                    <c:forEach var="finding" items="${tier.value}">
                                        <tr>
                                            <th scope="row" class="fw-normal text-muted w-50">
                                                <c:out value="${finding.key}"/>
                                            </th>
                                            <td class="text-break"><c:out value="${finding.value}"/></td>
                                        </tr>
                                    </c:forEach>
                                </tbody>
                            </table>
                        </div>
                    </c:otherwise>
                </c:choose>
            </div>
        </c:forEach>
    </div>
</c:if>

<%-- Actions --%>
<div class="mt-4 d-flex gap-2 flex-wrap">
    <c:if test="${job.status == 'COMPLETED'}">
        <%-- Generate Report PDF use case: POST /report/request (ReportWebController) --%>
        <form method="post" action="/report/request" class="d-inline">
            <input type="hidden" name="${mvc.csrf.name}" value="${mvc.csrf.token}"/>
            <input type="hidden" name="urlId" value="${job.url.id}"/>
            <button type="submit" class="btn btn-primary">Generate PDF report</button>
        </form>
    </c:if>
    <a href="/scan/new" class="btn btn-outline-primary">Submit another URL</a>
    <a href="/scan" class="btn btn-outline-secondary">My scans</a>
</div>
