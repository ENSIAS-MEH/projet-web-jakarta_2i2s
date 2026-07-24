<%--
  dashboard/public.jsp — Public Community Verdicts Dashboard (Part III §7)

  Receives from PublicDashboardWebController:
    entries       (List<PublicDashboardEntry>) — current page of URL entries
    totalElements (long)  — total matching rows
    totalPages    (int)   — total pages
    currentPage   (int)   — 1-based current page
    pageSize      (int)   — rows per page
    verdictFilter (String) — current verdict filter ("MALICIOUS","BENIGN","")
    error         (String) — validation error if any

  Empty state (Part V §1.6): rendered when entries is empty.
  Verdict badges: non-color-only (text + color) per Part V §2.8.
--%>
<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>
<%@ taglib prefix="fmt" uri="jakarta.tags.fmt" %>
<%@ taglib prefix="fn" uri="jakarta.tags.functions" %>

<h1 class="h3 mb-4">Community Verdicts</h1>

<%-- Validation error (e.g. bad ?verdict param) --%>
<c:if test="${not empty error}">
    <div class="alert alert-danger" role="alert" aria-live="assertive">
        <c:out value="${error}"/>
    </div>
</c:if>

<%-- Filter controls --%>
<form method="get" action="/dashboard/public" class="row g-2 mb-4" aria-label="Filter verdicts">
    <div class="col-auto">
        <label for="verdictSelect" class="col-form-label">Verdict</label>
    </div>
    <div class="col-auto">
        <select id="verdictSelect" name="verdict" class="form-select form-select-sm">
            <option value="" ${empty verdictFilter ? 'selected' : ''}>All established verdicts</option>
            <option value="MALICIOUS" ${'MALICIOUS' eq verdictFilter ? 'selected' : ''}>Malicious</option>
            <option value="BENIGN"    ${'BENIGN' eq verdictFilter    ? 'selected' : ''}>Benign</option>
        </select>
    </div>
    <div class="col-auto">
        <button type="submit" class="btn btn-sm btn-outline-secondary">Filter</button>
    </div>
</form>

<%-- Result summary --%>
<c:if test="${empty error}">
    <p class="text-muted small mb-2">
        <c:choose>
            <c:when test="${totalElements == 0}">No results.</c:when>
            <c:otherwise>
                Showing page <c:out value="${currentPage}"/> of <c:out value="${totalPages}"/>
                (<c:out value="${totalElements}"/> URLs total).
            </c:otherwise>
        </c:choose>
    </p>
</c:if>

<%-- Empty state (Part V §1.6) --%>
<c:if test="${empty entries and empty error}">
    <div class="alert alert-secondary" role="status" aria-live="polite">
        No community verdicts have been established yet. URLs are reviewed after incidents are submitted.
    </div>
</c:if>

<%-- Data table --%>
<c:if test="${not empty entries}">
    <div class="table-responsive">
        <table class="table table-hover align-middle" aria-label="Community verdict list">
            <thead class="table-dark">
                <tr>
                    <th scope="col">URL</th>
                    <th scope="col">Verdict</th>
                    <th scope="col">Threat Score</th>
                    <th scope="col">Last Scanned</th>
                </tr>
            </thead>
            <tbody>
                <c:forEach var="entry" items="${entries}">
                    <tr>
                        <td class="text-break small" style="max-width: 40ch;">
                            <a href="/dashboard/public?url=<c:out value='${entry.url}'/>"
                               title="<c:out value='${entry.url}'/>">
                                <c:out value="${entry.url}"/>
                            </a>
                        </td>
                        <td>
                            <%-- Non-color-only badge: text label + color (Part V §2.8) --%>
                            <c:choose>
                                <c:when test="${entry.communityVerdict == 'MALICIOUS'}">
                                    <span class="badge bg-danger" aria-label="Community verdict: Malicious">
                                        Malicious
                                    </span>
                                </c:when>
                                <c:when test="${entry.communityVerdict == 'BENIGN'}">
                                    <span class="badge bg-success" aria-label="Community verdict: Benign">
                                        Benign
                                    </span>
                                </c:when>
                                <c:otherwise>
                                    <span class="badge bg-secondary" aria-label="Community verdict: Unknown">
                                        <c:out value="${entry.communityVerdict}"/>
                                    </span>
                                </c:otherwise>
                            </c:choose>
                        </td>
                        <td>
                            <c:choose>
                                <c:when test="${not empty entry.threatScore}">
                                    <c:out value="${entry.threatScore}"/>
                                </c:when>
                                <c:otherwise>
                                    <span class="text-muted">—</span>
                                </c:otherwise>
                            </c:choose>
                        </td>
                        <td class="text-nowrap small">
                            <c:choose>
                                <c:when test="${not empty entry.lastScannedAt}">
                                    <c:out value="${entry.lastScannedAt}"/>
                                </c:when>
                                <c:otherwise>
                                    <span class="text-muted">—</span>
                                </c:otherwise>
                            </c:choose>
                        </td>
                    </tr>
                </c:forEach>
            </tbody>
        </table>
    </div>

    <%-- Pagination controls --%>
    <c:if test="${totalPages > 1}">
        <nav aria-label="Dashboard pagination">
            <ul class="pagination pagination-sm justify-content-center">
                <c:if test="${currentPage > 1}">
                    <li class="page-item">
                        <a class="page-link"
                           href="/dashboard/public?page=${currentPage - 1}&size=${pageSize}&verdict=${fn:escapeXml(verdictFilter)}"
                           aria-label="Previous page">Previous</a>
                    </li>
                </c:if>
                <c:forEach var="i" begin="1" end="${totalPages}">
                    <li class="page-item ${i == currentPage ? 'active' : ''}">
                        <a class="page-link"
                           href="/dashboard/public?page=${i}&size=${pageSize}&verdict=${fn:escapeXml(verdictFilter)}"
                           aria-label="Page ${i}"
                           ${i == currentPage ? 'aria-current="page"' : ''}>
                            <c:out value="${i}"/>
                        </a>
                    </li>
                </c:forEach>
                <c:if test="${currentPage < totalPages}">
                    <li class="page-item">
                        <a class="page-link"
                           href="/dashboard/public?page=${currentPage + 1}&size=${pageSize}&verdict=${fn:escapeXml(verdictFilter)}"
                           aria-label="Next page">Next</a>
                    </li>
                </c:if>
            </ul>
        </nav>
    </c:if>
</c:if>
