<%-- admin/review-queue.jsp — Analyst review queue (Part III §6) --%>
<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>

<h1>Review Queue</h1>
<p class="text-muted"><c:out value="${total}"/> report(s) awaiting review.</p>

<c:choose>
    <c:when test="${empty reports}">
        <%-- Empty state with context (Part V §1.6) --%>
        <div class="text-center py-5" role="status">
            <p class="text-muted mb-0">No reports pending review. All caught up!</p>
        </div>
    </c:when>
    <c:otherwise>
        <div class="table-responsive">
            <table class="table table-striped" aria-label="Pending Review Queue">
                <thead>
                    <tr>
                        <th scope="col">Report ID</th>
                        <th scope="col">URL</th>
                        <th scope="col">Submitted</th>
                        <th scope="col">Reported By</th>
                        <th scope="col">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <c:forEach var="report" items="${reports}">
                        <tr>
                            <td class="font-monospace small"><c:out value="${report.id}"/></td>
                            <td class="text-break" style="max-width:280px">
                                <c:out value="${report.url != null ? report.url.originalUrl : 'N/A'}"/>
                            </td>
                            <td><c:out value="${report.createdAt}"/></td>
                            <td>
                                <c:choose>
                                    <c:when test="${not empty report.reportedBy}">
                                        <c:out value="${report.reportedBy.username}"/>
                                    </c:when>
                                    <c:otherwise>[deleted]</c:otherwise>
                                </c:choose>
                            </td>
                            <td>
                                <a href="/admin/reviews/<c:out value='${report.id}'/>" class="btn btn-sm btn-primary">Review</a>
                            </td>
                        </tr>
                    </c:forEach>
                </tbody>
            </table>
        </div>
    </c:otherwise>
</c:choose>
