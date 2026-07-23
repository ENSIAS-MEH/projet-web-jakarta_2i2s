<%-- incident/list.jsp — Incident report list --%>
<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>

<h1>Incident Reports</h1>

<a href="/incident/new" class="btn btn-primary mb-3">Report New Incident</a>

<c:choose>
    <c:when test="${empty reports}">
        <%-- Empty state with next-action (Part V §1.6) --%>
        <div class="text-center py-5" role="status">
            <p class="text-muted mb-3">You haven&apos;t submitted any incident reports yet.</p>
            <a href="/incident/new" class="btn btn-primary">Report your first incident</a>
        </div>
    </c:when>
    <c:otherwise>
        <div class="table-responsive">
            <table class="table table-striped" aria-label="Incident Reports">
                <thead>
                    <tr>
                        <th scope="col">Report ID</th>
                        <th scope="col">URL</th>
                        <th scope="col">Status</th>
                        <th scope="col">Submitted</th>
                        <th scope="col">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <c:forEach var="report" items="${reports}">
                        <tr>
                            <td class="font-monospace small"><c:out value="${report.id}"/></td>
                            <td class="text-break" style="max-width:300px">
                                <c:out value="${report.url != null ? report.url.originalUrl : 'N/A'}"/>
                            </td>
                            <td>
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
                            </td>
                            <td><c:out value="${report.createdAt}"/></td>
                            <td>
                                <a href="/incident/${report.id}" class="btn btn-sm btn-outline-primary">View</a>
                            </td>
                        </tr>
                    </c:forEach>
                </tbody>
            </table>
        </div>
    </c:otherwise>
</c:choose>
