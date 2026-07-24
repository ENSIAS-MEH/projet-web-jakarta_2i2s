<%-- scan/list.jsp — Scan job list (own jobs for REPORTER, all for ANALYST/ADMIN) --%>
<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>

<h1>My Scans</h1>

<a href="/scan/new" class="btn btn-primary mb-3">Submit New URL</a>

<c:choose>
    <c:when test="${empty jobs}">
        <%-- Empty state with next-action (Part V §1.6) --%>
        <div class="text-center py-5" role="status">
            <p class="text-muted mb-3">You haven&apos;t submitted any URL scans yet.</p>
            <a href="/scan/new" class="btn btn-primary">Scan your first URL</a>
        </div>
    </c:when>
    <c:otherwise>
        <div class="table-responsive">
            <table class="table table-striped" aria-label="Scan Jobs">
                <thead>
                    <tr>
                        <th scope="col">URL</th>
                        <th scope="col">Depth</th>
                        <th scope="col">Status</th>
                        <th scope="col">Submitted</th>
                        <th scope="col">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <c:forEach var="job" items="${jobs}">
                        <tr>
                            <td class="text-break" style="max-width:300px">
                                <c:out value="${job.url != null ? job.url.originalUrl : 'N/A'}"/>
                            </td>
                            <td><c:out value="${job.scanDepth}"/></td>
                            <td>
                                <span class="badge
                                    <c:choose>
                                        <c:when test='${job.status == "COMPLETED"}'>bg-success</c:when>
                                        <c:when test='${job.status == "FAILED"}'>bg-danger</c:when>
                                        <c:when test='${job.status == "SUPERSEDED"}'>bg-secondary</c:when>
                                        <c:otherwise>bg-info text-dark</c:otherwise>
                                    </c:choose>">
                                    <c:out value="${job.status}"/>
                                </span>
                            </td>
                            <td><c:out value="${job.createdAt}"/></td>
                            <td>
                                <a href="/scan/${job.id}" class="btn btn-sm btn-outline-primary">View</a>
                            </td>
                        </tr>
                    </c:forEach>
                </tbody>
            </table>
        </div>
    </c:otherwise>
</c:choose>
