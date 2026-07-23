<%--
  share/list.jsp — authenticated share-links management page (Part III §5 GET /share).
--%>
<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>

<h1>My Share Links</h1>

<c:choose>
    <c:when test="${empty shareLinks}">
        <div class="alert alert-info" role="status">
            You have no share links. Generate a report and a share link will be created automatically.
        </div>
    </c:when>
    <c:otherwise>
        <div class="table-responsive">
            <table class="table table-striped table-hover">
                <caption class="visually-hidden">Share links list</caption>
                <thead>
                    <tr>
                        <th scope="col">UUID</th>
                        <th scope="col">URL</th>
                        <th scope="col">Expires</th>
                        <th scope="col">Access Count</th>
                        <th scope="col">Status</th>
                        <th scope="col">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <c:forEach var="link" items="${shareLinks}">
                        <tr>
                            <td class="font-monospace small">
                                <a href="/share/<c:out value='${link.uuidToken}'/>">
                                    <c:out value="${link.uuidToken}"/>
                                </a>
                            </td>
                            <td class="text-break">
                                <c:choose>
                                    <c:when test="${not empty link.reportJob.url.originalUrl}">
                                        <c:out value="${link.reportJob.url.originalUrl}"/>
                                    </c:when>
                                    <c:otherwise>N/A</c:otherwise>
                                </c:choose>
                            </td>
                            <td><c:out value="${link.expiresAt}"/></td>
                            <td><c:out value="${link.accessCount}"/></td>
                            <td>
                                <c:choose>
                                    <c:when test="${link.revoked}">
                                        <span class="badge bg-secondary">Revoked</span>
                                    </c:when>
                                    <c:otherwise>
                                        <span class="badge bg-success">Active</span>
                                    </c:otherwise>
                                </c:choose>
                            </td>
                            <td>
                                <c:if test="${not link.revoked}">
                                    <%-- js-revoke-form: modal confirmation via secbret.js (Part V §1.3) --%>
                                    <form method="post"
                                          action="/api/v1/share/<c:out value='${link.uuidToken}'/>"
                                          class="d-inline js-revoke-form"
                                          data-uuid="<c:out value='${link.uuidToken}'/>">
                                        <input type="hidden" name="_method" value="DELETE"/>
                                        <%-- CSRF token (Part II §5) --%>
                                        <input type="hidden" name="${mvc.csrf.name}" value="${mvc.csrf.token}"/>
                                        <button type="submit" class="btn btn-sm btn-outline-danger">Revoke</button>
                                    </form>
                                </c:if>
                            </td>
                        </tr>
                    </c:forEach>
                </tbody>
            </table>
        </div>
    </c:otherwise>
</c:choose>
