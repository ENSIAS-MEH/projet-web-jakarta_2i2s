<%-- admin/users.jsp — user management (ADMIN only, use case "Manage Users") --%>
<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>

<h1>User Management</h1>

<p class="text-muted">
    <c:out value="${totalUsers}"/> registered user(s). Changing a role takes effect
    on the user's next request; promoting to ANALYST grants access to the review queue.
</p>

<c:choose>
    <c:when test="${empty users}">
        <div class="text-center py-5" role="status">
            <p class="text-muted mb-0">No users found.</p>
        </div>
    </c:when>
    <c:otherwise>
        <div class="table-responsive">
            <table class="table table-striped align-middle" aria-label="Registered users">
                <thead>
                    <tr>
                        <th scope="col">Username</th>
                        <th scope="col">Email</th>
                        <th scope="col">Role</th>
                        <th scope="col">Status</th>
                        <th scope="col">Registered</th>
                        <th scope="col">Change role</th>
                    </tr>
                </thead>
                <tbody>
                    <c:forEach var="u" items="${users}">
                        <tr>
                            <td><c:out value="${u.username}"/></td>
                            <td class="text-break"><c:out value="${u.email}"/></td>
                            <td>
                                <span class="badge
                                    <c:choose>
                                        <c:when test='${u.role == "ADMIN"}'>bg-danger</c:when>
                                        <c:when test='${u.role == "ANALYST"}'>bg-primary</c:when>
                                        <c:otherwise>bg-secondary</c:otherwise>
                                    </c:choose>">
                                    <c:out value="${u.role}"/>
                                </span>
                            </td>
                            <td>
                                <c:choose>
                                    <c:when test="${u.enabled}">
                                        <span class="badge bg-success">Active</span>
                                    </c:when>
                                    <c:otherwise>
                                        <span class="badge bg-secondary">Disabled</span>
                                    </c:otherwise>
                                </c:choose>
                            </td>
                            <td><c:out value="${u.createdAt}"/></td>
                            <td>
                                <form method="post"
                                      action="/admin/users/${u.id}/role"
                                      class="d-flex gap-2 align-items-center">
                                    <input type="hidden" name="${mvc.csrf.name}" value="${mvc.csrf.token}"/>
                                    <label class="visually-hidden" for="role-${u.id}">
                                        New role for <c:out value="${u.username}"/>
                                    </label>
                                    <select class="form-select form-select-sm w-auto"
                                            id="role-${u.id}" name="role">
                                        <c:forEach var="r" items="${roles}">
                                            <option value="${r}" ${u.role == r ? 'selected' : ''}>${r}</option>
                                        </c:forEach>
                                    </select>
                                    <button type="submit" class="btn btn-sm btn-outline-primary">Save</button>
                                </form>
                            </td>
                        </tr>
                    </c:forEach>
                </tbody>
            </table>
        </div>
    </c:otherwise>
</c:choose>
