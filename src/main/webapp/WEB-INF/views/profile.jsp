<%-- profile.jsp — account information page for the signed-in user --%>
<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>

<h1>My Profile</h1>

<div class="card mb-4">
    <div class="card-header">
        <h2 class="h6 mb-0">Account information</h2>
    </div>
    <div class="card-body">
        <dl class="row mb-0">
            <dt class="col-sm-3">Username</dt>
            <dd class="col-sm-9"><c:out value="${user.username}"/></dd>

            <dt class="col-sm-3">Email</dt>
            <dd class="col-sm-9"><c:out value="${user.email}"/></dd>

            <dt class="col-sm-3">Role</dt>
            <dd class="col-sm-9">
                <span class="badge
                    <c:choose>
                        <c:when test='${user.role == "ADMIN"}'>bg-danger</c:when>
                        <c:when test='${user.role == "ANALYST"}'>bg-primary</c:when>
                        <c:otherwise>bg-secondary</c:otherwise>
                    </c:choose>">
                    <c:out value="${user.role}"/>
                </span>
                <c:if test='${user.role == "REPORTER"}'>
                    <span class="text-muted small ms-2">
                        Analyst access is granted by an administrator.
                    </span>
                </c:if>
            </dd>

            <dt class="col-sm-3">Member since</dt>
            <dd class="col-sm-9"><c:out value="${user.createdAt}"/></dd>

            <dt class="col-sm-3">Status</dt>
            <dd class="col-sm-9">
                <c:choose>
                    <c:when test="${user.enabled}">
                        <span class="badge bg-success">Active</span>
                    </c:when>
                    <c:otherwise>
                        <span class="badge bg-secondary">Disabled</span>
                    </c:otherwise>
                </c:choose>
            </dd>
        </dl>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <h2 class="h6 mb-0">Your activity</h2>
    </div>
    <div class="card-body d-flex gap-2 flex-wrap">
        <a href="/scan" class="btn btn-outline-primary">My Scans</a>
        <a href="/incident" class="btn btn-outline-primary">My Incident Reports</a>
        <a href="/shares" class="btn btn-outline-primary">My Share Links</a>
        <a href="/scan/new" class="btn btn-outline-secondary">Submit a URL</a>
        <a href="/incident/new" class="btn btn-outline-secondary">Report an Incident</a>
    </div>
</div>
