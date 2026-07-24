<%--
  report/error.jsp — error page for report request failures.
--%>
<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>

<div class="alert alert-danger" role="alert">
    <strong>Error:</strong>
    <c:choose>
        <c:when test="${not empty error}">
            <c:out value="${error}"/>
        </c:when>
        <c:otherwise>An unexpected error occurred. Please try again.</c:otherwise>
    </c:choose>
</div>
<a href="javascript:history.back()" class="btn btn-secondary">Go Back</a>
