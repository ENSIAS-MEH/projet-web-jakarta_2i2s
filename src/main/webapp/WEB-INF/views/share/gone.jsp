<%--
  share/gone.jsp — 410 Gone page for expired or revoked share links.
--%>
<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>

<div class="alert alert-warning" role="alert">
    <h4 class="alert-heading">Link Expired or Revoked</h4>
    <p>
        <c:choose>
            <c:when test="${not empty errorMessage}">
                <c:out value="${errorMessage}"/>
            </c:when>
            <c:otherwise>This share link has expired or been revoked and is no longer accessible.</c:otherwise>
        </c:choose>
    </p>
    <hr>
    <p class="mb-0">Please contact the report owner to request a new share link.</p>
</div>
