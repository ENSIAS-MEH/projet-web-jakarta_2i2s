<%--
  incident/status-fragment.jsp — HTMX polling fragment for incident analysis status.

  Returned by GET /incident/{id}/status-fragment. On a terminal status the
  controller sets HX-Trigger: stopPolling and HX-Refresh: true — the page
  reloads and renders the analysis server-side, so this fragment only ever
  needs the in-progress affordance.
--%>
<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>

<c:choose>
    <c:when test="${status == 'PENDING'}">
        <p class="text-muted">
            <span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>
            Analysis running&hellip;
        </p>
    </c:when>
    <c:otherwise>
        <p class="text-muted">Analysis complete. Loading results&hellip;</p>
    </c:otherwise>
</c:choose>
