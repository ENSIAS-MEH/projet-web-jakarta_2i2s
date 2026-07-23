package com.secbret.model.dto;

import java.util.List;

/** Paginated list response for GET /api/v1/incident. */
public class IncidentListResponse {

    private List<IncidentResponse> reports;
    private long totalElements;
    private int totalPages;
    private int currentPage;
    private int pageSize;

    public IncidentListResponse(List<IncidentResponse> reports, long totalElements, int currentPage, int pageSize) {
        this.reports = reports;
        this.totalElements = totalElements;
        this.currentPage = currentPage;
        this.pageSize = pageSize;
        this.totalPages = pageSize > 0 ? (int) Math.ceil((double) totalElements / pageSize) : 0;
    }

    public List<IncidentResponse> getReports() { return reports; }
    public long getTotalElements() { return totalElements; }
    public int getTotalPages() { return totalPages; }
    public int getCurrentPage() { return currentPage; }
    public int getPageSize() { return pageSize; }
}
