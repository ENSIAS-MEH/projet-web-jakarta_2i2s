package com.secbret.model.dto;

import java.util.List;

/**
 * Paginated response for GET /api/v1/dashboard/public (Part III §7).
 *
 * <pre>
 * {
 *   "urls": [...],
 *   "totalElements": 120,
 *   "totalPages": 6,
 *   "currentPage": 1,
 *   "pageSize": 20
 * }
 * </pre>
 */
public class PublicDashboardResponse {

    private final List<PublicDashboardEntry> urls;
    private final long totalElements;
    private final int totalPages;
    private final int currentPage;
    private final int pageSize;

    public PublicDashboardResponse(List<PublicDashboardEntry> urls, long totalElements,
                                   int currentPage, int pageSize) {
        this.urls = urls;
        this.totalElements = totalElements;
        this.currentPage = currentPage;
        this.pageSize = pageSize;
        this.totalPages = pageSize > 0 ? (int) Math.ceil((double) totalElements / pageSize) : 0;
    }

    public List<PublicDashboardEntry> getUrls() { return urls; }
    public long getTotalElements() { return totalElements; }
    public int getTotalPages() { return totalPages; }
    public int getCurrentPage() { return currentPage; }
    public int getPageSize() { return pageSize; }
}
