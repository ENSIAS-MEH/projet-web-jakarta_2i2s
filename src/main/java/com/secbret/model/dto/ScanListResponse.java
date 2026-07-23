package com.secbret.model.dto;

import java.util.List;

/**
 * Paginated list response for GET /api/v1/scan (Part III §2).
 *
 * <pre>
 * {
 *   "scans": [...],
 *   "totalElements": 42,
 *   "totalPages": 3,
 *   "currentPage": 1,
 *   "pageSize": 20
 * }
 * </pre>
 */
public class ScanListResponse {

    private final List<ScanJobResponse> scans;
    private final long totalElements;
    private final int totalPages;
    private final int currentPage;
    private final int pageSize;

    public ScanListResponse(List<ScanJobResponse> scans, long totalElements,
                             int currentPage, int pageSize) {
        this.scans = scans;
        this.totalElements = totalElements;
        this.currentPage = currentPage;
        this.pageSize = pageSize;
        this.totalPages = pageSize > 0 ? (int) Math.ceil((double) totalElements / pageSize) : 0;
    }

    public List<ScanJobResponse> getScans() { return scans; }
    public long getTotalElements() { return totalElements; }
    public int getTotalPages() { return totalPages; }
    public int getCurrentPage() { return currentPage; }
    public int getPageSize() { return pageSize; }
}
