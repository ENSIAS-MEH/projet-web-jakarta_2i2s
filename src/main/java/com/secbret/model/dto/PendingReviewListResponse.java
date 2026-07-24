package com.secbret.model.dto;

import java.util.List;

/** Response for GET /api/v1/admin/reviews/pending. */
public class PendingReviewListResponse {

    private List<PendingReviewEntry> pendingReviews;
    private long totalElements;
    private int totalPages;
    private int currentPage;
    private int pageSize;

    public PendingReviewListResponse(List<PendingReviewEntry> pendingReviews,
                                      long totalElements, int currentPage, int pageSize) {
        this.pendingReviews = pendingReviews;
        this.totalElements = totalElements;
        this.currentPage = currentPage;
        this.pageSize = pageSize;
        this.totalPages = pageSize > 0 ? (int) Math.ceil((double) totalElements / pageSize) : 0;
    }

    public List<PendingReviewEntry> getPendingReviews() { return pendingReviews; }
    public long getTotalElements() { return totalElements; }
    public int getTotalPages() { return totalPages; }
    public int getCurrentPage() { return currentPage; }
    public int getPageSize() { return pageSize; }
}
