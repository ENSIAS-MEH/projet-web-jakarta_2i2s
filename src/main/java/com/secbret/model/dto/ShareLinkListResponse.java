package com.secbret.model.dto;

import java.util.List;

/** Paginated GET /share response. */
public class ShareLinkListResponse {
    private List<ShareLinkResponse> shareLinks;
    private long totalElements;
    private int totalPages;
    private int currentPage;
    private int pageSize;

    public ShareLinkListResponse(List<ShareLinkResponse> shareLinks, long total, int page, int size) {
        this.shareLinks = shareLinks;
        this.totalElements = total;
        this.totalPages = (int) Math.ceil((double) total / size);
        this.currentPage = page;
        this.pageSize = size;
    }

    public List<ShareLinkResponse> getShareLinks() { return shareLinks; }
    public long getTotalElements() { return totalElements; }
    public int getTotalPages() { return totalPages; }
    public int getCurrentPage() { return currentPage; }
    public int getPageSize() { return pageSize; }
}
