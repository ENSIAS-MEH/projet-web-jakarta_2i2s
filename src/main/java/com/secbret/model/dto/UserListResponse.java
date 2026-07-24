package com.secbret.model.dto;

import java.util.List;

/**
 * Paginated user list for GET /admin/users.
 * Matches openapi.yaml#/components/schemas/UserListResponse (allOf UserResponse + PaginationMeta).
 *
 * <p>Items are {@link AdminUserDetailResponse} since the admin list also includes
 * email (UserResponse has email; UserSummaryResponse does not).
 * The spec's UserListResponse allOf references UserResponse (has id/username/email/role/enabled).
 * We use AdminUserDetailResponse which is a strict superset.
 */
public class UserListResponse {

    private final List<AdminUserDetailResponse> users;
    private final long totalElements;
    private final int totalPages;
    private final int currentPage;
    private final int pageSize;

    public UserListResponse(List<AdminUserDetailResponse> users, long totalElements,
                            int currentPage, int pageSize) {
        this.users = users;
        this.totalElements = totalElements;
        this.currentPage = currentPage;
        this.pageSize = pageSize;
        this.totalPages = pageSize > 0 ? (int) Math.ceil((double) totalElements / pageSize) : 0;
    }

    public List<AdminUserDetailResponse> getUsers()  { return users; }
    public long getTotalElements()                   { return totalElements; }
    public int getTotalPages()                       { return totalPages; }
    public int getCurrentPage()                      { return currentPage; }
    public int getPageSize()                         { return pageSize; }
}
