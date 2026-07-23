package com.secbret.model.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Maps V13__create_idempotency_key.sql — per-user-per-endpoint idempotency store
 * (Part III §Idempotency-Key). Three endpoints: POST /scan, POST /incident,
 * POST /report-jobs.
 */
@Entity
@Table(name = "idempotency_key")
public class IdempotencyKey {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id")
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private SecBretUser user;

    /** The client-supplied idempotency key string. */
    @Column(name = "idem_key", nullable = false, length = 255)
    private String idemKey;

    /** Path template: "POST /scan", "POST /incident", "POST /report-jobs". */
    @Column(name = "endpoint", nullable = false, length = 100)
    private String endpoint;

    /** SHA-256 hex of the canonical request body. */
    @Column(name = "request_hash", nullable = false, length = 64)
    private String requestHash;

    /** NULL while request is in-flight; set when response is captured. */
    @Column(name = "response_status")
    private Integer responseStatus;

    /** Serialized JSON response body; NULL while in-flight. */
    @Column(name = "response_body")
    private String responseBody;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    void onCreate() {
        createdAt = LocalDateTime.now();
    }

    public UUID getId() { return id; }
    public SecBretUser getUser() { return user; }
    public void setUser(SecBretUser user) { this.user = user; }
    public String getIdemKey() { return idemKey; }
    public void setIdemKey(String idemKey) { this.idemKey = idemKey; }
    public String getEndpoint() { return endpoint; }
    public void setEndpoint(String endpoint) { this.endpoint = endpoint; }
    public String getRequestHash() { return requestHash; }
    public void setRequestHash(String requestHash) { this.requestHash = requestHash; }
    public Integer getResponseStatus() { return responseStatus; }
    public void setResponseStatus(Integer responseStatus) { this.responseStatus = responseStatus; }
    public String getResponseBody() { return responseBody; }
    public void setResponseBody(String responseBody) { this.responseBody = responseBody; }
    public LocalDateTime getExpiresAt() { return expiresAt; }
    public void setExpiresAt(LocalDateTime expiresAt) { this.expiresAt = expiresAt; }
    public LocalDateTime getCreatedAt() { return createdAt; }

    /** True when the request has completed and the response has been captured. */
    public boolean isComplete() {
        return responseStatus != null;
    }

    /** True when the request is still in-flight (no response yet). */
    public boolean isInFlight() {
        return responseStatus == null;
    }
}
