package com.secbret.model.entity;

import com.secbret.model.enums.CommunityVerdict;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Maps V2__create_scanned_url.sql + V14 (deleted_at).
 *
 * <p>{@code deleted_at} is mapped but MUST NOT be written by any v1 code path, and no
 * {@code @Where}/{@code @Filter} soft-delete filtering is applied — Part II §16 defers
 * soft-delete enforcement to v2 deliberately.</p>
 */
@Entity
@Table(name = "scanned_url")
public class ScannedUrl {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id")
    private UUID id;

    @Column(name = "original_url", nullable = false, length = 2048)
    private String originalUrl;

    @Column(name = "normalized_hash", nullable = false, length = 64)
    private String normalizedHash;

    @Column(name = "last_scanned_at")
    private LocalDateTime lastScannedAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "community_verdict", length = 30)
    private CommunityVerdict communityVerdict;

    /** v2 soft-delete tombstone. No v1 write path touches this (Part II §16). */
    @Column(name = "deleted_at", insertable = false, updatable = false)
    private LocalDateTime deletedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    /** Also maintained by the V15 set_updated_at trigger for non-JPA write paths. */
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        createdAt = now;
        updatedAt = now;
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    public UUID getId() { return id; }
    public String getOriginalUrl() { return originalUrl; }
    public void setOriginalUrl(String originalUrl) { this.originalUrl = originalUrl; }
    public String getNormalizedHash() { return normalizedHash; }
    public void setNormalizedHash(String normalizedHash) { this.normalizedHash = normalizedHash; }
    public LocalDateTime getLastScannedAt() { return lastScannedAt; }
    public void setLastScannedAt(LocalDateTime lastScannedAt) { this.lastScannedAt = lastScannedAt; }
    public CommunityVerdict getCommunityVerdict() { return communityVerdict; }
    public void setCommunityVerdict(CommunityVerdict communityVerdict) { this.communityVerdict = communityVerdict; }
    public LocalDateTime getDeletedAt() { return deletedAt; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public LocalDateTime getUpdatedAt() { return updatedAt; }
}
