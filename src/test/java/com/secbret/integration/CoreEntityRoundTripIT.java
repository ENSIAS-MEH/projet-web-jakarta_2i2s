package com.secbret.integration;

import com.secbret.model.entity.ScanJob;
import com.secbret.model.entity.ScanResult;
import com.secbret.model.entity.ScannedUrl;
import com.secbret.model.entity.SecBretUser;
import com.secbret.model.enums.ScanDepth;
import com.secbret.model.enums.ScanJobStatus;
import com.secbret.model.enums.UserRole;
import com.secbret.repository.ScanJobRepository;
import com.secbret.repository.ScanResultRepository;
import com.secbret.repository.ScannedUrlRepository;
import com.secbret.repository.UserRepository;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Round-trips the four core entities through the real Flyway-migrated schema,
 * proving the JPA mappings agree with the V1-V20 DDL (column names, enum
 * strings, JSONB, FK wiring, optimistic-lock version).
 */
class CoreEntityRoundTripIT extends PostgresIntegrationSupport {

    private EntityManager em;

    @BeforeEach
    void openEm() {
        em = EMF.createEntityManager();
    }

    @AfterEach
    void closeEm() {
        if (em.getTransaction().isActive()) {
            em.getTransaction().rollback();
        }
        em.close();
    }

    @Test
    void userPersistsAndReadsBackThroughRepository() {
        UserRepository users = new UserRepository(em);
        String username = "reporter-" + UUID.randomUUID();

        SecBretUser user = new SecBretUser();
        user.setUsername(username);
        user.setEmail(username + "@example.test");
        user.setPasswordHash("$2a$12$0123456789012345678901uABCDEFGHIJKLMNOPQRSTUVWXYZ01234");
        user.setRole(UserRole.REPORTER);

        em.getTransaction().begin();
        users.persist(user);
        em.getTransaction().commit();
        em.clear();

        SecBretUser found = users.findByUsername(username).orElseThrow();
        assertThat(found.getId()).isNotNull();
        assertThat(found.getEmail()).isEqualTo(username + "@example.test");
        assertThat(found.getRole()).isEqualTo(UserRole.REPORTER);
        assertThat(found.isEnabled()).isTrue();
        assertThat(found.getFailedLoginAttempts()).isZero();
        assertThat(found.getCreatedAt()).isNotNull();
        assertThat(found.getUpdatedAt()).isNotNull();
    }

    @Test
    void scanGraphPersistsAndReadsBack() {
        ScannedUrlRepository urls = new ScannedUrlRepository(em);
        ScanJobRepository jobs = new ScanJobRepository(em);
        ScanResultRepository results = new ScanResultRepository(em);

        ScannedUrl url = new ScannedUrl();
        url.setOriginalUrl("https://example.test/login?a=1");
        url.setNormalizedHash(sha256LikeHash());

        ScanJob job = new ScanJob();
        job.setUrl(url);
        job.setScanDepth(ScanDepth.QUICK);
        job.setStatus(ScanJobStatus.PENDING);

        ScanResult result = new ScanResult();
        result.setUrl(url);
        result.setScanJob(job);
        result.setTier1Findings("{\"domainAgeDays\": 3, \"sslValid\": false}");
        result.setOverallScore(new BigDecimal("0.42"));

        em.getTransaction().begin();
        urls.persist(url);
        jobs.persist(job);
        results.persist(result);
        em.getTransaction().commit();
        em.clear();

        ScannedUrl foundUrl = urls.findByNormalizedHash(url.getNormalizedHash()).orElseThrow();
        assertThat(foundUrl.getOriginalUrl()).isEqualTo("https://example.test/login?a=1");
        assertThat(foundUrl.getDeletedAt()).isNull();

        ScanJob foundJob = jobs.findById(job.getId()).orElseThrow();
        assertThat(foundJob.getStatus()).isEqualTo(ScanJobStatus.PENDING);
        assertThat(foundJob.getScanDepth()).isEqualTo(ScanDepth.QUICK);
        // Trigger-owned column: no supersede happened, so it must be NULL —
        // and the entity mapping offers no setter/insertable path to write it.
        assertThat(foundJob.getSupersededBy()).isNull();

        ScanResult foundResult = results.findByScanJobId(job.getId()).orElseThrow();
        assertThat(foundResult.getTier1Findings()).contains("domainAgeDays");
        assertThat(foundResult.getOverallScore()).isEqualByComparingTo("0.42");
    }

    private static String sha256LikeHash() {
        return (UUID.randomUUID().toString() + UUID.randomUUID()).replace("-", "").substring(0, 64);
    }
}
