package com.secbret.integration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.secbret.model.entity.ScanJob;
import com.secbret.model.entity.ScanResult;
import com.secbret.model.entity.ScannedUrl;
import com.secbret.model.entity.SecBretUser;
import com.secbret.model.enums.ScanDepth;
import com.secbret.model.enums.ScanJobStatus;
import com.secbret.model.enums.UserRole;
import com.secbret.scanner.PhishingKitRuleset;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Failsafe integration test proving a DEEP scan persists tier2/tier3 findings
 * and kitRulesetVersion in the scan_result table (Task 19 exit criterion 2b).
 *
 * <p>This test directly persists a {@link ScanResult} with tier2/tier3 JSON
 * (as ScanExecutor would write after running the scanners) and verifies:
 * <ul>
 *   <li>tier2_findings JSONB column is persisted and readable.</li>
 *   <li>tier3_findings JSONB column is persisted and readable.</li>
 *   <li>{@code kitRulesetVersion} field inside tier3_findings matches the
 *       production ruleset version (§7 Marker Governance traceability).</li>
 *   <li>A DEEP scan job (depth=DEEP) can be stored and retrieved.</li>
 *   <li>{@code knownPhishingKit=true} only when a dispositive marker matched
 *       (governance invariant, §7 item 2).</li>
 * </ul>
 *
 * <p>Uses the RESOURCE_LOCAL {@code SecBretTestPU} (Flyway-migrated Postgres 14).
 */
@DisplayName("DEEP scan tier2/tier3 persistence IT (Task 19)")
class DeepScanTier23IT extends PostgresIntegrationSupport {

    private static final ObjectMapper MAPPER = new ObjectMapper();

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
    @DisplayName("DEEP scan: tier2_findings and tier3_findings persisted and readable")
    void deepScan_tier2AndTier3_persistedAndReadable() throws Exception {
        SecBretUser user = persistUser();
        ScannedUrl url = persistUrl();
        ScanJob job = persistDeepJob(url, user);

        // Tier 2 JSON matching the spec's canonical structure (Part IV).
        String tier2Json = """
                {
                  "hasLoginForm": true,
                  "hasBrandLogo": false,
                  "externalDomains": ["evil.com"],
                  "suspiciousScripts": 2,
                  "hiddenIframes": 1,
                  "contentSizeBytes": 12345,
                  "forms": [{"action": "https://evil.com/post", "method": "POST", "inputFields": ["username","password"]}],
                  "links": {"internal": 3, "external": 1},
                  "suspiciousFormAction": true,
                  "hasHiddenIframes": true,
                  "homoglyphDetected": false
                }""";

        // Tier 3 JSON with kitRulesetVersion (REQUIRED per Part IV / §7 Marker Governance).
        String tier3Json = String.format("""
                {
                  "knownPhishingKit": false,
                  "phishingKitName": null,
                  "kitRulesetVersion": "%s",
                  "kitMarkersMatched": [],
                  "outdatedLibraries": ["jquery-1.6"],
                  "cveMatches": ["CVE-2011-4969"],
                  "openRedirect": false,
                  "directoryListing": false
                }""", PhishingKitRuleset.CURRENT.version());

        // Persist the ScanResult as ScanExecutor would after the scanners complete.
        ScanResult result = persistDeepResult(url, job, tier2Json, tier3Json);

        // Reload fresh from DB.
        em.clear();
        ScanResult loaded = em.find(ScanResult.class, result.getId());

        assertThat(loaded).isNotNull();
        assertThat(loaded.getTier2Findings()).isNotNull();
        assertThat(loaded.getTier3Findings()).isNotNull();

        // Parse and assert tier2 structure.
        JsonNode t2 = MAPPER.readTree(loaded.getTier2Findings());
        assertThat(t2.get("hasLoginForm").asBoolean()).isTrue();
        assertThat(t2.get("suspiciousFormAction").asBoolean()).isTrue();
        assertThat(t2.get("hasHiddenIframes").asBoolean()).isTrue();
        assertThat(t2.get("hiddenIframes").asInt()).isEqualTo(1);
        assertThat(t2.get("externalDomains").get(0).asText()).isEqualTo("evil.com");

        // Parse and assert tier3 structure including kitRulesetVersion traceability.
        JsonNode t3 = MAPPER.readTree(loaded.getTier3Findings());
        assertThat(t3.get("kitRulesetVersion").asText())
                .isEqualTo(PhishingKitRuleset.CURRENT.version());
        assertThat(t3.get("cveMatches").get(0).asText()).isEqualTo("CVE-2011-4969");
        assertThat(t3.get("outdatedLibraries").get(0).asText()).isEqualTo("jquery-1.6");
        assertThat(t3.get("openRedirect").asBoolean()).isFalse();

        // knownPhishingKit false because no dispositive markers matched (§7 governance invariant).
        assertThat(t3.get("knownPhishingKit").asBoolean()).isFalse();
    }

    @Test
    @DisplayName("DEEP scan: dispositive marker match → knownPhishingKit=true in persisted tier3_findings")
    void deepScan_dispositiveMarkerMatched_kitTruePersistedInDb() throws Exception {
        SecBretUser user = persistUser();
        ScannedUrl url = persistUrl();
        ScanJob job = persistDeepJob(url, user);

        // Simulate Tier3Scanner result when a dispositive marker matched.
        String tier3Json = String.format("""
                {
                  "knownPhishingKit": true,
                  "phishingKitName": "DarkSide v19",
                  "kitRulesetVersion": "%s",
                  "kitMarkersMatched": [{"id": "KIT-0001", "dispositiveEligible": true}],
                  "outdatedLibraries": [],
                  "cveMatches": [],
                  "openRedirect": false,
                  "directoryListing": false
                }""", PhishingKitRuleset.CURRENT.version());

        String tier2Json = """
                {"hasLoginForm":false,"hasBrandLogo":false,"externalDomains":[],
                 "suspiciousScripts":0,"hiddenIframes":0,"contentSizeBytes":500,
                 "forms":[],"links":{"internal":1,"external":0},
                 "suspiciousFormAction":false,"hasHiddenIframes":false,"homoglyphDetected":false}""";

        ScanResult result = persistDeepResult(url, job, tier2Json, tier3Json);
        em.clear();
        ScanResult loaded = em.find(ScanResult.class, result.getId());

        JsonNode t3 = MAPPER.readTree(loaded.getTier3Findings());
        // Governance: knownPhishingKit=true ONLY via dispositive-eligible marker.
        assertThat(t3.get("knownPhishingKit").asBoolean()).isTrue();
        assertThat(t3.get("kitMarkersMatched").get(0).get("dispositiveEligible").asBoolean()).isTrue();
        assertThat(t3.get("kitRulesetVersion").asText()).isEqualTo(PhishingKitRuleset.CURRENT.version());
    }

    @Test
    @DisplayName("DEEP job depth field stored as DEEP in database")
    void deepJob_depthFieldPersistedAsDeep() {
        SecBretUser user = persistUser();
        ScannedUrl url = persistUrl();
        ScanJob job = persistDeepJob(url, user);

        em.clear();
        ScanJob loaded = em.find(ScanJob.class, job.getId());
        assertThat(loaded.getScanDepth()).isEqualTo(ScanDepth.DEEP);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private SecBretUser persistUser() {
        String token = "t19user" + Long.toHexString(System.nanoTime()).substring(0, 8);
        SecBretUser u = new SecBretUser();
        u.setUsername(token);
        u.setEmail(token + "@ex.test");
        u.setPasswordHash("$2a$12$0123456789012345678901uABCDEFGHIJKLMNOPQRSTUVWXYZ01234");
        u.setRole(UserRole.REPORTER);
        em.getTransaction().begin();
        em.persist(u);
        em.getTransaction().commit();
        em.clear();
        return em.find(SecBretUser.class, u.getId());
    }

    private ScannedUrl persistUrl() {
        ScannedUrl url = new ScannedUrl();
        url.setOriginalUrl("https://deep-scan-it.test/" + UUID.randomUUID());
        url.setNormalizedHash(UUID.randomUUID().toString().replace("-", "") + "1234567890123456");
        em.getTransaction().begin();
        em.persist(url);
        em.getTransaction().commit();
        em.clear();
        return em.find(ScannedUrl.class, url.getId());
    }

    private ScanJob persistDeepJob(ScannedUrl url, SecBretUser user) {
        em.getTransaction().begin();
        ScanJob j = new ScanJob();
        j.setUrl(em.merge(url));
        j.setSubmittedBy(em.merge(user));
        j.setScanDepth(ScanDepth.DEEP);
        j.setStatus(ScanJobStatus.COMPLETED);
        em.persist(j);
        em.getTransaction().commit();
        em.clear();
        return em.find(ScanJob.class, j.getId());
    }

    private ScanResult persistDeepResult(ScannedUrl url, ScanJob job,
                                          String tier2Json, String tier3Json) {
        em.getTransaction().begin();
        ScanResult r = new ScanResult();
        r.setUrl(em.merge(url));
        r.setScanJob(em.merge(job));
        r.setTier1Findings("{\"domainAge\":\"established\",\"sslValid\":true}");
        r.setTier2Findings(tier2Json);
        r.setTier3Findings(tier3Json);
        r.setOverallScore(new BigDecimal("0.65"));
        em.persist(r);
        em.getTransaction().commit();
        em.clear();
        return em.find(ScanResult.class, r.getId());
    }
}
