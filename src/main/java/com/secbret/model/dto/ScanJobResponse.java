package com.secbret.model.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.secbret.model.entity.ScanJob;
import com.secbret.model.entity.ScanResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

/**
 * Response DTO for a scan job, covering all statuses
 * (Part III §2: PENDING / RUNNING / COMPLETED / FAILED / SUPERSEDED).
 *
 * <p>Null-valued optional fields are omitted from JSON output via
 * {@link JsonInclude#NON_NULL} to keep the response compact per the spec examples.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ScanJobResponse {

    private UUID jobId;
    private UUID urlId;
    private String url;
    private String depth;
    private String status;
    private LocalDateTime createdAt;
    private LocalDateTime startedAt;
    private LocalDateTime completedAt;
    private String errorMessage;
    /** Set when status=SUPERSEDED; points to the new active job (trigger-owned). */
    private UUID supersededBy;
    /** Non-null when status=COMPLETED: the scan result payload. */
    private ScanResultPayload result;

    // -------------------------------------------------------------------------
    // Factory methods
    // -------------------------------------------------------------------------

    /**
     * Build a response for a job with no result yet (PENDING / RUNNING / FAILED /
     * SUPERSEDED).
     */
    public static ScanJobResponse from(ScanJob job) {
        ScanJobResponse r = new ScanJobResponse();
        r.jobId        = job.getId();
        r.urlId        = job.getUrl().getId();
        r.url          = job.getUrl().getOriginalUrl();
        r.depth        = job.getScanDepth().name();
        r.status       = job.getStatus().name();
        r.createdAt    = job.getCreatedAt();
        r.startedAt    = job.getStartedAt();
        r.completedAt  = job.getCompletedAt();
        r.errorMessage = job.getErrorMessage();
        r.supersededBy = job.getSupersededBy();
        return r;
    }

    /**
     * Build a response for a COMPLETED job, including the scan result.
     */
    public static ScanJobResponse fromCompleted(ScanJob job, ScanResult scanResult) {
        ScanJobResponse r = from(job);
        if (scanResult != null) {
            r.result = ScanResultPayload.from(scanResult);
        }
        return r;
    }

    // -------------------------------------------------------------------------
    // Nested result payload
    // -------------------------------------------------------------------------

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class ScanResultPayload {

        private static final Logger log = LoggerFactory.getLogger(ScanResultPayload.class);
        private static final ObjectMapper MAPPER = new ObjectMapper();
        private static final TypeReference<Map<String, Object>> MAP_TYPE =
                new TypeReference<Map<String, Object>>() {};

        private UUID id;
        private Double overallScore;
        /**
         * tier_findings columns are stored as JSON strings in the DB.
         * We parse them into {@code Map<String, Object>} here so that any JAX-RS
         * JSON provider (Jackson or MOXy) serializes them as a nested JSON object
         * rather than as a JSON string or empty object.
         */
        private Map<String, Object> tier1Findings;
        private Map<String, Object> tier2Findings;
        private Map<String, Object> tier3Findings;

        static ScanResultPayload from(ScanResult sr) {
            ScanResultPayload p = new ScanResultPayload();
            p.id = sr.getId();
            p.overallScore = sr.getOverallScore() != null ? sr.getOverallScore().doubleValue() : null;
            p.tier1Findings = parseJsonMap(sr.getTier1Findings());
            p.tier2Findings = parseJsonMap(sr.getTier2Findings());
            p.tier3Findings = parseJsonMap(sr.getTier3Findings());
            return p;
        }

        /**
         * Parse a raw JSON string into a {@code Map<String, Object>}.
         * Returns {@code null} for blank/null input so {@code @JsonInclude(NON_NULL)}
         * omits the field entirely.  Parse errors are logged and treated as null.
         */
        private static Map<String, Object> parseJsonMap(String json) {
            if (json == null || json.isBlank()) {
                return null;
            }
            try {
                return MAPPER.readValue(json, MAP_TYPE);
            } catch (Exception e) {
                log.warn("Failed to parse findings JSON — omitting from response: {}", e.getMessage());
                return null;
            }
        }

        public UUID getId() { return id; }
        public Double getOverallScore() { return overallScore; }
        public Map<String, Object> getTier1Findings() { return tier1Findings; }
        public Map<String, Object> getTier2Findings() { return tier2Findings; }
        public Map<String, Object> getTier3Findings() { return tier3Findings; }
    }

    // -------------------------------------------------------------------------
    // Getters
    // -------------------------------------------------------------------------

    public UUID getJobId() { return jobId; }
    public UUID getUrlId() { return urlId; }
    public String getUrl() { return url; }
    public String getDepth() { return depth; }
    public String getStatus() { return status; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public LocalDateTime getStartedAt() { return startedAt; }
    public LocalDateTime getCompletedAt() { return completedAt; }
    public String getErrorMessage() { return errorMessage; }
    public UUID getSupersededBy() { return supersededBy; }
    public ScanResultPayload getResult() { return result; }
}
