package com.secbret.model.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.List;

/**
 * Request body for POST /api/v1/incident (Part III §3).
 *
 * <p>Bean Validation annotations match openapi.yaml IncidentReportRequest constraints (Phase 5).
 * The manual validateRequest() guard in IncidentResource is retained as defense-in-depth
 * for the web form path; the @Valid path covers the JSON API path.
 */
public class IncidentRequest {

    @NotBlank(message = "url is required")
    @Size(max = 2048, message = "url must not exceed 2048 characters")
    private String url;

    @NotBlank(message = "evidenceDescription is required")
    @Size(min = 10, max = 2000,
          message = "evidenceDescription must be 10–2000 characters")
    private String evidenceDescription;

    @Size(max = 5, message = "evidenceUrls may contain at most 5 entries")
    private List<String> evidenceUrls;

    public IncidentRequest() {}

    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }

    public String getEvidenceDescription() { return evidenceDescription; }
    public void setEvidenceDescription(String evidenceDescription) { this.evidenceDescription = evidenceDescription; }

    public List<String> getEvidenceUrls() { return evidenceUrls; }
    public void setEvidenceUrls(List<String> evidenceUrls) { this.evidenceUrls = evidenceUrls; }
}
