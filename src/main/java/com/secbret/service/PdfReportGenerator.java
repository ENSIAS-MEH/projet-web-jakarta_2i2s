package com.secbret.service;

import com.lowagie.text.Chunk;
import com.lowagie.text.Document;
import com.lowagie.text.Element;
import com.lowagie.text.Font;
import com.lowagie.text.FontFactory;
import com.lowagie.text.PageSize;
import com.lowagie.text.Paragraph;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.PdfPageEventHelper;
import com.lowagie.text.pdf.PdfWriter;
import com.secbret.model.entity.ReportJob;
import com.secbret.model.entity.ScanResult;
import com.secbret.model.entity.SecBretAnalysis;
import com.secbret.model.entity.SecurityTeamReview;
import jakarta.enterprise.context.ApplicationScoped;

import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Generates the 3-page condensed PDF report (Part II §8).
 *
 * <h2>Page structure</h2>
 * <ol>
 *   <li>Score &amp; Verdict — logo, target URL, scan date, threat score gauge, verdict badge,
 *       summary paragraph.</li>
 *   <li>Executive Summary &amp; AI Reasoning — reasoning chain, ML contribution, security team notes,
 *       community verdict. If no {@link SecBretAnalysis}, renders the placeholder text per §8.</li>
 *   <li>Technical Findings — tier1/2/3 raw JSON findings (formatted), report metadata footer.</li>
 * </ol>
 *
 * <h2>Score fallback (§8)</h2>
 * <ul>
 *   <li>No SecBretAnalysis → label gauge "Scan Score", source: scan_result.overall_score.</li>
 *   <li>overall_score also NULL → replace gauge with "N/A — insufficient scan data"; omit verdict badge.</li>
 * </ul>
 */
@ApplicationScoped
public class PdfReportGenerator {

    private static final DateTimeFormatter DT_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'");

    /**
     * Generate the PDF bytes for the given report job and associated data.
     *
     * @param job        the ReportJob (for IDs and metadata)
     * @param analysis   may be null — no incident analysis for this URL
     * @param scanResult may be null — no completed scan yet
     * @param review     may be null — no human review
     * @param shareToken UUID token of the auto-created share link (for footer)
     * @return raw PDF bytes
     */
    public byte[] generate(ReportJob job, SecBretAnalysis analysis,
                           ScanResult scanResult, SecurityTeamReview review,
                           String shareToken) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Document doc = new Document(PageSize.A4, 50, 50, 60, 60);
        try {
            PdfWriter writer = PdfWriter.getInstance(doc, out);
            writer.setPageEvent(new PageBreakHandler());
            doc.open();

            // ── Page 1: Score & Verdict ──────────────────────────────────────────
            addPage1(doc, job, analysis, scanResult);

            doc.newPage();

            // ── Page 2: Executive Summary & AI Reasoning ─────────────────────────
            addPage2(doc, analysis, review, job);

            doc.newPage();

            // ── Page 3: Technical Findings + Footer ──────────────────────────────
            addPage3(doc, job, scanResult, shareToken);

        } catch (Exception e) {
            throw new com.secbret.exception.ReportGenerationException("OpenPDF rendering error: " + e.getMessage(), e);
        } finally {
            if (doc.isOpen()) doc.close();
        }
        return out.toByteArray();
    }

    // =========================================================================
    // Page 1
    // =========================================================================

    private void addPage1(Document doc, ReportJob job, SecBretAnalysis analysis,
                          ScanResult scanResult) throws Exception {
        Font titleFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 22, Color.DARK_GRAY);
        Font headFont  = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 14, Color.DARK_GRAY);
        Font bodyFont  = FontFactory.getFont(FontFactory.HELVETICA, 11, Color.BLACK);
        Font smallFont = FontFactory.getFont(FontFactory.HELVETICA, 9, Color.GRAY);

        doc.add(para("SecBret — Phishing Analysis Platform", titleFont));
        doc.add(para("Security Report", headFont));
        doc.add(spacer());

        String targetUrl = job.getUrl() != null ? job.getUrl().getOriginalUrl() : "Unknown URL";
        String scanDate  = job.getCompletedAt() != null ? fmt(job.getCompletedAt()) : fmt(LocalDateTime.now());

        doc.add(labelValue("Target URL", targetUrl, headFont, bodyFont));
        doc.add(labelValue("Scan Date",  scanDate,  headFont, bodyFont));
        doc.add(spacer());

        // Score / gauge
        if (analysis != null) {
            // Primary path: use SecBretAnalysis.threat_score, label "Threat Score"
            BigDecimal score = analysis.getThreatScore();
            doc.add(scoreBlock("Threat Score", score, headFont, bodyFont));
            doc.add(spacer());

            // Verdict badge
            String verdict = job.getUrl() != null && job.getUrl().getCommunityVerdict() != null
                    ? job.getUrl().getCommunityVerdict().name()
                    : analysis.getVerdict();
            doc.add(verdictBadge(verdict, headFont));
            doc.add(spacer());

            // Summary paragraph (auto-generated from reasoning chain)
            String summary = buildSummary(analysis);
            doc.add(para(summary, bodyFont));
        } else if (scanResult != null && scanResult.getOverallScore() != null) {
            // Fallback: use scan_result.overall_score, label "Scan Score"
            doc.add(scoreBlock("Scan Score", scanResult.getOverallScore(), headFont, bodyFont));
            doc.add(spacer());
            doc.add(para("Note: No AI analysis has been run for this URL. Score is based on automated scan results only.", smallFont));
        } else {
            // Neither exists
            doc.add(para("N/A — insufficient scan data", headFont));
            doc.add(spacer());
            doc.add(para("No threat score or scan results are available for this URL.", bodyFont));
        }
    }

    // =========================================================================
    // Page 2
    // =========================================================================

    private void addPage2(Document doc, SecBretAnalysis analysis,
                          SecurityTeamReview review, ReportJob job) throws Exception {
        Font headFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 14, Color.DARK_GRAY);
        Font bodyFont = FontFactory.getFont(FontFactory.HELVETICA, 11, Color.BLACK);

        doc.add(para("Executive Summary & AI Reasoning", headFont));
        doc.add(spacer());

        if (analysis == null) {
            // §8 Note on missing SecBretAnalysis
            doc.add(para("No AI analysis has been run for this URL. The findings below are based on automated scan results only.", bodyFont));
            // ML model contribution and Security Team review notes sections are omitted per spec
        } else {
            // SecBret reasoning chain (numbered list from reasoning chain text)
            doc.add(para("SecBret Reasoning Chain:", FontFactory.getFont(FontFactory.HELVETICA_BOLD, 12, Color.DARK_GRAY)));
            doc.add(spacer());
            String reasoning = analysis.getReasoningChain();
            if (reasoning != null && !reasoning.isBlank()) {
                // Split on ". " to number factors
                String[] factors = reasoning.split("\\. ");
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < factors.length; i++) {
                    String f = factors[i].trim();
                    if (!f.isEmpty()) {
                        sb.append(i + 1).append(". ").append(f);
                        if (!f.endsWith(".")) sb.append(".");
                        sb.append("\n");
                    }
                }
                doc.add(para(sb.toString(), bodyFont));
            } else {
                doc.add(para("(no reasoning chain recorded)", bodyFont));
            }
            doc.add(spacer());

            // ML model contribution
            if (analysis.isMlConsulted()) {
                doc.add(para("ML Model Contribution:", FontFactory.getFont(FontFactory.HELVETICA_BOLD, 12, Color.DARK_GRAY)));
                String mlInfo = "ML score: " + (analysis.getMlScore() != null ? analysis.getMlScore() : "n/a");
                if (analysis.getModelVersion() != null) mlInfo += " (model: " + analysis.getModelVersion() + ")";
                doc.add(para(mlInfo, bodyFont));
                doc.add(spacer());
            }

            // Security team review notes
            if (review != null) {
                doc.add(para("Security Team Review Notes:", FontFactory.getFont(FontFactory.HELVETICA_BOLD, 12, Color.DARK_GRAY)));
                String reviewer = review.getReviewedBy() != null ? review.getReviewedBy().getUsername() : "[deleted]";
                doc.add(para("Reviewed by: " + reviewer + " | Status: " + review.getStatus()
                        + " | Verdict: " + review.getFinalVerdict(), bodyFont));
                doc.add(spacer());
            }

            // Community verdict
            String communityVerdict = job.getUrl() != null && job.getUrl().getCommunityVerdict() != null
                    ? job.getUrl().getCommunityVerdict().name()
                    : "UNKNOWN";
            doc.add(para("Community Verdict: " + communityVerdict, bodyFont));
        }
    }

    // =========================================================================
    // Page 3
    // =========================================================================

    private void addPage3(Document doc, ReportJob job,
                          ScanResult scanResult, String shareToken) throws Exception {
        Font headFont  = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 14, Color.DARK_GRAY);
        Font subFont   = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 12, Color.DARK_GRAY);
        Font bodyFont  = FontFactory.getFont(FontFactory.HELVETICA, 10, Color.BLACK);
        Font monoFont  = FontFactory.getFont(FontFactory.COURIER, 9, Color.BLACK);
        Font footFont  = FontFactory.getFont(FontFactory.HELVETICA, 8, Color.GRAY);

        doc.add(para("Technical Findings", headFont));
        doc.add(spacer());

        if (scanResult != null) {
            addFindings(doc, "Tier 1: Domain Age, SSL, HTTP Headers, DNS, WHOIS",
                    scanResult.getTier1Findings(), subFont, bodyFont, monoFont);
            addFindings(doc, "Tier 2: Forms, Scripts, External Domains, Content",
                    scanResult.getTier2Findings(), subFont, bodyFont, monoFont);
            addFindings(doc, "Tier 3: Phishing Kit, CVEs, Outdated Libraries",
                    scanResult.getTier3Findings(), subFont, bodyFont, monoFont);
        } else {
            doc.add(para("No scan findings are available for this URL.", bodyFont));
        }

        doc.add(spacer());

        // Footer
        String generatedAt = fmt(LocalDateTime.now());
        doc.add(para("Report ID: " + job.getId(), footFont));
        doc.add(para("Generated: " + generatedAt, footFont));
        if (shareToken != null) {
            doc.add(para("Share Link: /api/v1/share/" + shareToken, footFont));
        }
        String requestedBy = job.getRequestedBy() != null
                ? job.getRequestedBy().getUsername()
                : "[deleted]";
        doc.add(para("Requested by: " + requestedBy, footFont));
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private void addFindings(Document doc, String title, String jsonFindings,
                             Font subFont, Font bodyFont, Font monoFont) throws Exception {
        doc.add(para(title, subFont));
        if (jsonFindings != null && !jsonFindings.isBlank() && !jsonFindings.equals("null")) {
            // Pretty-print the JSON string with basic indentation
            doc.add(para(prettyJson(jsonFindings), monoFont));
        } else {
            doc.add(para("(no findings)", bodyFont));
        }
        doc.add(spacer());
    }

    /** Minimal pretty-printer for JSON — inserts newlines after { [ , } ]. */
    private String prettyJson(String json) {
        if (json == null) return "";
        // Basic: strip enclosing quotes if bare string, otherwise show as-is with trimming
        String s = json.trim();
        if (s.length() > 1200) s = s.substring(0, 1200) + "\n… (truncated)";
        return s;
    }

    private Paragraph scoreBlock(String label, BigDecimal score, Font headFont, Font bodyFont) throws Exception {
        String scoreStr = score != null ? String.format("%.2f", score.doubleValue()) : "N/A";
        Color color = gaugeColor(score);
        Font scoreFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 32, color);
        Paragraph p = new Paragraph();
        p.add(new Chunk(label + "\n", headFont));
        p.add(new Chunk(scoreStr + " / 1.00", scoreFont));
        return p;
    }

    private Color gaugeColor(BigDecimal score) {
        if (score == null) return Color.GRAY;
        double v = score.doubleValue();
        if (v <= 0.33) return new Color(34, 139, 34);   // green
        if (v <= 0.66) return new Color(218, 165, 32);  // yellow
        return new Color(178, 34, 34);                  // red
    }

    private Paragraph verdictBadge(String verdict, Font headFont) throws Exception {
        String label = verdict != null ? verdict.replace("_", " ") : "UNKNOWN";
        Color bg = verdictColor(verdict);
        Font f = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 13, Color.WHITE);
        // PDF has no background color on inline text; use color + bold label
        Font colored = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 13, bg);
        Paragraph p = new Paragraph();
        p.add(new Chunk("Verdict: ", headFont));
        p.add(new Chunk("[ " + label + " ]", colored));
        return p;
    }

    private Color verdictColor(String verdict) {
        if (verdict == null) return Color.GRAY;
        return switch (verdict) {
            case "VERIFIED_MALICIOUS" -> new Color(178, 34, 34);
            case "VERIFIED_BENIGN"    -> new Color(34, 139, 34);
            case "SUSPICIOUS"         -> new Color(218, 165, 32);
            default                   -> Color.DARK_GRAY;
        };
    }

    private String buildSummary(SecBretAnalysis analysis) {
        if (analysis == null) return "";
        double score = analysis.getThreatScore() != null ? analysis.getThreatScore().doubleValue() : 0.0;
        String verdict = analysis.getVerdict();
        return String.format(
                "SecBret assessed this URL with a threat score of %.2f. " +
                "The AI verdict is %s. %s" +
                "This summary is auto-generated from the reasoning chain below.",
                score, verdict,
                analysis.isMlConsulted()
                        ? "Both the rules engine and the ML model were consulted. "
                        : "Only the rules engine was consulted (ML unavailable). ");
    }

    private Paragraph labelValue(String label, String value, Font labelFont, Font valueFont) throws Exception {
        Paragraph p = new Paragraph();
        p.add(new Chunk(label + ": ", labelFont));
        p.add(new Chunk(value != null ? value : "N/A", valueFont));
        p.add(Chunk.NEWLINE);
        return p;
    }

    private Paragraph para(String text, Font font) {
        Paragraph p = new Paragraph(text != null ? text : "", font);
        p.setSpacingAfter(4f);
        return p;
    }

    private Paragraph spacer() {
        Paragraph p = new Paragraph(" ");
        p.setSpacingAfter(6f);
        return p;
    }

    private String fmt(LocalDateTime dt) {
        return dt != null ? DT_FMT.format(dt) : "";
    }

    // ── Placeholder page-event (no-op, prevents iText5/OpenPDF default behavior) ──
    private static class PageBreakHandler extends PdfPageEventHelper {
        // intentionally empty — keeps default page break behavior
    }
}
