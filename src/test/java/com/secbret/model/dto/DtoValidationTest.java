package com.secbret.model.dto;

import com.secbret.model.enums.UserRole;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Bean Validation unit tests for all request DTOs (Phase 5, Part II §9 / openapi.yaml).
 *
 * <p>Uses the default Jakarta Bean Validation provider (Hibernate Validator on the classpath).
 */
class DtoValidationTest {

    private static Validator validator;

    @BeforeAll
    static void buildValidator() {
        validator = Validation.buildDefaultValidatorFactory().getValidator();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ScanRequest (already annotated in Phase 3 — regression guard)
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("ScanRequest")
    class ScanRequestTests {

        @Test
        @DisplayName("valid request passes")
        void valid() {
            assertThat(validator.validate(new ScanRequest("https://example.com", "QUICK"))).isEmpty();
        }

        @Test
        @DisplayName("blank url → violation on 'url'")
        void blankUrl() {
            Set<ConstraintViolation<ScanRequest>> v = validator.validate(new ScanRequest("", null));
            assertThat(fieldNames(v)).contains("url");
        }

        @Test
        @DisplayName("url exceeding 2048 chars → violation on 'url'")
        void urlTooLong() {
            String longUrl = "https://example.com/" + "a".repeat(2040);
            Set<ConstraintViolation<ScanRequest>> v = validator.validate(new ScanRequest(longUrl, null));
            assertThat(fieldNames(v)).contains("url");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // IncidentRequest (Phase 5 — newly annotated)
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("IncidentRequest")
    class IncidentRequestTests {

        @Test
        @DisplayName("valid request passes")
        void valid() {
            IncidentRequest r = new IncidentRequest();
            r.setUrl("https://phishing.example.com");
            r.setEvidenceDescription("This site impersonates a bank login page.");
            assertThat(validator.validate(r)).isEmpty();
        }

        @Test
        @DisplayName("blank url → violation on 'url'")
        void blankUrl() {
            IncidentRequest r = new IncidentRequest();
            r.setUrl("   ");
            r.setEvidenceDescription("This site impersonates a bank login page.");
            assertThat(fieldNames(validator.validate(r))).contains("url");
        }

        @Test
        @DisplayName("missing evidenceDescription → violation on 'evidenceDescription'")
        void missingEvidence() {
            IncidentRequest r = new IncidentRequest();
            r.setUrl("https://phishing.example.com");
            // no description
            assertThat(fieldNames(validator.validate(r))).contains("evidenceDescription");
        }

        @Test
        @DisplayName("evidenceDescription too short (< 10) → violation on 'evidenceDescription'")
        void evidenceTooShort() {
            IncidentRequest r = new IncidentRequest();
            r.setUrl("https://phishing.example.com");
            r.setEvidenceDescription("short");
            assertThat(fieldNames(validator.validate(r))).contains("evidenceDescription");
        }

        @Test
        @DisplayName("evidenceDescription too long (> 2000) → violation on 'evidenceDescription'")
        void evidenceTooLong() {
            IncidentRequest r = new IncidentRequest();
            r.setUrl("https://phishing.example.com");
            r.setEvidenceDescription("x".repeat(2001));
            assertThat(fieldNames(validator.validate(r))).contains("evidenceDescription");
        }

        @Test
        @DisplayName("more than 5 evidenceUrls → violation on 'evidenceUrls'")
        void tooManyEvidenceUrls() {
            IncidentRequest r = new IncidentRequest();
            r.setUrl("https://phishing.example.com");
            r.setEvidenceDescription("Valid description here, ten chars.");
            r.setEvidenceUrls(List.of("a", "b", "c", "d", "e", "f")); // 6 items
            assertThat(fieldNames(validator.validate(r))).contains("evidenceUrls");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ChangeRoleRequest
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("ChangeRoleRequest")
    class ChangeRoleRequestTests {

        @Test
        @DisplayName("null role → violation on 'role'")
        void nullRole() {
            ChangeRoleRequest r = new ChangeRoleRequest();
            assertThat(fieldNames(validator.validate(r))).contains("role");
        }

        @Test
        @DisplayName("valid role passes")
        void valid() {
            ChangeRoleRequest r = new ChangeRoleRequest();
            r.setRole(UserRole.ANALYST);
            assertThat(validator.validate(r)).isEmpty();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ChangeStatusRequest
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("ChangeStatusRequest")
    class ChangeStatusRequestTests {

        @Test
        @DisplayName("null enabled → violation on 'enabled'")
        void nullEnabled() {
            ChangeStatusRequest r = new ChangeStatusRequest();
            assertThat(fieldNames(validator.validate(r))).contains("enabled");
        }

        @Test
        @DisplayName("valid enabled passes")
        void valid() {
            ChangeStatusRequest r = new ChangeStatusRequest();
            r.setEnabled(true);
            assertThat(validator.validate(r)).isEmpty();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GdprDeleteRequest
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("GdprDeleteRequest")
    class GdprDeleteRequestTests {

        @Test
        @DisplayName("blank currentPassword → violation on 'currentPassword'")
        void blankPassword() {
            GdprDeleteRequest r = new GdprDeleteRequest();
            r.setCurrentPassword("   ");
            assertThat(fieldNames(validator.validate(r))).contains("currentPassword");
        }

        @Test
        @DisplayName("valid currentPassword passes")
        void valid() {
            GdprDeleteRequest r = new GdprDeleteRequest();
            r.setCurrentPassword("somePassw0rd!");
            assertThat(validator.validate(r)).isEmpty();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ShareLinkRequest
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("ShareLinkRequest")
    class ShareLinkRequestTests {

        @Test
        @DisplayName("null reportJobId → violation on 'reportJobId'")
        void nullJobId() {
            ShareLinkRequest r = new ShareLinkRequest();
            assertThat(fieldNames(validator.validate(r))).contains("reportJobId");
        }

        @Test
        @DisplayName("expiryDays=0 → violation on 'expiryDays'")
        void expiryDaysTooLow() {
            ShareLinkRequest r = new ShareLinkRequest();
            r.setReportJobId(UUID.randomUUID());
            r.setExpiryDays(0);
            assertThat(fieldNames(validator.validate(r))).contains("expiryDays");
        }

        @Test
        @DisplayName("expiryDays=366 → violation on 'expiryDays'")
        void expiryDaysTooHigh() {
            ShareLinkRequest r = new ShareLinkRequest();
            r.setReportJobId(UUID.randomUUID());
            r.setExpiryDays(366);
            assertThat(fieldNames(validator.validate(r))).contains("expiryDays");
        }

        @Test
        @DisplayName("valid request passes")
        void valid() {
            ShareLinkRequest r = new ShareLinkRequest();
            r.setReportJobId(UUID.randomUUID());
            r.setExpiryDays(30);
            assertThat(validator.validate(r)).isEmpty();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ReviewRequest
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("ReviewRequest")
    class ReviewRequestTests {

        @Test
        @DisplayName("blank action → violation on 'action'")
        void blankAction() {
            ReviewRequest r = new ReviewRequest();
            r.setAction("");
            assertThat(fieldNames(validator.validate(r))).contains("action");
        }

        @Test
        @DisplayName("reviewerNotes exceeding 5000 chars → violation")
        void reviewerNotesTooLong() {
            ReviewRequest r = new ReviewRequest();
            r.setAction("APPROVE");
            r.setReviewerNotes("x".repeat(5001));
            assertThat(fieldNames(validator.validate(r))).contains("reviewerNotes");
        }

        @Test
        @DisplayName("valid request passes")
        void valid() {
            ReviewRequest r = new ReviewRequest();
            r.setAction("APPROVE");
            assertThat(validator.validate(r)).isEmpty();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helper
    // ─────────────────────────────────────────────────────────────────────────

    private static <T> Set<String> fieldNames(Set<ConstraintViolation<T>> violations) {
        return violations.stream()
                .map(v -> {
                    String path = v.getPropertyPath().toString();
                    int dot = path.lastIndexOf('.');
                    return dot >= 0 ? path.substring(dot + 1) : path;
                })
                .collect(Collectors.toSet());
    }
}
