package com.secbret.ai.ml;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Unit tests for {@link MlScoreRequest} validation and factory. */
@DisplayName("MlScoreRequest")
class MlScoreRequestTest {

    @Test
    @DisplayName("valid full construction")
    void validFull() {
        MlScoreRequest r = new MlScoreRequest("https://example.com", 0.5, "{}", null, null);
        assertThat(r.url()).isEqualTo("https://example.com");
        assertThat(r.ruleScore()).isEqualTo(0.5);
        assertThat(r.tier1FindingsJson()).isEqualTo("{}");
    }

    @Test
    @DisplayName("ofRulesOnly factory sets tier findings to null")
    void ofRulesOnly() {
        MlScoreRequest r = MlScoreRequest.ofRulesOnly("https://example.com", 0.3);
        assertThat(r.tier1FindingsJson()).isNull();
        assertThat(r.tier2FindingsJson()).isNull();
        assertThat(r.tier3FindingsJson()).isNull();
    }

    @Test
    @DisplayName("rejects null url")
    void rejectsNullUrl() {
        assertThatThrownBy(() -> MlScoreRequest.ofRulesOnly(null, 0.5))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("rejects blank url")
    void rejectsBlankUrl() {
        assertThatThrownBy(() -> MlScoreRequest.ofRulesOnly("   ", 0.5))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("rejects ruleScore < 0")
    void rejectsNegativeScore() {
        assertThatThrownBy(() -> MlScoreRequest.ofRulesOnly("https://example.com", -0.1))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("rejects ruleScore > 1")
    void rejectsScoreAboveOne() {
        assertThatThrownBy(() -> MlScoreRequest.ofRulesOnly("https://example.com", 1.01))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("accepts boundary scores 0.0 and 1.0")
    void acceptsBoundaryScores() {
        assertThat(MlScoreRequest.ofRulesOnly("https://example.com", 0.0).ruleScore()).isEqualTo(0.0);
        assertThat(MlScoreRequest.ofRulesOnly("https://example.com", 1.0).ruleScore()).isEqualTo(1.0);
    }
}
