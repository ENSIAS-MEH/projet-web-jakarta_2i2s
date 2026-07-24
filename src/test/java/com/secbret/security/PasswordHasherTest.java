package com.secbret.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PasswordHasherTest {

    private final PasswordHasher hasher = new PasswordHasher(12);

    @Test
    @DisplayName("hash then verify round-trips for the correct password")
    void hash_thenVerify_correctPassword_returnsTrue() {
        String raw = "correct horse battery staple";

        String stored = hasher.hash(raw);

        assertThat(stored).isNotBlank().isNotEqualTo(raw);
        assertThat(hasher.verify(raw, stored)).isTrue();
    }

    @Test
    @DisplayName("verify returns false for a wrong password")
    void verify_wrongPassword_returnsFalse() {
        String stored = hasher.hash("the-right-password-1");

        assertThat(hasher.verify("the-wrong-password-1", stored)).isFalse();
    }

    @Test
    @DisplayName("uses the configured cost factor (12) in the emitted hash")
    void hash_encodesConfiguredCost() {
        // BCrypt format: $2a$<cost>$<salt+hash>
        String stored = hasher.hash("some-password-1234");

        assertThat(stored).startsWith("$2a$12$");
        assertThat(hasher.cost()).isEqualTo(12);
    }

    @Test
    @DisplayName("verify returns false for null or blank stored hash instead of throwing")
    void verify_nullOrBlankStored_returnsFalse() {
        assertThat(hasher.verify("anything", null)).isFalse();
        assertThat(hasher.verify("anything", "")).isFalse();
        assertThat(hasher.verify("anything", "not-a-bcrypt-hash")).isFalse();
    }

    @Test
    @DisplayName("two hashes of the same password differ (random salt)")
    void hash_sameInput_differentSalts() {
        String a = hasher.hash("repeatme-repeatme");
        String b = hasher.hash("repeatme-repeatme");

        assertThat(a).isNotEqualTo(b);
        assertThat(hasher.verify("repeatme-repeatme", a)).isTrue();
        assertThat(hasher.verify("repeatme-repeatme", b)).isTrue();
    }
}
