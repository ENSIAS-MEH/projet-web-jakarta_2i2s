/**
 * Tiered scanning engines.
 * Tier 1: domain age, SSL, headers (Phase 3).
 * Tier 2: jsoup HTML parsing — forms, iframes, homoglyphs (Phase 4 Lane C).
 * Tier 3: kit detection (Phase 4 Lane C).
 */
package com.secbret.scanner;
