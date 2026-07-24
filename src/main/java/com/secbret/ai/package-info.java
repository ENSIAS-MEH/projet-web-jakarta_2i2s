/**
 * SecBret AI scoring layer (Part II §7).
 *
 * <p>Task 11 (this package's current scope):
 * <ul>
 *   <li>{@link com.secbret.ai.RuleInput} / {@link com.secbret.ai.RuleWeights} /
 *       {@link com.secbret.ai.RuleResult} — the eight §7 indicators, their
 *       relative weights (Σ = 1.30), and the scoring outcome.
 *   <li>{@link com.secbret.ai.RulesEngine} — two-stage evaluation: Stage 1
 *       dispositive override ({@code knownPhishingKit} → 1.0), else Stage 2
 *       normalized weighted average (caps at 0.827).
 *   <li>{@link com.secbret.ai.ThreatAnalyzer} — blends ruleScore (0.4) and
 *       mlScore (0.6) with compile-time constants; the ML-consultation band is
 *       the open interval derived from {@code AUTO_APPROVE_LOW/HIGH}; rules-only
 *       fallback when {@link com.secbret.ai.MlConsultation} is unavailable.
 *   <li>{@link com.secbret.ai.AutoActionVerdict} /
 *       {@link com.secbret.ai.TentativeVerdict} — the two derived verdicts.
 * </ul>
 *
 * <p>The gRPC ML client + circuit breaker (Task 12 / Lane C) plug into
 * {@link com.secbret.ai.MlConsultation}; they are out of Task 11 scope.
 */
package com.secbret.ai;
