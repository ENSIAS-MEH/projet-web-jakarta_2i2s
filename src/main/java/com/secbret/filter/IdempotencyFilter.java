package com.secbret.filter;

import com.secbret.model.entity.IdempotencyKey;
import com.secbret.model.entity.SecBretUser;
import com.secbret.repository.IdempotencyKeyRepository;
import com.secbret.repository.UserRepository;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;
import jakarta.ws.rs.ext.Provider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * JAX-RS filter implementing Idempotency-Key semantics (Part III §Idempotency-Key).
 *
 * <p>Applies only to the three endpoints that support idempotency keys:
 * POST /scan, POST /incident, POST /report-jobs. Other endpoints pass through.
 *
 * <p>Behaviour when Idempotency-Key header is present:
 * <ul>
 *   <li>No existing record → create in-flight entry, process normally, capture response</li>
 *   <li>Same key + same body + complete → replay stored response</li>
 *   <li>Same key + same body + in-flight → 409 with Retry-After: 5</li>
 *   <li>Same key + different body → 409 Conflict</li>
 * </ul>
 */
@Provider
public class IdempotencyFilter implements ContainerRequestFilter, ContainerResponseFilter {

    private static final Logger log = LoggerFactory.getLogger(IdempotencyFilter.class);
    private static final String IDEM_KEY_HEADER = "Idempotency-Key";
    private static final String ATTR_KEY_ID    = "secbret.idem.keyId";
    private static final String ATTR_BODY_HASH = "secbret.idem.bodyHash";

    /** Endpoints (path templates) that support idempotency keys. */
    private static final Set<String> IDEMPOTENT_PATHS = Set.of(
            "/api/v1/scan",
            "/api/v1/incident",
            "/api/v1/report-jobs"
    );

    @Inject
    IdempotencyKeyRepository idempotencyKeyRepository;

    @Inject
    UserRepository userRepository;

    @Context
    ResourceInfo resourceInfo;

    @Override
    public void filter(ContainerRequestContext req) throws IOException {
        String idemKey = req.getHeaderString(IDEM_KEY_HEADER);
        if (idemKey == null || idemKey.isBlank()) {
            return; // key omitted → no idempotency protection
        }

        String path = req.getUriInfo().getAbsolutePath().getPath();
        String endpoint = resolveEndpoint(path);
        if (endpoint == null) {
            return; // path not in the idempotent set
        }
        if (!"POST".equalsIgnoreCase(req.getMethod())) {
            return; // only POST is covered
        }

        // Identify the caller
        SecurityContext sec = req.getSecurityContext();
        if (sec == null || sec.getUserPrincipal() == null) {
            return; // unauthenticated — let the auth filter handle it
        }
        String username = sec.getUserPrincipal().getName();
        Optional<SecBretUser> maybeUser = userRepository.findByUsername(username);
        if (maybeUser.isEmpty()) {
            return;
        }
        UUID userId = maybeUser.get().getId();

        // Buffer the request body to hash it (allows re-reading downstream)
        byte[] body = req.getEntityStream().readAllBytes();
        req.setEntityStream(new ByteArrayInputStream(body));
        String bodyHash = sha256Hex(body);

        Optional<IdempotencyKey> existing =
                idempotencyKeyRepository.findByUserEndpointKey(userId, endpoint, idemKey);

        if (existing.isPresent()) {
            IdempotencyKey rec = existing.get();
            if (!rec.getRequestHash().equals(bodyHash)) {
                // Same key, different body → 409
                req.abortWith(Response.status(409)
                        .type(MediaType.APPLICATION_JSON)
                        .entity("{\"error\":\"Idempotency key already used with a different request body\",\"status\":409}")
                        .build());
                return;
            }
            if (rec.isInFlight()) {
                // In-flight → 409 with Retry-After
                req.abortWith(Response.status(409)
                        .header("Retry-After", "5")
                        .type(MediaType.APPLICATION_JSON)
                        .entity("{\"error\":\"Request with this Idempotency-Key is still being processed\",\"status\":409}")
                        .build());
                return;
            }
            // Complete match → replay
            req.abortWith(Response.status(rec.getResponseStatus())
                    .type(MediaType.APPLICATION_JSON)
                    .entity(rec.getResponseBody())
                    .build());
            return;
        }

        // New key — create in-flight record
        IdempotencyKey rec = new IdempotencyKey();
        rec.setUser(maybeUser.get());
        rec.setIdemKey(idemKey);
        rec.setEndpoint(endpoint);
        rec.setRequestHash(bodyHash);
        rec.setExpiresAt(LocalDateTime.now().plusHours(24));
        IdempotencyKey saved = idempotencyKeyRepository.persist(rec);

        // Pass key ID and body hash to the response filter via request attributes
        req.setProperty(ATTR_KEY_ID, saved.getId());
        req.setProperty(ATTR_BODY_HASH, bodyHash);
    }

    @Override
    public void filter(ContainerRequestContext req, ContainerResponseContext resp) {
        UUID keyId = (UUID) req.getProperty(ATTR_KEY_ID);
        if (keyId == null) {
            return; // this request didn't create an in-flight record
        }

        int status = resp.getStatus();
        String body = "";
        if (resp.hasEntity()) {
            // Capture the entity as string; it may already be serialized
            Object entity = resp.getEntity();
            body = entity != null ? entity.toString() : "";
        }

        idempotencyKeyRepository.captureResponse(keyId, status, body);
        log.debug("Captured idempotency response keyId={} status={}", keyId, status);
    }

    /** Maps an incoming path to its path-template endpoint label. */
    private static String resolveEndpoint(String path) {
        if (path == null) return null;
        // Exact match for /api/v1/scan and /api/v1/incident
        if ("/api/v1/scan".equals(path))     return "POST /scan";
        if ("/api/v1/incident".equals(path)) return "POST /incident";
        // /api/v1/report-jobs/{urlId} — match prefix
        if (path.startsWith("/api/v1/report-jobs")) return "POST /report-jobs";
        return null;
    }

    private static String sha256Hex(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input);
            StringBuilder sb = new StringBuilder(64);
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
