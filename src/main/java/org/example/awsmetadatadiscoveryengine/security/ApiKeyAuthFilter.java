package org.example.awsmetadatadiscoveryengine.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.awsmetadatadiscoveryengine.model.ErrorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Filter enforcing API Key authentication on protected REST endpoints.
 * Executes at @Order(3) (after RateLimitingFilter at @Order(2)) so that IP-based
 * rate limiting precedes authentication.
 * Employs constant-time string comparison to safeguard against timing side-channel attacks,
 * never logs credentials, and applies optional per-key rate limiting to authenticated requests.
 */
@Component
@Order(3)
public class ApiKeyAuthFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(ApiKeyAuthFilter.class);
    private static final String MDC_CORRELATION_ID = "discoveryId";
    private static final String HEADER_CORRELATION_ID = "X-Correlation-ID";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final Pattern SAFE_CORRELATION_ID_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{1,64}$");

    private final SecurityProperties securityProperties;
    private final ObjectMapper objectMapper;
    private final RateLimitingFilter rateLimitingFilter;

    public ApiKeyAuthFilter(SecurityProperties securityProperties, ObjectMapper objectMapper) {
        this(securityProperties, objectMapper, null);
    }

    @org.springframework.beans.factory.annotation.Autowired
    public ApiKeyAuthFilter(@org.springframework.beans.factory.annotation.Autowired(required = false) SecurityProperties securityProperties,
                            @org.springframework.beans.factory.annotation.Autowired(required = false) ObjectMapper objectMapper,
                            @org.springframework.beans.factory.annotation.Autowired(required = false) RateLimitingFilter rateLimitingFilter) {
        this.securityProperties = securityProperties;
        this.objectMapper = objectMapper != null ? objectMapper : new ObjectMapper();
        this.rateLimitingFilter = rateLimitingFilter;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();
        String correlationId = resolveCorrelationId(request);
        response.setHeader(HEADER_CORRELATION_ID, correlationId);
        MDC.put(MDC_CORRELATION_ID, correlationId);

        try {
            // Check if endpoint requires API Key authentication (enabled by default)
            if (isProtectedPath(path) && isAuthEnabled()) {
                String providedKey = extractApiKey(request);

                if (providedKey == null || !isValidApiKey(providedKey, correlationId, path)) {
                    log.warn("[correlationId={}] Unauthorized request to {}: missing or invalid API key", correlationId, path);
                    sendUnauthorizedResponse(request, response, correlationId);
                    return;
                }

                // Authenticated! Apply optional per-key rate limit using non-reversible key identifier
                if (rateLimitingFilter != null && securityProperties != null && securityProperties.getRateLimit().isEnabled()) {
                    String keyHash = RateLimitingFilter.hashKey(providedKey);
                    int maxAllowed = securityProperties.getRateLimit().getRequestsPerMinute();

                    if (rateLimitingFilter.isRateLimited("key-hash:" + keyHash, maxAllowed)) {
                        log.warn("[correlationId={}] Rate limit exceeded for authenticated client", correlationId);
                        rateLimitingFilter.sendRateLimitResponse(request, response, correlationId);
                        return;
                    }
                }
            }

            filterChain.doFilter(request, response);
        } finally {
            MDC.remove(MDC_CORRELATION_ID);
        }
    }

    private boolean isAuthEnabled() {
        // Authentication is enabled by default unless explicitly disabled in configuration
        return securityProperties == null || securityProperties.getApiKey().isEnabled();
    }

    private boolean isProtectedPath(String path) {
        if (path == null) {
            return false;
        }
        // Protect all /api/** endpoints; allow actuator health/info public monitoring
        return path.startsWith("/api/");
    }

    private String extractApiKey(HttpServletRequest request) {
        String headerName = securityProperties != null ? securityProperties.getApiKey().getHeaderName() : "X-API-Key";
        String key = request.getHeader(headerName);
        if (key != null && !key.isBlank()) {
            return key.trim();
        }

        // Fallback to Authorization: Bearer <key>
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
            return authHeader.substring(BEARER_PREFIX.length()).trim();
        }

        return null;
    }

    private boolean isValidApiKey(String providedKey, String correlationId, String path) {
        if (providedKey == null || providedKey.isBlank()) {
            return false;
        }

        String expectedKey = securityProperties != null ? securityProperties.getApiKey().getSecret() : null;
        if (expectedKey == null || expectedKey.isBlank()) {
            // Secret is unconfigured or blank: fail safely. Never allow protected requests.
            log.error("[correlationId={}] Rejecting request to {}: API authentication is enabled, but API key secret is unconfigured/empty.",
                    correlationId, path);
            return false;
        }

        byte[] providedBytes = providedKey.getBytes(StandardCharsets.UTF_8);
        byte[] expectedBytes = expectedKey.getBytes(StandardCharsets.UTF_8);

        // Constant-time comparison to prevent timing attacks
        return MessageDigest.isEqual(providedBytes, expectedBytes);
    }

    private void sendUnauthorizedResponse(HttpServletRequest request, HttpServletResponse response, String correlationId)
            throws IOException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());

        String headerName = securityProperties != null ? securityProperties.getApiKey().getHeaderName() : "X-API-Key";
        ErrorResponse errorResponse = ErrorResponse.of(
                HttpStatus.UNAUTHORIZED.value(),
                "Unauthorized",
                "Missing or invalid API key. Provide a valid '" + headerName
                        + "' or 'Authorization: Bearer <key>' header.",
                request.getRequestURI(),
                correlationId
        );

        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }

    private String resolveCorrelationId(HttpServletRequest request) {
        String incomingId = request.getHeader(HEADER_CORRELATION_ID);
        if (incomingId != null && SAFE_CORRELATION_ID_PATTERN.matcher(incomingId.trim()).matches()) {
            return incomingId.trim();
        }
        return UUID.randomUUID().toString();
    }
}
