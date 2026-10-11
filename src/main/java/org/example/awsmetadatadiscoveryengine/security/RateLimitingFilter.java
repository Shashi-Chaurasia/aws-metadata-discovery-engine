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
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

/**
 * In-memory sliding-window rate limiter protecting API endpoints from DoS flooding.
 * Executes at @Order(2) so that IP-based rate limiting is strictly applied BEFORE
 * authentication (@Order(3)), ensuring repeated failed authentication attempts are throttled.
 *
 * NOTE: Rate limits enforced by this filter are in-memory and local PER APPLICATION INSTANCE.
 * In a clustered or multi-pod deployment, limits apply individually to each replica. For
 * cluster-wide rate limiting, an external distributed cache (e.g. Redis) or API Gateway is required.
 *
 * Employs automatic eviction of expired entries and hard capacity bounds to prevent unbounded memory growth.
 */
@Component
@Order(2)
public class RateLimitingFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RateLimitingFilter.class);
    private static final long WINDOW_MS = 60_000L;
    public static final int MAX_ENTRIES = 10_000;
    private static final int CLEANUP_THRESHOLD = 500;
    private static final String MDC_CORRELATION_ID = "discoveryId";
    private static final String HEADER_CORRELATION_ID = "X-Correlation-ID";
    private static final Pattern SAFE_CORRELATION_ID_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{1,64}$");

    private final SecurityProperties securityProperties;
    private final ObjectMapper objectMapper;
    private final Map<String, Deque<Long>> requestCounts = new ConcurrentHashMap<>();
    private final AtomicInteger requestCounter = new AtomicInteger(0);

    @org.springframework.beans.factory.annotation.Autowired
    public RateLimitingFilter(@org.springframework.beans.factory.annotation.Autowired(required = false) SecurityProperties securityProperties,
                              @org.springframework.beans.factory.annotation.Autowired(required = false) ObjectMapper objectMapper) {
        this.securityProperties = securityProperties;
        this.objectMapper = objectMapper != null ? objectMapper : new ObjectMapper();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();
        String correlationId = resolveCorrelationId(request);
        response.setHeader(HEADER_CORRELATION_ID, correlationId);
        MDC.put(MDC_CORRELATION_ID, correlationId);

        try {
            // Apply IP-based rate limiting before authentication
            if (path.startsWith("/api/") && securityProperties != null && securityProperties.getRateLimit().isEnabled()) {
                String clientIp = resolveClientIp(request);
                int maxAllowed = securityProperties.getRateLimit().getRequestsPerMinute();

                if (isRateLimited("ip:" + clientIp, maxAllowed)) {
                    log.warn("[correlationId={}] Rate limit exceeded for client IP: {}", correlationId, clientIp);
                    sendRateLimitResponse(request, response, correlationId);
                    return;
                }
            }

            filterChain.doFilter(request, response);
        } finally {
            MDC.remove(MDC_CORRELATION_ID);
        }
    }

    /**
     * Determines whether a client has exceeded their rate limit.
     * Uses atomic computation to maintain correctness under concurrent requests
     * and periodically evicts stale client entries to prevent unbounded memory growth.
     */
    public boolean isRateLimited(String clientKey, int maxAllowed) {
        long now = System.currentTimeMillis();
        long windowStart = now - WINDOW_MS;

        // Bounded memory maintenance: clean up inactive entries periodically or when threshold is reached
        if (requestCounter.incrementAndGet() % 100 == 0 || requestCounts.size() > CLEANUP_THRESHOLD) {
            cleanupExpiredEntries(windowStart);
        }

        AtomicBoolean rateLimited = new AtomicBoolean(false);

        requestCounts.compute(clientKey, (k, timestamps) -> {
            if (timestamps == null) {
                // If capacity limit is reached, evict stale or oldest entry before adding new client
                if (requestCounts.size() >= MAX_ENTRIES) {
                    evictStaleOrOldestEntry(windowStart);
                }
                timestamps = new ArrayDeque<>();
            }

            // Evict expired timestamps within the sliding window
            while (!timestamps.isEmpty() && timestamps.peekFirst() < windowStart) {
                timestamps.pollFirst();
            }

            if (timestamps.size() >= maxAllowed) {
                rateLimited.set(true);
                return timestamps;
            }

            timestamps.addLast(now);
            return timestamps;
        });

        return rateLimited.get();
    }

    /**
     * Evicts client entries where all timestamps have expired beyond the sliding window.
     */
    public void cleanupExpiredEntries(long windowStart) {
        requestCounts.entrySet().removeIf(entry -> {
            Deque<Long> deque = entry.getValue();
            synchronized (deque) {
                while (!deque.isEmpty() && deque.peekFirst() < windowStart) {
                    deque.pollFirst();
                }
                return deque.isEmpty();
            }
        });
    }

    private synchronized void evictStaleOrOldestEntry(long windowStart) {
        cleanupExpiredEntries(windowStart);
        if (requestCounts.size() >= MAX_ENTRIES) {
            Iterator<Map.Entry<String, Deque<Long>>> it = requestCounts.entrySet().iterator();
            if (it.hasNext()) {
                it.next();
                it.remove();
            }
        }
    }

    /**
     * Visible for testing: Returns current number of client entries in memory map.
     */
    int getActiveEntryCount() {
        return requestCounts.size();
    }

    /**
     * Visible for testing: Records a request timestamp for testing bounded expiration cleanup.
     */
    void recordRequestForTesting(String clientKey, long timestamp) {
        requestCounts.compute(clientKey, (k, timestamps) -> {
            if (timestamps == null) {
                timestamps = new ArrayDeque<>();
            }
            timestamps.addLast(timestamp);
            return timestamps;
        });
    }

    public String resolveClientIp(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();
        if (remoteAddr == null || remoteAddr.isBlank()) {
            remoteAddr = "127.0.0.1";
        } else {
            remoteAddr = remoteAddr.trim();
        }

        // Only trust X-Forwarded-For if explicitly configured AND request originates from a trusted proxy
        if (securityProperties != null && securityProperties.getRateLimit().isTrustForwardedFor()) {
            if (isTrustedProxy(remoteAddr)) {
                String xForwardedFor = request.getHeader("X-Forwarded-For");
                if (xForwardedFor != null && !xForwardedFor.isBlank()) {
                    String[] parts = xForwardedFor.split(",");
                    if (parts.length > 0 && !parts[0].trim().isBlank()) {
                        return parts[0].trim();
                    }
                }
            }
        }

        return remoteAddr;
    }

    public boolean isTrustedProxy(String remoteAddr) {
        if (remoteAddr == null || remoteAddr.isBlank() || securityProperties == null) {
            return false;
        }
        java.util.List<String> trusted = securityProperties.getRateLimit().getTrustedProxies();
        if (trusted == null || trusted.isEmpty()) {
            return false;
        }
        String cleanRemote = remoteAddr.trim();
        for (String proxy : trusted) {
            if (proxy != null && proxy.trim().equalsIgnoreCase(cleanRemote)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Produces a non-reversible SHA-256 fingerprint of the key for internal rate-limit map lookup.
     * Never stores or logs raw credentials.
     */
    public static String hashKey(String input) {
        if (input == null || input.isBlank()) {
            return "opaque";
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.trim().getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.substring(0, 16);
        } catch (Exception e) {
            return "opaque";
        }
    }

    public void sendRateLimitResponse(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String correlationId = response.getHeader(HEADER_CORRELATION_ID);
        if (correlationId == null) {
            correlationId = resolveCorrelationId(request);
        }
        sendRateLimitResponse(request, response, correlationId);
    }

    public void sendRateLimitResponse(HttpServletRequest request, HttpServletResponse response, String correlationId)
            throws IOException {
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());

        ErrorResponse errorResponse = ErrorResponse.of(
                HttpStatus.TOO_MANY_REQUESTS.value(),
                "Too Many Requests",
                "API rate limit exceeded. Please retry later.",
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

    public int getTrackedClientCount() {
        return requestCounts.size();
    }

    /**
     * Resets rate limit cache (useful for tests).
     */
    public void reset() {
        requestCounts.clear();
        requestCounter.set(0);
    }
}
