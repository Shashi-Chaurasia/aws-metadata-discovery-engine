package org.example.awsmetadatadiscoveryengine.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.awsmetadatadiscoveryengine.model.ErrorResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class RateLimitingFilterTest {

    private SecurityProperties properties;
    private ObjectMapper objectMapper;
    private RateLimitingFilter filter;
    private FilterChain chain;

    @BeforeEach
    void setUp() {
        properties = new SecurityProperties();
        properties.getRateLimit().setEnabled(true);
        properties.getRateLimit().setRequestsPerMinute(3);
        properties.getApiKey().setEnabled(true);
        properties.getApiKey().setSecret("valid-test-key-12345");

        objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());

        filter = new RateLimitingFilter(properties, objectMapper);
        chain = mock(FilterChain.class);
    }

    @Test
    @DisplayName("Allows requests within configured rate limit")
    void shouldAllowRequestsUnderLimit() throws ServletException, IOException {
        for (int i = 0; i < 3; i++) {
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/discover");
            request.setRemoteAddr("192.168.1.100");
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilter(request, response, chain);
            assertThat(response.getStatus()).isEqualTo(200);
        }

        verify(chain, times(3)).doFilter(any(), any());
    }

    @Test
    @DisplayName("Rejects requests exceeding rate limit with 429 Too Many Requests")
    void shouldRejectRequestsOverLimitWith429() throws ServletException, IOException {
        String clientIp = "192.168.1.200";

        // Consume all 3 permits
        for (int i = 0; i < 3; i++) {
            MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/discover");
            req.setRemoteAddr(clientIp);
            MockHttpServletResponse res = new MockHttpServletResponse();
            filter.doFilter(req, res, chain);
        }

        // 4th request exceeds limit
        MockHttpServletRequest excessiveReq = new MockHttpServletRequest("POST", "/api/discover");
        excessiveReq.setRemoteAddr(clientIp);
        MockHttpServletResponse excessiveRes = new MockHttpServletResponse();

        filter.doFilter(excessiveReq, excessiveRes, chain);

        assertThat(excessiveRes.getStatus()).isEqualTo(429);
        ErrorResponse errorResponse = objectMapper.readValue(excessiveRes.getContentAsString(), ErrorResponse.class);
        assertThat(errorResponse.status()).isEqualTo(429);
        assertThat(errorResponse.error()).isEqualTo("Too Many Requests");
        assertThat(errorResponse.message()).contains("rate limit exceeded");
        assertThat(excessiveRes.getHeader("X-Correlation-ID")).isNotBlank();
    }

    @Test
    @DisplayName("Allows requests when rate limiting is disabled")
    void shouldAllowWhenRateLimitingDisabled() throws ServletException, IOException {
        properties.getRateLimit().setEnabled(false);

        for (int i = 0; i < 10; i++) {
            MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/discover");
            req.setRemoteAddr("10.0.0.1");
            MockHttpServletResponse res = new MockHttpServletResponse();
            filter.doFilter(req, res, chain);
            assertThat(res.getStatus()).isEqualTo(200);
        }
    }

    @Test
    @DisplayName("Does not trust X-Forwarded-For header by default, binding to remoteAddr")
    void shouldNotTrustForwardedForByDefault() throws ServletException, IOException {
        String spoofedClientIp = "203.0.113.195";
        String realPeerIp = "192.168.1.50";

        // Consume 3 permits from realPeerIp while sending different spoofed X-Forwarded-For headers
        for (int i = 0; i < 3; i++) {
            MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/discover");
            req.setRemoteAddr(realPeerIp);
            req.addHeader("X-Forwarded-For", "spoofed-" + i + ".example.com");
            MockHttpServletResponse res = new MockHttpServletResponse();
            filter.doFilter(req, res, chain);
            assertThat(res.getStatus()).isEqualTo(200);
        }

        // 4th request from same realPeerIp should be rate limited even with another spoofed header
        MockHttpServletRequest excessiveReq = new MockHttpServletRequest("POST", "/api/discover");
        excessiveReq.setRemoteAddr(realPeerIp);
        excessiveReq.addHeader("X-Forwarded-For", spoofedClientIp);
        MockHttpServletResponse excessiveRes = new MockHttpServletResponse();

        filter.doFilter(excessiveReq, excessiveRes, chain);
        assertThat(excessiveRes.getStatus()).isEqualTo(429);
    }

    @Test
    @DisplayName("Trusts X-Forwarded-For only when trustForwardedFor is enabled AND peer is a trusted proxy")
    void shouldTrustForwardedForWhenEnabledAndOriginatesFromTrustedProxy() throws ServletException, IOException {
        properties.getRateLimit().setTrustForwardedFor(true);
        properties.getRateLimit().setTrustedProxies(java.util.List.of("10.0.0.1")); // internal load balancer IP

        String clientA = "198.51.100.1";
        String clientB = "198.51.100.2";

        // 3 requests from Client A via trusted proxy
        for (int i = 0; i < 3; i++) {
            MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/discover");
            req.setRemoteAddr("10.0.0.1");
            req.addHeader("X-Forwarded-For", clientA);
            MockHttpServletResponse res = new MockHttpServletResponse();
            filter.doFilter(req, res, chain);
            assertThat(res.getStatus()).isEqualTo(200);
        }

        // 4th request from Client A via trusted proxy is rate-limited
        MockHttpServletRequest excessiveReqA = new MockHttpServletRequest("POST", "/api/discover");
        excessiveReqA.setRemoteAddr("10.0.0.1");
        excessiveReqA.addHeader("X-Forwarded-For", clientA);
        MockHttpServletResponse resA = new MockHttpServletResponse();
        filter.doFilter(excessiveReqA, resA, chain);
        assertThat(resA.getStatus()).isEqualTo(429);

        // Meanwhile, Client B via the same trusted proxy is NOT rate-limited
        MockHttpServletRequest reqB = new MockHttpServletRequest("POST", "/api/discover");
        reqB.setRemoteAddr("10.0.0.1");
        reqB.addHeader("X-Forwarded-For", clientB);
        MockHttpServletResponse resB = new MockHttpServletResponse();
        filter.doFilter(reqB, resB, chain);
        assertThat(resB.getStatus()).isEqualTo(200);
    }

    @Test
    @DisplayName("Never logs raw API keys or bearer tokens when IP rate limit is exceeded")
    void shouldNeverLogRawApiKey() throws ServletException, IOException {
        ch.qos.logback.classic.Logger filterLogger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(RateLimitingFilter.class);
        ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent> appender = new ch.qos.logback.core.read.ListAppender<>();
        appender.start();
        filterLogger.addAppender(appender);

        String secretKey = "super-secret-key-that-must-never-be-logged";

        try {
            // Exceed limit using this client IP and API key
            for (int i = 0; i < 4; i++) {
                MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/discover");
                req.setRemoteAddr("192.168.1.88");
                req.addHeader("X-API-Key", secretKey);
                req.addHeader("Authorization", "Bearer " + secretKey);
                MockHttpServletResponse res = new MockHttpServletResponse();
                filter.doFilter(req, res, chain);
            }

            for (ch.qos.logback.classic.spi.ILoggingEvent event : appender.list) {
                assertThat(event.getFormattedMessage()).doesNotContain(secretKey);
                assertThat(event.getFormattedMessage()).contains("client IP: 192.168.1.88");
            }
        } finally {
            filterLogger.detachAppender(appender);
        }
    }

    @Test
    @DisplayName("Ensures repeated failed authentication attempts are rate-limited before auth")
    void shouldRateLimitRepeatedFailedAuthenticationAttempts() throws Exception {
        ApiKeyAuthFilter authFilter = new ApiKeyAuthFilter(properties, objectMapper, filter);
        FilterChain targetChain = mock(FilterChain.class);

        // Chain RateLimitingFilter -> ApiKeyAuthFilter
        FilterChain twoFilterPipeline = new FilterChain() {
            @Override
            public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
                authFilter.doFilter(request, response, targetChain);
            }
        };

        String attackingIp = "203.0.113.99";

        // Send 3 failed authentication requests with invalid keys from the same IP
        for (int i = 0; i < 3; i++) {
            MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/discover");
            req.setRemoteAddr(attackingIp);
            req.addHeader("X-API-Key", "invalid-key-attempt-" + i);
            MockHttpServletResponse res = new MockHttpServletResponse();

            filter.doFilter(req, res, twoFilterPipeline);

            // Reaches authFilter and is rejected with 401 Unauthorized
            assertThat(res.getStatus()).isEqualTo(401);
        }

        // 4th request from the attacking IP is blocked by RateLimitingFilter with 429 Too Many Requests
        MockHttpServletRequest fourthReq = new MockHttpServletRequest("POST", "/api/discover");
        fourthReq.setRemoteAddr(attackingIp);
        fourthReq.addHeader("X-API-Key", "another-invalid-key");
        MockHttpServletResponse fourthRes = new MockHttpServletResponse();

        filter.doFilter(fourthReq, fourthRes, twoFilterPipeline);

        assertThat(fourthRes.getStatus()).isEqualTo(429);
        ErrorResponse err = objectMapper.readValue(fourthRes.getContentAsString(), ErrorResponse.class);
        assertThat(err.status()).isEqualTo(429);
        assertThat(err.error()).isEqualTo("Too Many Requests");

        // The target controller/service chain was never reached
        verify(targetChain, never()).doFilter(any(), any());
    }

    @Test
    @DisplayName("Applies per-key rate limit to authenticated requests using non-reversible identifier")
    void shouldApplyPerKeyLimitToAuthenticatedRequests() throws Exception {
        ApiKeyAuthFilter authFilter = new ApiKeyAuthFilter(properties, objectMapper, filter);
        FilterChain downstream = mock(FilterChain.class);

        String validKey = "valid-test-key-12345";
        String nonReversibleHash = RateLimitingFilter.hashKey(validKey);

        // Send 3 valid requests across 3 different IPs (bypassing individual IP limits)
        for (int i = 0; i < 3; i++) {
            MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/discover");
            req.setRemoteAddr("10.0.0." + (i + 1));
            req.addHeader("X-API-Key", validKey);
            MockHttpServletResponse res = new MockHttpServletResponse();

            authFilter.doFilter(req, res, downstream);

            assertThat(res.getStatus()).isEqualTo(200);
        }

        verify(downstream, times(3)).doFilter(any(), any());

        // 4th valid request using the same key exceeds the per-key limit and returns 429
        MockHttpServletRequest fourthReq = new MockHttpServletRequest("POST", "/api/discover");
        fourthReq.setRemoteAddr("10.0.0.99");
        fourthReq.addHeader("X-API-Key", validKey);
        MockHttpServletResponse fourthRes = new MockHttpServletResponse();

        authFilter.doFilter(fourthReq, fourthRes, downstream);

        assertThat(fourthRes.getStatus()).isEqualTo(429);
        ErrorResponse err = objectMapper.readValue(fourthRes.getContentAsString(), ErrorResponse.class);
        assertThat(err.status()).isEqualTo(429);
        assertThat(err.error()).isEqualTo("Too Many Requests");

        // Downstream was not called on the 4th request
        verify(downstream, times(3)).doFilter(any(), any());
    }

    @Test
    @DisplayName("Cleans up expired entries and enforces bounded memory map")
    void shouldCleanUpExpiredEntriesAndBoundMap() {
        // Populate entries with old timestamps (older than 60s)
        long expiredTimestamp = System.currentTimeMillis() - 70_000;
        for (int i = 0; i < 20; i++) {
            filter.recordRequestForTesting("expired-client-" + i, expiredTimestamp);
        }

        // Add 5 recent entries
        long now = System.currentTimeMillis();
        for (int i = 0; i < 5; i++) {
            filter.recordRequestForTesting("active-client-" + i, now);
        }

        assertThat(filter.getActiveEntryCount()).isEqualTo(25);

        // Run explicit cleanup for window starting 60s ago
        filter.cleanupExpiredEntries(now - 60_000);

        // All 20 expired client entries should be pruned, retaining only the 5 active clients
        assertThat(filter.getActiveEntryCount()).isEqualTo(5);
    }

    @Test
    @DisplayName("Maintains correct rate limit accounting under concurrent requests")
    void shouldHandleConcurrentRequestsCorrectly() throws Exception {
        int limit = 10;
        int totalRequests = 25;
        properties.getRateLimit().setRequestsPerMinute(limit);

        java.util.concurrent.ExecutorService executor = java.util.concurrent.Executors.newFixedThreadPool(totalRequests);
        java.util.concurrent.CountDownLatch readyLatch = new java.util.concurrent.CountDownLatch(totalRequests);
        java.util.concurrent.CountDownLatch startLatch = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.atomic.AtomicInteger allowedCount = new java.util.concurrent.atomic.AtomicInteger(0);
        java.util.concurrent.atomic.AtomicInteger rejectedCount = new java.util.concurrent.atomic.AtomicInteger(0);

        String clientIp = "192.168.1.99";

        for (int i = 0; i < totalRequests; i++) {
            executor.submit(() -> {
                readyLatch.countDown();
                try {
                    startLatch.await();
                    MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/discover");
                    req.setRemoteAddr(clientIp);
                    MockHttpServletResponse res = new MockHttpServletResponse();
                    filter.doFilter(req, res, chain);
                    if (res.getStatus() == 200) {
                        allowedCount.incrementAndGet();
                    } else if (res.getStatus() == 429) {
                        rejectedCount.incrementAndGet();
                    }
                } catch (Exception e) {
                    // ignore
                }
            });
        }

        readyLatch.await(5, java.util.concurrent.TimeUnit.SECONDS);
        startLatch.countDown();
        executor.shutdown();
        boolean terminated = executor.awaitTermination(5, java.util.concurrent.TimeUnit.SECONDS);
        assertThat(terminated).isTrue();

        // Exactly 'limit' requests should be allowed and remaining rejected
        assertThat(allowedCount.get()).isEqualTo(limit);
        assertThat(rejectedCount.get()).isEqualTo(totalRequests - limit);
    }
}
