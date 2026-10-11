package org.example.awsmetadatadiscoveryengine.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.example.awsmetadatadiscoveryengine.model.ErrorResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class ApiKeyAuthFilterTest {

    private SecurityProperties properties;
    private ObjectMapper objectMapper;
    private ApiKeyAuthFilter filter;
    private FilterChain filterChain;

    @BeforeEach
    void setUp() {
        properties = new SecurityProperties();
        properties.getApiKey().setEnabled(true);
        properties.getApiKey().setSecret("test-secret-key-12345");
        properties.getApiKey().setHeaderName("X-API-Key");

        objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());

        filter = new ApiKeyAuthFilter(properties, objectMapper);
        filterChain = mock(FilterChain.class);
    }

    @Test
    @DisplayName("Returns 401 Unauthorized when API key is missing on /api/discover")
    void shouldReturn401WhenApiKeyMissing() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/discover");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(401);
        verify(filterChain, never()).doFilter(request, response);

        ErrorResponse errorResponse = objectMapper.readValue(response.getContentAsString(), ErrorResponse.class);
        assertThat(errorResponse.status()).isEqualTo(401);
        assertThat(errorResponse.error()).isEqualTo("Unauthorized");
        assertThat(errorResponse.message()).contains("Missing or invalid API key");
        assertThat(response.getHeader("X-Correlation-ID")).isNotBlank();
    }

    @Test
    @DisplayName("Returns 401 Unauthorized when API key is invalid")
    void shouldReturn401WhenApiKeyInvalid() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/discover");
        request.addHeader("X-API-Key", "invalid-key-value");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(401);
        verify(filterChain, never()).doFilter(request, response);
    }

    @Test
    @DisplayName("Allows request when valid X-API-Key header is supplied")
    void shouldAllowRequestWithValidApiKeyHeader() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/discover");
        request.addHeader("X-API-Key", "test-secret-key-12345");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(200);
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    @DisplayName("Allows request when valid Authorization Bearer header is supplied")
    void shouldAllowRequestWithValidBearerToken() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/discover");
        request.addHeader("Authorization", "Bearer test-secret-key-12345");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(200);
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    @DisplayName("Allows public actuator endpoint without API key")
    void shouldAllowPublicActuatorPathWithoutApiKey() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/actuator/health");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(200);
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    @DisplayName("Bypasses authentication when security is disabled in configuration")
    void shouldBypassWhenApiKeySecurityDisabled() throws ServletException, IOException {
        properties.getApiKey().setEnabled(false);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/discover");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(200);
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    @DisplayName("Propagates valid incoming X-Correlation-ID header")
    void shouldPropagateIncomingCorrelationId() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/discover");
        request.addHeader("X-API-Key", "test-secret-key-12345");
        request.addHeader("X-Correlation-ID", "custom-trace-id-123");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertThat(response.getHeader("X-Correlation-ID")).isEqualTo("custom-trace-id-123");
    }

    @Test
    @DisplayName("Missing configured secret (null) never bypasses authentication and returns 401")
    void shouldRejectWhenConfiguredSecretIsNull() throws ServletException, IOException {
        properties.getApiKey().setSecret(null);
        properties.getApiKey().setEnabled(true);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/discover");
        request.addHeader("X-API-Key", "attempted-key-value");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(401);
        verify(filterChain, never()).doFilter(request, response);
    }

    @Test
    @DisplayName("Blank configured secret never bypasses authentication and returns 401")
    void shouldRejectWhenConfiguredSecretIsBlank() throws ServletException, IOException {
        properties.getApiKey().setSecret("   ");
        properties.getApiKey().setEnabled(true);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/discover");
        request.addHeader("X-API-Key", "attempted-key-value");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(401);
        verify(filterChain, never()).doFilter(request, response);
    }

    @Test
    @DisplayName("Missing SecurityProperties object never bypasses authentication and returns 401")
    void shouldRejectWhenSecurityPropertiesIsNull() throws ServletException, IOException {
        ApiKeyAuthFilter filterWithoutProps = new ApiKeyAuthFilter(null, objectMapper);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/discover");
        request.addHeader("X-API-Key", "some-key");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filterWithoutProps.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(401);
        verify(filterChain, never()).doFilter(request, response);
    }

    @Test
    @DisplayName("API key is never written to logs during request processing or failure")
    void shouldNeverLogApiKey() throws ServletException, IOException {
        ch.qos.logback.classic.Logger filterLogger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(ApiKeyAuthFilter.class);
        ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent> appender = new ch.qos.logback.core.read.ListAppender<>();
        appender.start();
        filterLogger.addAppender(appender);

        String secretKey = "super-sensitive-secret-token-do-not-log";
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/discover");
        request.addHeader("X-API-Key", secretKey);
        MockHttpServletResponse response = new MockHttpServletResponse();

        try {
            filter.doFilter(request, response, filterChain);

            for (ch.qos.logback.classic.spi.ILoggingEvent event : appender.list) {
                assertThat(event.getFormattedMessage()).doesNotContain(secretKey);
            }
        } finally {
            filterLogger.detachAppender(appender);
        }
    }

    @Test
    @DisplayName("API key and key hashes are never written to logs when rate limited")
    void shouldNeverLogApiKeyOrHashWhenRateLimited() throws Exception {
        ch.qos.logback.classic.Logger filterLogger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(ApiKeyAuthFilter.class);
        ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent> appender = new ch.qos.logback.core.read.ListAppender<>();
        appender.start();
        filterLogger.addAppender(appender);

        String secretKey = "test-secret-key-12345";
        String keyHash = RateLimitingFilter.hashKey(secretKey);

        RateLimitingFilter rateLimiter = new RateLimitingFilter(properties, objectMapper);
        ApiKeyAuthFilter authFilter = new ApiKeyAuthFilter(properties, objectMapper, rateLimiter);
        properties.getRateLimit().setRequestsPerMinute(1);

        try {
            // First request passes
            MockHttpServletRequest req1 = new MockHttpServletRequest("POST", "/api/discover");
            req1.addHeader("X-API-Key", secretKey);
            MockHttpServletResponse res1 = new MockHttpServletResponse();
            authFilter.doFilter(req1, res1, filterChain);

            // Second request gets rate limited
            MockHttpServletRequest req2 = new MockHttpServletRequest("POST", "/api/discover");
            req2.addHeader("X-API-Key", secretKey);
            MockHttpServletResponse res2 = new MockHttpServletResponse();
            authFilter.doFilter(req2, res2, filterChain);

            assertThat(res2.getStatus()).isEqualTo(429);

            for (ch.qos.logback.classic.spi.ILoggingEvent event : appender.list) {
                assertThat(event.getFormattedMessage()).doesNotContain(secretKey);
                assertThat(event.getFormattedMessage()).doesNotContain(keyHash);
                assertThat(event.getFormattedMessage()).doesNotContain("key-hash");
            }
        } finally {
            filterLogger.detachAppender(appender);
        }
    }
}
