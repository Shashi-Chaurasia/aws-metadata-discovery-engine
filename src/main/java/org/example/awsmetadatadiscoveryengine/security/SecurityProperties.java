package org.example.awsmetadatadiscoveryengine.security;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration properties for ComplyDP API security.
 */
@Component
@ConfigurationProperties(prefix = "complydp.security")
public class SecurityProperties {

    private ApiKey apiKey = new ApiKey();
    private RateLimit rateLimit = new RateLimit();
    private Cors cors = new Cors();
    private Privacy privacy = new Privacy();

    public ApiKey getApiKey() {
        return apiKey;
    }

    public void setApiKey(ApiKey apiKey) {
        this.apiKey = apiKey;
    }

    public RateLimit getRateLimit() {
        return rateLimit;
    }

    public void setRateLimit(RateLimit rateLimit) {
        this.rateLimit = rateLimit;
    }

    public Cors getCors() {
        return cors;
    }

    public void setCors(Cors cors) {
        this.cors = cors;
    }

    public Privacy getPrivacy() {
        return privacy;
    }

    public void setPrivacy(Privacy privacy) {
        this.privacy = privacy;
    }

    public static class ApiKey {
        private boolean enabled = true;
        private String secret;
        private String headerName = "X-API-Key";

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getSecret() {
            return secret;
        }

        public void setSecret(String secret) {
            this.secret = secret;
        }

        public String getHeaderName() {
            return headerName;
        }

        public void setHeaderName(String headerName) {
            this.headerName = headerName;
        }
    }

    public static class RateLimit {
        private boolean enabled = true;
        private int requestsPerMinute = 60;
        private boolean trustForwardedFor = false;
        private List<String> trustedProxies = new ArrayList<>(List.of("127.0.0.1", "0:0:0:0:0:0:0:1", "::1"));

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public int getRequestsPerMinute() {
            return requestsPerMinute;
        }

        public void setRequestsPerMinute(int requestsPerMinute) {
            this.requestsPerMinute = requestsPerMinute;
        }

        public boolean isTrustForwardedFor() {
            return trustForwardedFor;
        }

        public void setTrustForwardedFor(boolean trustForwardedFor) {
            this.trustForwardedFor = trustForwardedFor;
        }

        public List<String> getTrustedProxies() {
            return trustedProxies;
        }

        public void setTrustedProxies(List<String> trustedProxies) {
            this.trustedProxies = trustedProxies;
        }
    }

    public static class Cors {
        private List<String> allowedOrigins = new ArrayList<>(List.of("http://localhost:3000", "http://localhost:8080"));
        private List<String> allowedMethods = new ArrayList<>(List.of("POST", "OPTIONS"));
        private List<String> allowedHeaders = new ArrayList<>(List.of("Content-Type", "X-API-Key", "Authorization", "X-Correlation-ID"));
        private long maxAgeSeconds = 3600;

        public List<String> getAllowedOrigins() {
            return allowedOrigins;
        }

        public void setAllowedOrigins(List<String> allowedOrigins) {
            this.allowedOrigins = allowedOrigins;
        }

        public List<String> getAllowedMethods() {
            return allowedMethods;
        }

        public void setAllowedMethods(List<String> allowedMethods) {
            this.allowedMethods = allowedMethods;
        }

        public List<String> getAllowedHeaders() {
            return allowedHeaders;
        }

        public void setAllowedHeaders(List<String> allowedHeaders) {
            this.allowedHeaders = allowedHeaders;
        }

        public long getMaxAgeSeconds() {
            return maxAgeSeconds;
        }

        public void setMaxAgeSeconds(long maxAgeSeconds) {
            this.maxAgeSeconds = maxAgeSeconds;
        }
    }

    public static class Privacy {
        private boolean includeTagValues = false; // default false: exclude tag values by default

        public boolean isIncludeTagValues() {
            return includeTagValues;
        }

        public void setIncludeTagValues(boolean includeTagValues) {
            this.includeTagValues = includeTagValues;
        }
    }
}
