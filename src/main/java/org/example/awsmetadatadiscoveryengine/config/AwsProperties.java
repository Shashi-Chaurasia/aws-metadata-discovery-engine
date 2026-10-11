package org.example.awsmetadatadiscoveryengine.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Configuration properties for AWS discovery operations.
 */
@Component
@ConfigurationProperties(prefix = "aws.discovery")
public class AwsProperties {

    /**
     * Timeout for the entire AWS API call execution including all retries.
     */
    private int apiCallTimeoutSeconds = 15;

    /**
     * Timeout for an individual HTTP attempt.
     */
    private int apiCallAttemptTimeoutSeconds = 5;

    /**
     * Maximum number of retry attempts for transient errors.
     */
    private int maxRetries = 2;

    public int getApiCallTimeoutSeconds() {
        return apiCallTimeoutSeconds;
    }

    public void setApiCallTimeoutSeconds(int apiCallTimeoutSeconds) {
        this.apiCallTimeoutSeconds = apiCallTimeoutSeconds;
    }

    public int getApiCallAttemptTimeoutSeconds() {
        return apiCallAttemptTimeoutSeconds;
    }

    public void setApiCallAttemptTimeoutSeconds(int apiCallAttemptTimeoutSeconds) {
        this.apiCallAttemptTimeoutSeconds = apiCallAttemptTimeoutSeconds;
    }

    public int getMaxRetries() {
        return maxRetries;
    }

    public void setMaxRetries(int maxRetries) {
        this.maxRetries = maxRetries;
    }
}
