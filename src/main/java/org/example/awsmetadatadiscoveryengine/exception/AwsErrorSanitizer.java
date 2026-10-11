package org.example.awsmetadatadiscoveryengine.exception;

import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.exception.ApiCallAttemptTimeoutException;
import software.amazon.awssdk.core.exception.ApiCallTimeoutException;
import software.amazon.awssdk.core.exception.SdkClientException;

/**
 * Utility to categorize and sanitize AWS errors into safe user-facing representations,
 * strictly preventing the leakage of credentials, internal account IDs, or sensitive error messages.
 */
public final class AwsErrorSanitizer {

    private AwsErrorSanitizer() {
    }

    public record SanitizedError(String category, String safeMessage) {}

    public static SanitizedError sanitize(Throwable throwable, String service) {
        if (throwable == null) {
            return new SanitizedError("UNKNOWN", "An unknown error occurred while discovering " + service);
        }

        if (throwable instanceof ApiCallTimeoutException || throwable instanceof ApiCallAttemptTimeoutException) {
            return new SanitizedError("TIMEOUT", "API call timed out while discovering " + service + " metadata");
        }

        if (throwable instanceof AwsServiceException awsException) {
            int statusCode = awsException.statusCode();
            String errorCode = awsException.awsErrorDetails() != null ? awsException.awsErrorDetails().errorCode() : "";

            if (statusCode == 403 || "AccessDenied".equalsIgnoreCase(errorCode) || "UnauthorizedOperation".equalsIgnoreCase(errorCode)) {
                return new SanitizedError("ACCESS_DENIED", "Access denied when querying AWS " + service + " APIs. Check IAM permissions.");
            }

            if (statusCode == 401 || "AuthFailure".equalsIgnoreCase(errorCode)) {
                return new SanitizedError("AUTHENTICATION_ERROR", "AWS authentication failed. Check credentials provider configuration.");
            }

            if (statusCode == 429 || "Throttling".equalsIgnoreCase(errorCode) || "RequestLimitExceeded".equalsIgnoreCase(errorCode)) {
                return new SanitizedError("RATE_LIMITED", "AWS API rate limit exceeded for " + service + ".");
            }

            if (statusCode >= 500) {
                return new SanitizedError("SERVICE_UNAVAILABLE", "AWS " + service + " service returned a temporary server error (" + statusCode + ").");
            }

            if (statusCode == 400 || "InvalidParameterValue".equalsIgnoreCase(errorCode) || "ValidationError".equalsIgnoreCase(errorCode)) {
                return new SanitizedError("INVALID_REQUEST", "Invalid request parameters sent to AWS " + service + ".");
            }

            return new SanitizedError("PROVIDER_ERROR", "AWS " + service + " returned error code: " + (errorCode.isBlank() ? "HTTP_" + statusCode : errorCode));
        }

        if (throwable instanceof SdkClientException) {
            String msg = throwable.getMessage();
            if (msg != null && (msg.contains("credentials") || msg.contains("Credentials"))) {
                return new SanitizedError("AUTHENTICATION_ERROR", "Unable to load AWS credentials from provider chain (Environment, Profile, or IAM Role).");
            }
            return new SanitizedError("CLIENT_ERROR", "Client communication error while contacting AWS " + service + ".");
        }

        return new SanitizedError("INTERNAL_ERROR", "Unexpected error during " + service + " discovery.");
    }
}
