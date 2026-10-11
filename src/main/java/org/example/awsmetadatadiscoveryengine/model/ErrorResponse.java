package org.example.awsmetadatadiscoveryengine.model;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.Instant;
import java.util.List;

/**
 * Standardized safe error response model for API errors.
 * Guarantees no sensitive provider traces or stack traces are leaked to clients.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ErrorResponse(
        Instant timestamp,
        int status,
        String error,
        String message,
        String path,
        String correlationId,
        List<String> details
) {
    public static ErrorResponse of(int status, String error, String message, String path, String correlationId, List<String> details) {
        return new ErrorResponse(Instant.now(), status, error, message, path, correlationId, details);
    }

    public static ErrorResponse of(int status, String error, String message, String path, String correlationId) {
        return new ErrorResponse(Instant.now(), status, error, message, path, correlationId, null);
    }
}
