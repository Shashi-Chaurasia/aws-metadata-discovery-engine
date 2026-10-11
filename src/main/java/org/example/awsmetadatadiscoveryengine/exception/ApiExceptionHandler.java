package org.example.awsmetadatadiscoveryengine.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.example.awsmetadatadiscoveryengine.model.ErrorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Centralized exception handler for REST API.
 * Ensures error responses are safe, structured, and free of stack traces or sensitive credentials.
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);
    private static final String MDC_DISCOVERY_ID = "discoveryId";

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationErrors(MethodArgumentNotValidException ex, HttpServletRequest request) {
        String correlationId = getOrGenerateCorrelationId();
        List<String> details = new ArrayList<>();
        for (FieldError fieldError : ex.getBindingResult().getFieldErrors()) {
            details.add(fieldError.getField() + ": " + fieldError.getDefaultMessage());
        }

        log.warn("[correlationId={}] Request validation failed: {}", correlationId, details);

        ErrorResponse response = ErrorResponse.of(
                HttpStatus.BAD_REQUEST.value(),
                "Validation Failed",
                "Invalid request parameters",
                request.getRequestURI(),
                correlationId,
                details
        );

        return ResponseEntity.badRequest().body(response);
    }

    @ExceptionHandler(DiscoveryValidationException.class)
    public ResponseEntity<ErrorResponse> handleDiscoveryValidation(DiscoveryValidationException ex, HttpServletRequest request) {
        String correlationId = getOrGenerateCorrelationId();
        log.warn("[correlationId={}] Discovery validation error: {}", correlationId, ex.getMessage());

        ErrorResponse response = ErrorResponse.of(
                HttpStatus.BAD_REQUEST.value(),
                "Bad Request",
                ex.getMessage(),
                request.getRequestURI(),
                correlationId
        );

        return ResponseEntity.badRequest().body(response);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleMalformedJson(HttpMessageNotReadableException ex, HttpServletRequest request) {
        String correlationId = getOrGenerateCorrelationId();
        log.warn("[correlationId={}] Malformed JSON request body", correlationId);

        ErrorResponse response = ErrorResponse.of(
                HttpStatus.BAD_REQUEST.value(),
                "Bad Request",
                "Malformed or unreadable JSON request body",
                request.getRequestURI(),
                correlationId
        );

        return ResponseEntity.badRequest().body(response);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgument(IllegalArgumentException ex, HttpServletRequest request) {
        String correlationId = getOrGenerateCorrelationId();
        log.warn("[correlationId={}] Illegal argument: {}", correlationId, ex.getMessage());

        ErrorResponse response = ErrorResponse.of(
                HttpStatus.BAD_REQUEST.value(),
                "Bad Request",
                ex.getMessage(),
                request.getRequestURI(),
                correlationId
        );

        return ResponseEntity.badRequest().body(response);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGenericException(Exception ex, HttpServletRequest request) {
        String correlationId = getOrGenerateCorrelationId();
        log.error("[correlationId={}] Unhandled server exception: {}", correlationId, ex.getMessage(), ex);

        ErrorResponse response = ErrorResponse.of(
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                "Internal Server Error",
                "An unexpected internal error occurred. Please contact the administrator with correlation ID: " + correlationId,
                request.getRequestURI(),
                correlationId
        );

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }

    private String getOrGenerateCorrelationId() {
        String id = MDC.get(MDC_DISCOVERY_ID);
        return (id != null && !id.isBlank()) ? id : UUID.randomUUID().toString();
    }
}
