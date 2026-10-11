package org.example.awsmetadatadiscoveryengine.exception;

/**
 * Exception thrown when a discovery request fails validation.
 */
public class DiscoveryValidationException extends RuntimeException {

    public DiscoveryValidationException(String message) {
        super(message);
    }
}
