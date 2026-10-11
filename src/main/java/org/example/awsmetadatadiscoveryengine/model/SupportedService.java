package org.example.awsmetadatadiscoveryengine.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Arrays;
import java.util.Optional;

/**
 * Enumeration of AWS services supported by the discovery engine.
 */
public enum SupportedService {
    EC2("EC2"),
    S3("S3");

    private final String value;

    SupportedService(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }

    @JsonCreator
    public static SupportedService fromString(String text) {
        if (text == null || text.isBlank()) {
            throw new IllegalArgumentException("Service name must not be blank");
        }
        return fromStringOptional(text)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Unsupported AWS service: '" + text + "'. Supported services: " + Arrays.toString(values())));
    }

    public static Optional<SupportedService> fromStringOptional(String text) {
        if (text == null) {
            return Optional.empty();
        }
        for (SupportedService service : values()) {
            if (service.name().equalsIgnoreCase(text.trim()) || service.value.equalsIgnoreCase(text.trim())) {
                return Optional.of(service);
            }
        }
        return Optional.empty();
    }
}
