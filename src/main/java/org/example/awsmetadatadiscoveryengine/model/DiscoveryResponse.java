package org.example.awsmetadatadiscoveryengine.model;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Top-level response for a discovery request.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record DiscoveryResponse(
        String discoveryId,
        DiscoveryStatus status,
        String region,
        int totalResources,
        long durationMs,
        Map<String, ServiceDiscoveryResult> serviceResults,
        List<String> warnings
) {
    public DiscoveryResponse {
        serviceResults = serviceResults != null ? Collections.unmodifiableMap(serviceResults) : Collections.emptyMap();
        warnings = warnings != null ? Collections.unmodifiableList(warnings) : Collections.emptyList();
    }
}
