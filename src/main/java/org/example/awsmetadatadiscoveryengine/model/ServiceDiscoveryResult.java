package org.example.awsmetadatadiscoveryengine.model;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Collections;
import java.util.List;

/**
 * Result of metadata discovery for a specific AWS service.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ServiceDiscoveryResult(
        String service,
        DiscoveryStatus status,
        int resourceCount,
        long durationMs,
        List<ResourceMetadata> resources,
        List<String> warnings,
        String errorCategory,
        String errorMessage
) {
    public ServiceDiscoveryResult {
        resources = resources != null ? Collections.unmodifiableList(resources) : Collections.emptyList();
        warnings = warnings != null ? Collections.unmodifiableList(warnings) : Collections.emptyList();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static ServiceDiscoveryResult success(String service, List<ResourceMetadata> resources, List<String> warnings, long durationMs) {
        return builder()
                .service(service)
                .status(DiscoveryStatus.SUCCESS)
                .resourceCount(resources != null ? resources.size() : 0)
                .durationMs(durationMs)
                .resources(resources)
                .warnings(warnings)
                .build();
    }

    public static ServiceDiscoveryResult partial(String service, List<ResourceMetadata> resources, List<String> warnings, String errorCategory, String errorMessage, long durationMs) {
        return builder()
                .service(service)
                .status(DiscoveryStatus.PARTIAL)
                .resourceCount(resources != null ? resources.size() : 0)
                .durationMs(durationMs)
                .resources(resources)
                .warnings(warnings)
                .errorCategory(errorCategory)
                .errorMessage(errorMessage)
                .build();
    }

    public static ServiceDiscoveryResult failure(String service, String errorCategory, String errorMessage, List<String> warnings, long durationMs) {
        return builder()
                .service(service)
                .status(DiscoveryStatus.FAILED)
                .resourceCount(0)
                .durationMs(durationMs)
                .resources(Collections.emptyList())
                .warnings(warnings)
                .errorCategory(errorCategory)
                .errorMessage(errorMessage)
                .build();
    }

    public static class Builder {
        private String service;
        private DiscoveryStatus status;
        private int resourceCount;
        private long durationMs;
        private List<ResourceMetadata> resources;
        private List<String> warnings;
        private String errorCategory;
        private String errorMessage;

        public Builder service(String service) {
            this.service = service;
            return this;
        }

        public Builder status(DiscoveryStatus status) {
            this.status = status;
            return this;
        }

        public Builder resourceCount(int resourceCount) {
            this.resourceCount = resourceCount;
            return this;
        }

        public Builder durationMs(long durationMs) {
            this.durationMs = durationMs;
            return this;
        }

        public Builder resources(List<ResourceMetadata> resources) {
            this.resources = resources;
            return this;
        }

        public Builder warnings(List<String> warnings) {
            this.warnings = warnings;
            return this;
        }

        public Builder errorCategory(String errorCategory) {
            this.errorCategory = errorCategory;
            return this;
        }

        public Builder errorMessage(String errorMessage) {
            this.errorMessage = errorMessage;
            return this;
        }

        public ServiceDiscoveryResult build() {
            return new ServiceDiscoveryResult(
                    service,
                    status != null ? status : DiscoveryStatus.FAILED,
                    resourceCount,
                    durationMs,
                    resources,
                    warnings,
                    errorCategory,
                    errorMessage
            );
        }
    }
}
