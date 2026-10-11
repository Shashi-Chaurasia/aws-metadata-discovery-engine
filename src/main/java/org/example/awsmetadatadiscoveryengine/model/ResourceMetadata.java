package org.example.awsmetadatadiscoveryengine.model;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Collections;
import java.util.Map;

/**
 * Normalized representation of discovered AWS resource metadata.
 * Customer data and sensitive values are excluded by design.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ResourceMetadata(
        String service,
        String resourceType,
        String resourceId,
        String region,
        String arn,
        Map<String, Object> attributes,
        Map<String, String> tags
) {
    public ResourceMetadata {
        attributes = attributes != null ? Collections.unmodifiableMap(attributes) : Collections.emptyMap();
        tags = tags != null ? Collections.unmodifiableMap(tags) : Collections.emptyMap();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String service;
        private String resourceType;
        private String resourceId;
        private String region;
        private String arn;
        private Map<String, Object> attributes;
        private Map<String, String> tags;

        public Builder service(String service) {
            this.service = service;
            return this;
        }

        public Builder resourceType(String resourceType) {
            this.resourceType = resourceType;
            return this;
        }

        public Builder resourceId(String resourceId) {
            this.resourceId = resourceId;
            return this;
        }

        public Builder region(String region) {
            this.region = region;
            return this;
        }

        public Builder arn(String arn) {
            this.arn = arn;
            return this;
        }

        public Builder attributes(Map<String, Object> attributes) {
            this.attributes = attributes;
            return this;
        }

        public Builder tags(Map<String, String> tags) {
            this.tags = tags;
            return this;
        }

        public ResourceMetadata build() {
            return new ResourceMetadata(service, resourceType, resourceId, region, arn, attributes, tags);
        }
    }
}
