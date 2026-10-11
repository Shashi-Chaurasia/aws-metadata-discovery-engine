package org.example.awsmetadatadiscoveryengine.privacy;

import org.example.awsmetadatadiscoveryengine.model.ResourceMetadata;
import org.example.awsmetadatadiscoveryengine.security.SecurityProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Privacy Guard enforcing privacy-by-design through explicit per-resource-type attribute allowlisting
 * and safe tag filtering.
 *
 * Prevents accidental exposure of customer content, secrets, environment variables, or unapproved metadata.
 */
@Component
public class PrivacyGuard {

    private static final Logger log = LoggerFactory.getLogger(PrivacyGuard.class);

    // Explicit allowlists per resource type
    private static final Map<String, Set<String>> ALLOWED_ATTRIBUTES = Map.of(
            "ec2:instance", Set.of(
                    "instanceId",
                    "instanceType",
                    "instanceState",
                    "region",
                    "availabilityZone",
                    "vpcId",
                    "subnetId",
                    "architecture",
                    "platform",
                    "hypervisor",
                    "virtualizationType",
                    "launchTime",
                    "rootDeviceType",
                    "rootDeviceName",
                    "ebsOptimized"
            ),
            "s3:bucket", Set.of(
                    "bucketName",
                    "region",
                    "creationDate",
                    "versioningStatus",
                    "serverSideEncryptionEnabled",
                    "serverSideEncryptionAlgorithm",
                    "publicAccessBlockEnabled"
            )
    );

    // Explicit allowlist of recognized safe operational tag keys (case-insensitive)
    private static final Set<String> ALLOWED_TAG_KEYS = Set.of(
            "name",
            "environment",
            "project",
            "owner",
            "managedby",
            "costcenter",
            "application",
            "tier",
            "service",
            "component",
            "department",
            "stage",
            "stack",
            "version"
    );

    // Strict safe operational tag value pattern: alphanumeric, dash, underscore, dot (max 64 chars)
    // Excludes arbitrary prose, whitespace, punctuation, JSON, and unstructured scripts
    private static final Pattern SAFE_TAG_VALUE_PATTERN = Pattern.compile("^[a-zA-Z0-9_.-]{1,64}$");

    // Prohibited substrings in tag keys or values (defense-in-depth)
    private static final Pattern SENSITIVE_KEYWORD_PATTERN = Pattern.compile(
            "(?i).*(password|secret|credential|bearer|apikey|accesskey|secretkey|jwt|private_?key|session_?token).*"
    );

    // IP address patterns (IPv4 and IPv6) to exclude any tag values embedding private or public IP addresses
    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b"
    );
    private static final Pattern IPV6_PATTERN = Pattern.compile(
            "(?i)\\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\\b|::1|fe80::[0-9a-f:]+"
    );

    // AWS credential / access key pattern to prevent accidental credential leakage in tag values
    private static final Pattern AWS_CREDENTIAL_PATTERN = Pattern.compile(
            "(?i)(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|[0-9a-zA-Z/+]{40})"
    );

    private final boolean includeTagValues;

    public PrivacyGuard() {
        this(false);
    }

    public PrivacyGuard(boolean includeTagValues) {
        this.includeTagValues = includeTagValues;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public PrivacyGuard(@org.springframework.beans.factory.annotation.Autowired(required = false) SecurityProperties securityProperties) {
        this(securityProperties != null && securityProperties.getPrivacy().isIncludeTagValues());
    }

    public boolean isIncludeTagValues() {
        return includeTagValues;
    }

    /**
     * Filters and normalizes a resource metadata object against explicit allowlists.
     *
     * @param raw the raw unverified ResourceMetadata
     * @return a clean, allowlisted ResourceMetadata
     */
    public ResourceMetadata filter(ResourceMetadata raw) {
        if (raw == null) {
            return null;
        }

        Map<String, Object> sanitizedAttributes = filterAttributes(raw.resourceType(), raw.attributes());
        Map<String, String> sanitizedTags = filterTags(raw.tags());

        return ResourceMetadata.builder()
                .service(raw.service())
                .resourceType(raw.resourceType())
                .resourceId(raw.resourceId())
                .region(raw.region())
                .arn(raw.arn())
                .attributes(sanitizedAttributes)
                .tags(sanitizedTags)
                .build();
    }

    /**
     * Filters attributes against the explicit allowlist for the given resource type.
     */
    public Map<String, Object> filterAttributes(String resourceType, Map<String, Object> attributes) {
        if (attributes == null || attributes.isEmpty()) {
            return Collections.emptyMap();
        }

        Set<String> allowedKeys = ALLOWED_ATTRIBUTES.getOrDefault(resourceType, Collections.emptySet());
        Map<String, Object> clean = new LinkedHashMap<>();

        for (Map.Entry<String, Object> entry : attributes.entrySet()) {
            String key = entry.getKey();
            Object val = entry.getValue();
            if (key != null && allowedKeys.contains(key)) {
                clean.put(key, val);
            } else {
                log.debug("PrivacyGuard: Dropped unapproved attribute '{}' for resource type '{}'", key, resourceType);
            }
        }

        return Collections.unmodifiableMap(clean);
    }

    /**
     * Filters tags against the explicit tag key allowlist and ensures strict tag value privacy.
     *
     * Tag filtering policy:
     * 1. Default (includeTagValues == false):
     *    Tag values are excluded by default for privacy. Approved operational tag keys are
     *    preserved with empty string values ("") so schema structure is retained while
     *    preventing data exposure. Unapproved tag keys are completely omitted.
     *
     * 2. Explicitly Enabled (includeTagValues == true):
     *    Only safe operational tag values passing privacy validation are included.
     *    Any tag with an unapproved key or a rejected/suspicious value (prose, whitespace,
     *    JSON, IP addresses, credentials, or secrets) causes the whole tag to be omitted.
     */
    public Map<String, String> filterTags(Map<String, String> tags) {
        if (tags == null || tags.isEmpty()) {
            return Collections.emptyMap();
        }

        Map<String, String> clean = new LinkedHashMap<>();

        for (Map.Entry<String, String> entry : tags.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();

            if (!isTagKeyAllowed(key)) {
                log.debug("PrivacyGuard: Dropped unapproved/suspicious tag key '{}'", key);
                continue;
            }

            if (!includeTagValues) {
                // Tag value privacy: exclude tag values by default, preserving approved tag keys with empty strings
                clean.put(key, "");
            } else {
                // When tag values are explicitly enabled, allow only values passing strict privacy rules.
                // Rejected values cause the whole tag to be omitted.
                if (isTagValueAllowed(value)) {
                    clean.put(key, value.trim());
                } else {
                    log.debug("PrivacyGuard: Omitted tag '{}' due to rejected/suspicious value", key);
                }
            }
        }

        return Collections.unmodifiableMap(clean);
    }

    public boolean isTagKeyAllowed(String key) {
        if (key == null || key.isBlank()) {
            return false;
        }

        String normalizedKey = key.trim().toLowerCase(Locale.ROOT);

        // 1. Must be in the explicit tag allowlist
        if (!ALLOWED_TAG_KEYS.contains(normalizedKey)) {
            return false;
        }

        // 2. Key must not contain sensitive keywords
        return !SENSITIVE_KEYWORD_PATTERN.matcher(key).matches();
    }

    public boolean isTagValueAllowed(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }

        String trimmedVal = value.trim();

        // Must match safe operational identifier pattern (max 64 chars, no spaces/prose/JSON)
        if (!SAFE_TAG_VALUE_PATTERN.matcher(trimmedVal).matches()) {
            return false;
        }

        // Value must not contain sensitive keywords, credentials, or IP addresses
        return !isForbiddenValue(trimmedVal);
    }

    public boolean isTagAllowed(String key, String value) {
        if (!isTagKeyAllowed(key)) {
            return false;
        }
        if (!includeTagValues) {
            return true;
        }
        return isTagValueAllowed(value);
    }

    private boolean isForbiddenValue(String text) {
        if (text == null || text.isBlank()) {
            return false;
        }
        return SENSITIVE_KEYWORD_PATTERN.matcher(text).matches()
                || IPV4_PATTERN.matcher(text).find()
                || IPV6_PATTERN.matcher(text).find()
                || AWS_CREDENTIAL_PATTERN.matcher(text).find();
    }

    public boolean isAttributeAllowed(String resourceType, String attributeKey) {
        Set<String> allowed = ALLOWED_ATTRIBUTES.get(resourceType);
        return allowed != null && allowed.contains(attributeKey);
    }
}
