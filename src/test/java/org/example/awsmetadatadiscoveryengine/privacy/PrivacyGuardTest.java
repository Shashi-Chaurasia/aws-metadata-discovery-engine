package org.example.awsmetadatadiscoveryengine.privacy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.example.awsmetadatadiscoveryengine.model.DiscoveryResponse;
import org.example.awsmetadatadiscoveryengine.model.DiscoveryStatus;
import org.example.awsmetadatadiscoveryengine.model.ResourceMetadata;
import org.example.awsmetadatadiscoveryengine.model.ServiceDiscoveryResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class PrivacyGuardTest {

    private PrivacyGuard privacyGuard;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        privacyGuard = new PrivacyGuard(); // Default: includeTagValues = false
        objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
    }

    @Test
    @DisplayName("PrivacyGuard allows approved EC2 attributes and removes unapproved ones including private/public IPs")
    void shouldAllowOnlyApprovedEc2Attributes() {
        Map<String, Object> rawAttributes = new HashMap<>();
        rawAttributes.put("instanceId", "i-1234567890abcdef0");
        rawAttributes.put("instanceType", "t3.micro");
        rawAttributes.put("instanceState", "running");
        rawAttributes.put("region", "ap-south-1");
        // Sensitive or unapproved attributes that must be stripped by default:
        rawAttributes.put("privateIpAddress", "10.0.1.50");
        rawAttributes.put("publicIpAddress", "54.21.22.23");
        rawAttributes.put("userData", "base64EncodedUserDataWithSecrets");
        rawAttributes.put("rootPassword", "supersecret");
        rawAttributes.put("customerContent", "confidential customer text");
        rawAttributes.put("unknownCustomField", "sensitive-value");

        ResourceMetadata raw = ResourceMetadata.builder()
                .service("EC2")
                .resourceType("ec2:instance")
                .resourceId("i-1234567890abcdef0")
                .region("ap-south-1")
                .attributes(rawAttributes)
                .tags(Map.of("Environment", "Production"))
                .build();

        ResourceMetadata filtered = privacyGuard.filter(raw);

        assertThat(filtered.attributes())
                .containsEntry("instanceId", "i-1234567890abcdef0")
                .containsEntry("instanceType", "t3.micro")
                .containsEntry("instanceState", "running")
                .doesNotContainKey("privateIpAddress")
                .doesNotContainKey("publicIpAddress")
                .doesNotContainKey("userData")
                .doesNotContainKey("rootPassword")
                .doesNotContainKey("customerContent")
                .doesNotContainKey("unknownCustomField");
    }

    @Test
    @DisplayName("PrivacyGuard allows approved S3 attributes and removes unapproved ones")
    void shouldAllowOnlyApprovedS3Attributes() {
        Map<String, Object> rawAttributes = new HashMap<>();
        rawAttributes.put("bucketName", "my-safe-bucket");
        rawAttributes.put("region", "ap-south-1");
        rawAttributes.put("creationDate", "2026-01-01T00:00:00Z");
        // Unapproved attributes:
        rawAttributes.put("objectPayload", "binary content");
        rawAttributes.put("accessKey", "AKIAIOSFODNN7EXAMPLE");

        ResourceMetadata raw = ResourceMetadata.builder()
                .service("S3")
                .resourceType("s3:bucket")
                .resourceId("my-safe-bucket")
                .region("ap-south-1")
                .attributes(rawAttributes)
                .tags(Map.of())
                .build();

        ResourceMetadata filtered = privacyGuard.filter(raw);

        assertThat(filtered.attributes())
                .containsEntry("bucketName", "my-safe-bucket")
                .containsEntry("region", "ap-south-1")
                .containsEntry("creationDate", "2026-01-01T00:00:00Z")
                .doesNotContainKey("objectPayload")
                .doesNotContainKey("accessKey");
    }

    @Test
    @DisplayName("PrivacyGuard excludes tag values by default while preserving approved operational tag keys")
    void shouldExcludeTagValuesByDefaultWhilePreservingApprovedKeys() {
        Map<String, String> rawTags = new HashMap<>();
        rawTags.put("Name", "prod-web-server");
        rawTags.put("Environment", "Production");
        rawTags.put("Project", "ComplyDP");
        rawTags.put("Owner", "SecOps");
        // Unapproved tag keys:
        rawTags.put("RandomInternalNote", "some note");
        rawTags.put("SecretKey", "12345");

        Map<String, String> sanitizedTags = privacyGuard.filterTags(rawTags);

        // Approved keys preserved with empty string values; tag values excluded by default
        assertThat(sanitizedTags)
                .containsEntry("Name", "")
                .containsEntry("Environment", "")
                .containsEntry("Project", "")
                .containsEntry("Owner", "")
                .doesNotContainKey("RandomInternalNote")
                .doesNotContainKey("SecretKey");

        // Values must NOT be present
        assertThat(sanitizedTags.values()).allMatch(String::isEmpty);
    }

    @Test
    @DisplayName("PrivacyGuard allows safe tag values when explicitly enabled via configuration")
    void shouldAllowSafeTagValuesWhenExplicitlyEnabled() {
        PrivacyGuard guardWithValues = new PrivacyGuard(true);

        Map<String, String> rawTags = new HashMap<>();
        rawTags.put("Name", "prod-web-server");
        rawTags.put("Environment", "Production");
        rawTags.put("Project", "ComplyDP");
        rawTags.put("Owner", "SecOps");
        rawTags.put("RandomInternalNote", "some note"); // unapproved key
        rawTags.put("SecretKey", "12345"); // sensitive key

        Map<String, String> sanitizedTags = guardWithValues.filterTags(rawTags);

        assertThat(sanitizedTags)
                .containsEntry("Name", "prod-web-server")
                .containsEntry("Environment", "Production")
                .containsEntry("Project", "ComplyDP")
                .containsEntry("Owner", "SecOps")
                .doesNotContainKey("RandomInternalNote")
                .doesNotContainKey("SecretKey");
    }

    @Test
    @DisplayName("When tag values are enabled, arbitrary prose, JSON, and scripts are still excluded")
    void shouldExcludeArbitraryTagValuesWhenEnabled() {
        PrivacyGuard guardWithValues = new PrivacyGuard(true);

        Map<String, String> rawTags = new HashMap<>();
        rawTags.put("Name", "web-server-01"); // valid identifier
        rawTags.put("Environment", "Arbitrary freeform text note with spaces"); // prose rejected
        rawTags.put("Project", "{\"json\":\"payload\"}"); // json rejected
        rawTags.put("Owner", "<script>alert(1)</script>"); // code rejected
        rawTags.put("Tier", "frontend-tier.prod"); // valid identifier

        Map<String, String> sanitizedTags = guardWithValues.filterTags(rawTags);

        assertThat(sanitizedTags)
                .containsEntry("Name", "web-server-01")
                .containsEntry("Tier", "frontend-tier.prod")
                .doesNotContainKey("Environment")
                .doesNotContainKey("Project")
                .doesNotContainKey("Owner");
    }

    @Test
    @DisplayName("When tag values are enabled, IP addresses and AWS credentials in values are strictly scrubbed")
    void shouldExcludeIpAddressesAndCredentialsInTagValuesWhenEnabled() {
        PrivacyGuard guardWithValues = new PrivacyGuard(true);

        Map<String, String> rawTags = new HashMap<>();
        rawTags.put("Name", "10.0.1.50"); // private IP rejected
        rawTags.put("Environment", "54.21.22.23"); // public IP rejected
        rawTags.put("Project", "fe80::1"); // IPv6 rejected
        rawTags.put("Owner", "AKIAIOSFODNN7EXAMPLE"); // AWS credential rejected
        rawTags.put("Component", "auth-service"); // valid

        Map<String, String> sanitizedTags = guardWithValues.filterTags(rawTags);

        assertThat(sanitizedTags)
                .containsEntry("Component", "auth-service")
                .doesNotContainKey("Name")
                .doesNotContainKey("Environment")
                .doesNotContainKey("Project")
                .doesNotContainKey("Owner");
    }

    @Test
    @DisplayName("Proves that tag values do not appear in the final serialized response when setting is disabled (default)")
    void shouldProveTagValuesDoNotAppearInSerializedResponseWhenDisabled() throws Exception {
        Map<String, Object> rawAttributes = new HashMap<>();
        rawAttributes.put("instanceId", "i-0123456789abcdef0");
        rawAttributes.put("instanceType", "t3.micro");
        rawAttributes.put("instanceState", "running");
        rawAttributes.put("region", "ap-south-1");
        // Forbidden fields to test leakage:
        rawAttributes.put("privateIpAddress", "172.31.10.15");
        rawAttributes.put("publicIpAddress", "13.233.50.88");
        rawAttributes.put("userData", "curl http://169.254.169.254/latest/meta-data/");
        rawAttributes.put("adminCredentials", "admin:SecretP@ssword123");
        rawAttributes.put("unknownInternalField", "internal-debug-data");

        Map<String, String> rawTags = new HashMap<>();
        rawTags.put("Name", "prod-api-server");
        rawTags.put("Environment", "Production");
        rawTags.put("PrivateIP", "172.31.10.15");
        rawTags.put("PublicIP", "13.233.50.88");
        rawTags.put("AdminPassword", "super-secret-password");
        rawTags.put("AccessKey", "AKIAI44QH8DHBEXAMPLE");
        rawTags.put("CustomNotes", "Customer phone: +1-555-0199 and email user@example.com");

        ResourceMetadata rawMetadata = ResourceMetadata.builder()
                .service("EC2")
                .resourceType("ec2:instance")
                .resourceId("i-0123456789abcdef0")
                .region("ap-south-1")
                .arn("arn:aws:ec2:ap-south-1:123456789012:instance/i-0123456789abcdef0")
                .attributes(rawAttributes)
                .tags(rawTags)
                .build();

        // Using default privacyGuard (includeTagValues = false)
        ResourceMetadata sanitized = privacyGuard.filter(rawMetadata);

        ServiceDiscoveryResult result = ServiceDiscoveryResult.success(
                "EC2", List.of(sanitized), List.of(), 15L
        );

        DiscoveryResponse response = new DiscoveryResponse(
                "discovery-test-trace-id",
                DiscoveryStatus.SUCCESS,
                "ap-south-1",
                1,
                15L,
                Map.of("EC2", result),
                List.of()
        );

        String json = objectMapper.writeValueAsString(response);

        // Verify approved metadata keys ARE present:
        assertThat(json).contains("i-0123456789abcdef0");
        assertThat(json).contains("t3.micro");
        assertThat(json).contains("\"Name\":\"\"");
        assertThat(json).contains("\"Environment\":\"\"");

        // PROOF: Tag values DO NOT appear anywhere in the final response:
        assertThat(json).doesNotContain("prod-api-server");
        assertThat(json).doesNotContain("Production");

        // Verify forbidden attributes, IPs, credentials, and unapproved tags ARE ABSENT:
        assertThat(json).doesNotContain("172.31.10.15");
        assertThat(json).doesNotContain("13.233.50.88");
        assertThat(json).doesNotContain("privateIpAddress");
        assertThat(json).doesNotContain("publicIpAddress");
        assertThat(json).doesNotContain("PrivateIP");
        assertThat(json).doesNotContain("PublicIP");
        assertThat(json).doesNotContain("userData");
        assertThat(json).doesNotContain("169.254.169.254");
        assertThat(json).doesNotContain("adminCredentials");
        assertThat(json).doesNotContain("SecretP@ssword123");
        assertThat(json).doesNotContain("AdminPassword");
        assertThat(json).doesNotContain("super-secret-password");
        assertThat(json).doesNotContain("AccessKey");
        assertThat(json).doesNotContain("AKIAI44QH8DHBEXAMPLE");
        assertThat(json).doesNotContain("CustomNotes");
        assertThat(json).doesNotContain("user@example.com");
        assertThat(json).doesNotContain("unknownInternalField");
        assertThat(json).doesNotContain("internal-debug-data");
    }

    @Test
    @DisplayName("Verifies that when tag values are enabled, safe values appear in serialized response while forbidden fields remain absent")
    void shouldIncludeSafeTagValuesInSerializedResponseWhenEnabled() throws Exception {
        PrivacyGuard guardWithValues = new PrivacyGuard(true);

        Map<String, Object> rawAttributes = new HashMap<>();
        rawAttributes.put("instanceId", "i-enabled-999");
        rawAttributes.put("instanceType", "t3.small");

        Map<String, String> rawTags = new HashMap<>();
        rawTags.put("Name", "billing-worker");
        rawTags.put("Environment", "Staging");
        rawTags.put("SecretKey", "forbidden-token");

        ResourceMetadata rawMetadata = ResourceMetadata.builder()
                .service("EC2")
                .resourceType("ec2:instance")
                .resourceId("i-enabled-999")
                .region("ap-south-1")
                .arn("arn:aws:ec2:ap-south-1:123456789012:instance/i-enabled-999")
                .attributes(rawAttributes)
                .tags(rawTags)
                .build();

        ResourceMetadata sanitized = guardWithValues.filter(rawMetadata);

        ServiceDiscoveryResult result = ServiceDiscoveryResult.success(
                "EC2", List.of(sanitized), List.of(), 10L
        );

        DiscoveryResponse response = new DiscoveryResponse(
                "trace-enabled-123",
                DiscoveryStatus.SUCCESS,
                "ap-south-1",
                1,
                10L,
                Map.of("EC2", result),
                List.of()
        );

        String json = objectMapper.writeValueAsString(response);

        // Safe tag values DO appear when enabled:
        assertThat(json).contains("\"Name\":\"billing-worker\"");
        assertThat(json).contains("\"Environment\":\"Staging\"");

        // Unapproved / sensitive tag key remains absent:
        assertThat(json).doesNotContain("SecretKey");
        assertThat(json).doesNotContain("forbidden-token");
    }
}
