package org.example.awsmetadatadiscoveryengine.connector;

import org.example.awsmetadatadiscoveryengine.config.AwsClientFactory;
import org.example.awsmetadatadiscoveryengine.exception.AwsErrorSanitizer;
import org.example.awsmetadatadiscoveryengine.model.ResourceMetadata;
import org.example.awsmetadatadiscoveryengine.model.ServiceDiscoveryResult;
import org.example.awsmetadatadiscoveryengine.model.SupportedService;
import org.example.awsmetadatadiscoveryengine.privacy.PrivacyGuard;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;

import java.util.*;

/**
 * Metadata discovery connector for AWS S3.
 * Discovers S3 bucket metadata for the requested region, queries bucket-level tags
 * where permissions allow, and enforces strict privacy-by-design allowlists.
 * Never reads bucket objects, object keys, or customer payload data.
 */
@Component
public class S3Connector implements AwsResourceConnector {

    private static final Logger log = LoggerFactory.getLogger(S3Connector.class);
    private static final String RESOURCE_TYPE = "s3:bucket";

    private final AwsClientFactory clientFactory;
    private final PrivacyGuard privacyGuard;

    public S3Connector(AwsClientFactory clientFactory, PrivacyGuard privacyGuard) {
        this.clientFactory = clientFactory;
        this.privacyGuard = privacyGuard;
    }

    @Override
    public SupportedService getSupportedService() {
        return SupportedService.S3;
    }

    @Override
    public ServiceDiscoveryResult discover(String regionName, String discoveryId) {
        long startTime = System.currentTimeMillis();
        Region awsRegion = Region.of(regionName);
        List<ResourceMetadata> discovered = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        boolean hadPartialFailures = false;

        log.info("[discoveryId={}] Starting S3 discovery in region: {}", discoveryId, regionName);

        try {
            S3Client s3Client = clientFactory.getS3Client(awsRegion);

            ListBucketsResponse listBucketsResponse = s3Client.listBuckets(ListBucketsRequest.builder().build());
            List<Bucket> allBuckets = listBucketsResponse.buckets();

            log.info("[discoveryId={}] Found {} total account buckets. Filtering for region: {}",
                    discoveryId, allBuckets != null ? allBuckets.size() : 0, regionName);

            if (allBuckets != null) {
                for (Bucket bucket : allBuckets) {
                    String bucketName = bucket.name();
                    String bucketRegion = null;

                    try {
                        GetBucketLocationResponse locResponse = s3Client.getBucketLocation(
                                GetBucketLocationRequest.builder().bucket(bucketName).build()
                        );
                        bucketRegion = normalizeS3Region(locResponse.locationConstraintAsString());
                    } catch (S3Exception e) {
                        String warnMsg = "Bucket '" + bucketName + "': could not verify location (" +
                                (e.statusCode() == 403 ? "AccessDenied" : e.awsErrorDetails() != null ? e.awsErrorDetails().errorCode() : "Error") + ")";
                        warnings.add(warnMsg);
                        hadPartialFailures = true;
                        log.debug("[discoveryId={}] S3 getBucketLocation warning: {}", discoveryId, warnMsg);
                        continue;
                    } catch (Exception e) {
                        warnings.add("Bucket '" + bucketName + "': error resolving region");
                        hadPartialFailures = true;
                        continue;
                    }

                    // Filter buckets to those belonging to the requested region
                    if (!regionName.equalsIgnoreCase(bucketRegion)) {
                        continue;
                    }

                    // Bucket belongs to requested region: discover metadata
                    Map<String, String> tags = new LinkedHashMap<>();
                    try {
                        GetBucketTaggingResponse tagResponse = s3Client.getBucketTagging(
                                GetBucketTaggingRequest.builder().bucket(bucketName).build()
                        );
                        if (tagResponse.hasTagSet()) {
                            for (software.amazon.awssdk.services.s3.model.Tag tag : tagResponse.tagSet()) {
                                if (tag.key() != null) {
                                    tags.put(tag.key(), tag.value() != null ? tag.value() : "");
                                }
                            }
                        }
                    } catch (S3Exception e) {
                        int code = e.statusCode();
                        String errCode = e.awsErrorDetails() != null ? e.awsErrorDetails().errorCode() : "";
                        if ("NoSuchTagSet".equalsIgnoreCase(errCode) || code == 404) {
                            // Bucket has no tags - standard condition
                            log.debug("[discoveryId={}] Bucket '{}' has no tags", discoveryId, bucketName);
                        } else if (code == 403 || "AccessDenied".equalsIgnoreCase(errCode)) {
                            warnings.add("Bucket '" + bucketName + "': tags omitted due to AccessDenied (s3:GetBucketTagging)");
                            hadPartialFailures = true;
                        } else {
                            warnings.add("Bucket '" + bucketName + "': tags could not be retrieved (" + errCode + ")");
                            hadPartialFailures = true;
                        }
                    }

                    Map<String, Object> attributes = new LinkedHashMap<>();
                    attributes.put("bucketName", bucketName);
                    attributes.put("region", bucketRegion);
                    if (bucket.creationDate() != null) {
                        attributes.put("creationDate", bucket.creationDate().toString());
                    }

                    ResourceMetadata raw = ResourceMetadata.builder()
                            .service(SupportedService.S3.name())
                            .resourceType(RESOURCE_TYPE)
                            .resourceId(bucketName)
                            .region(bucketRegion)
                            .arn("arn:aws:s3:::" + bucketName)
                            .attributes(attributes)
                            .tags(tags)
                            .build();

                    discovered.add(privacyGuard.filter(raw));
                }
            }

            long duration = System.currentTimeMillis() - startTime;
            log.info("[discoveryId={}] Completed S3 discovery in {}ms. Discovered {} buckets for region {}",
                    discoveryId, duration, discovered.size(), regionName);

            if (hadPartialFailures) {
                return ServiceDiscoveryResult.partial(
                        SupportedService.S3.name(),
                        discovered,
                        warnings,
                        "PERMISSION_PARTIAL",
                        "One or more bucket-level metadata calls could not be completed due to permissions or service limits",
                        duration
                );
            }

            return ServiceDiscoveryResult.success(SupportedService.S3.name(), discovered, warnings, duration);

        } catch (Exception e) {
            long duration = System.currentTimeMillis() - startTime;
            AwsErrorSanitizer.SanitizedError sanitized = AwsErrorSanitizer.sanitize(e, SupportedService.S3.name());

            log.warn("[discoveryId={}] S3 discovery failed: category={}, safeMessage={}",
                    discoveryId, sanitized.category(), sanitized.safeMessage());

            return ServiceDiscoveryResult.failure(
                    SupportedService.S3.name(),
                    sanitized.category(),
                    sanitized.safeMessage(),
                    warnings,
                    duration
            );
        }
    }

    /**
     * Normalizes the S3 location constraint string to standard AWS region naming.
     * S3 returns null or empty string for 'us-east-1', and 'EU' for 'eu-west-1'.
     */
    public static String normalizeS3Region(String constraint) {
        if (constraint == null || constraint.isBlank()) {
            return "us-east-1";
        }
        if ("EU".equalsIgnoreCase(constraint)) {
            return "eu-west-1";
        }
        return constraint;
    }
}
