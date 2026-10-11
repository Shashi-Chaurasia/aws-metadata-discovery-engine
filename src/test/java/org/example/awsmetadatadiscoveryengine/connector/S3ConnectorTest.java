package org.example.awsmetadatadiscoveryengine.connector;

import org.example.awsmetadatadiscoveryengine.config.AwsClientFactory;
import org.example.awsmetadatadiscoveryengine.model.DiscoveryStatus;
import org.example.awsmetadatadiscoveryengine.model.ResourceMetadata;
import org.example.awsmetadatadiscoveryengine.model.ServiceDiscoveryResult;
import org.example.awsmetadatadiscoveryengine.privacy.PrivacyGuard;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class S3ConnectorTest {

    @Mock
    private AwsClientFactory clientFactory;

    @Mock
    private S3Client s3Client;

    private PrivacyGuard privacyGuard;
    private S3Connector connector;

    @BeforeEach
    void setUp() {
        privacyGuard = new PrivacyGuard();
        connector = new S3Connector(clientFactory, privacyGuard);
    }

    @Test
    @DisplayName("S3 connector maps bucket metadata safely and filters by requested region")
    void shouldMapBucketMetadataSafelyForMatchingRegion() {
        String region = "ap-south-1";
        when(clientFactory.getS3Client(Region.of(region))).thenReturn(s3Client);

        Bucket bucket1 = Bucket.builder()
                .name("complydp-ap-south-bucket")
                .creationDate(Instant.parse("2026-02-01T10:00:00Z"))
                .build();
        Bucket bucket2 = Bucket.builder()
                .name("complydp-us-east-bucket")
                .creationDate(Instant.parse("2026-02-01T11:00:00Z"))
                .build();

        when(s3Client.listBuckets(any(ListBucketsRequest.class)))
                .thenReturn(ListBucketsResponse.builder().buckets(bucket1, bucket2).build());

        // Bucket 1 location is ap-south-1
        when(s3Client.getBucketLocation(GetBucketLocationRequest.builder().bucket("complydp-ap-south-bucket").build()))
                .thenReturn(GetBucketLocationResponse.builder().locationConstraint("ap-south-1").build());

        // Bucket 2 location is us-east-1 (returns null or empty string in S3)
        when(s3Client.getBucketLocation(GetBucketLocationRequest.builder().bucket("complydp-us-east-bucket").build()))
                .thenReturn(GetBucketLocationResponse.builder().locationConstraint("").build());

        // Bucket 1 tags
        when(s3Client.getBucketTagging(GetBucketTaggingRequest.builder().bucket("complydp-ap-south-bucket").build()))
                .thenReturn(GetBucketTaggingResponse.builder().tagSet(
                        Tag.builder().key("Environment").value("Production").build(),
                        Tag.builder().key("Project").value("ComplyDP").build()
                ).build());

        ServiceDiscoveryResult result = connector.discover(region, "test-disc-s3-1");

        assertThat(result.status()).isEqualTo(DiscoveryStatus.SUCCESS);
        assertThat(result.resourceCount()).isEqualTo(1);
        assertThat(result.resources()).hasSize(1);

        ResourceMetadata metadata = result.resources().get(0);
        assertThat(metadata.resourceId()).isEqualTo("complydp-ap-south-bucket");
        assertThat(metadata.resourceType()).isEqualTo("s3:bucket");
        assertThat(metadata.region()).isEqualTo("ap-south-1");
        assertThat(metadata.arn()).isEqualTo("arn:aws:s3:::complydp-ap-south-bucket");
        assertThat(metadata.attributes())
                .containsEntry("bucketName", "complydp-ap-south-bucket")
                .containsEntry("region", "ap-south-1")
                .containsKey("creationDate");
        assertThat(metadata.tags())
                .containsEntry("Environment", "")
                .containsEntry("Project", "");
    }

    @Test
    @DisplayName("S3 connector handles NoSuchTagSet gracefully without failing")
    void shouldHandleNoSuchTagSetCleanly() {
        String region = "ap-south-1";
        when(clientFactory.getS3Client(Region.of(region))).thenReturn(s3Client);

        Bucket bucket = Bucket.builder().name("untagged-bucket").build();
        when(s3Client.listBuckets(any(ListBucketsRequest.class)))
                .thenReturn(ListBucketsResponse.builder().buckets(bucket).build());

        when(s3Client.getBucketLocation(any(GetBucketLocationRequest.class)))
                .thenReturn(GetBucketLocationResponse.builder().locationConstraint("ap-south-1").build());

        S3Exception noSuchTagSet = (S3Exception) S3Exception.builder()
                .statusCode(404)
                .awsErrorDetails(AwsErrorDetails.builder().errorCode("NoSuchTagSet").build())
                .build();
        when(s3Client.getBucketTagging(any(GetBucketTaggingRequest.class))).thenThrow(noSuchTagSet);

        ServiceDiscoveryResult result = connector.discover(region, "test-disc-s3-2");

        assertThat(result.status()).isEqualTo(DiscoveryStatus.SUCCESS);
        assertThat(result.resourceCount()).isEqualTo(1);
        assertThat(result.resources().get(0).tags()).isEmpty();
        assertThat(result.warnings()).isEmpty();
    }

    @Test
    @DisplayName("S3 connector handles tagging AccessDenied with warning and partial status")
    void shouldHandleBucketTaggingAccessDeniedWithWarningAndPartialStatus() {
        String region = "ap-south-1";
        when(clientFactory.getS3Client(Region.of(region))).thenReturn(s3Client);

        Bucket bucket = Bucket.builder().name("restricted-tag-bucket").build();
        when(s3Client.listBuckets(any(ListBucketsRequest.class)))
                .thenReturn(ListBucketsResponse.builder().buckets(bucket).build());

        when(s3Client.getBucketLocation(any(GetBucketLocationRequest.class)))
                .thenReturn(GetBucketLocationResponse.builder().locationConstraint("ap-south-1").build());

        S3Exception accessDenied = (S3Exception) S3Exception.builder()
                .statusCode(403)
                .awsErrorDetails(AwsErrorDetails.builder().errorCode("AccessDenied").build())
                .build();
        when(s3Client.getBucketTagging(any(GetBucketTaggingRequest.class))).thenThrow(accessDenied);

        ServiceDiscoveryResult result = connector.discover(region, "test-disc-s3-3");

        assertThat(result.status()).isEqualTo(DiscoveryStatus.PARTIAL);
        assertThat(result.resourceCount()).isEqualTo(1);
        assertThat(result.warnings()).hasSize(1);
        assertThat(result.warnings().get(0)).contains("tags omitted due to AccessDenied");
    }

    @Test
    @DisplayName("S3 connector handles root listBuckets failure returning FAILED")
    void shouldHandleRootListBucketsFailureWithSanitizedError() {
        String region = "ap-south-1";
        when(clientFactory.getS3Client(Region.of(region))).thenReturn(s3Client);

        S3Exception accessDenied = (S3Exception) S3Exception.builder()
                .statusCode(403)
                .awsErrorDetails(AwsErrorDetails.builder()
                        .errorCode("AccessDenied")
                        .errorMessage("Access Denied")
                        .build())
                .build();
        when(s3Client.listBuckets(any(ListBucketsRequest.class))).thenThrow(accessDenied);

        ServiceDiscoveryResult result = connector.discover(region, "test-disc-s3-4");

        assertThat(result.status()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(result.resourceCount()).isEqualTo(0);
        assertThat(result.errorCategory()).isEqualTo("ACCESS_DENIED");
    }
}
