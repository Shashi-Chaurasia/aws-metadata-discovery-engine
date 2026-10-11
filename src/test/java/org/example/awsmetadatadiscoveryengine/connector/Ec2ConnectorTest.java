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
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.*;
import software.amazon.awssdk.services.ec2.paginators.DescribeInstancesIterable;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class Ec2ConnectorTest {

    @Mock
    private AwsClientFactory clientFactory;

    @Mock
    private Ec2Client ec2Client;

    @Mock
    private DescribeInstancesIterable paginator;

    private PrivacyGuard privacyGuard;
    private Ec2Connector connector;

    @BeforeEach
    void setUp() {
        privacyGuard = new PrivacyGuard();
        connector = new Ec2Connector(clientFactory, privacyGuard);
    }

    @Test
    @DisplayName("EC2 connector maps multiple instances into normalized metadata")
    void shouldMapMultipleInstancesIntoNormalizedMetadata() {
        String region = "ap-south-1";
        when(clientFactory.getEc2Client(Region.of(region))).thenReturn(ec2Client);

        Instance instance1 = Instance.builder()
                .instanceId("i-001")
                .instanceType(InstanceType.T3_MICRO)
                .state(InstanceState.builder().name(InstanceStateName.RUNNING).build())
                .placement(Placement.builder().availabilityZone("ap-south-1a").build())
                .vpcId("vpc-123")
                .subnetId("subnet-456")
                .launchTime(Instant.parse("2026-01-01T10:00:00Z"))
                .tags(Tag.builder().key("Name").value("web-server-1").build(),
                        Tag.builder().key("Environment").value("Production").build())
                .build();

        Instance instance2 = Instance.builder()
                .instanceId("i-002")
                .instanceType(InstanceType.C5_LARGE)
                .state(InstanceState.builder().name(InstanceStateName.STOPPED).build())
                .placement(Placement.builder().availabilityZone("ap-south-1b").build())
                .vpcId("vpc-123")
                .subnetId("subnet-789")
                .tags(Tag.builder().key("Name").value("batch-worker").build())
                .build();

        DescribeInstancesResponse response = DescribeInstancesResponse.builder()
                .reservations(
                        Reservation.builder().instances(instance1).build(),
                        Reservation.builder().instances(instance2).build()
                )
                .build();

        when(paginator.iterator()).thenReturn(List.of(response).iterator());
        when(ec2Client.describeInstancesPaginator(any(DescribeInstancesRequest.class))).thenReturn(paginator);

        ServiceDiscoveryResult result = connector.discover(region, "test-disc-1");

        assertThat(result.status()).isEqualTo(DiscoveryStatus.SUCCESS);
        assertThat(result.resourceCount()).isEqualTo(2);
        assertThat(result.resources()).hasSize(2);

        ResourceMetadata res1 = result.resources().get(0);
        assertThat(res1.resourceId()).isEqualTo("i-001");
        assertThat(res1.resourceType()).isEqualTo("ec2:instance");
        assertThat(res1.region()).isEqualTo("ap-south-1");
        assertThat(res1.attributes())
                .containsEntry("instanceType", "t3.micro")
                .containsEntry("instanceState", "running")
                .containsEntry("vpcId", "vpc-123")
                .containsEntry("availabilityZone", "ap-south-1a");
        assertThat(res1.tags())
                .containsEntry("Name", "")
                .containsEntry("Environment", "");

        ResourceMetadata res2 = result.resources().get(1);
        assertThat(res2.resourceId()).isEqualTo("i-002");
        assertThat(res2.attributes()).containsEntry("instanceState", "stopped");
    }

    @Test
    @DisplayName("EC2 empty result is successful with resource count 0")
    void shouldReturnSuccessOnEmptyEc2Instances() {
        String region = "us-east-1";
        when(clientFactory.getEc2Client(Region.of(region))).thenReturn(ec2Client);

        DescribeInstancesResponse emptyResponse = DescribeInstancesResponse.builder()
                .reservations(List.of())
                .build();

        when(paginator.iterator()).thenReturn(List.of(emptyResponse).iterator());
        when(ec2Client.describeInstancesPaginator(any(DescribeInstancesRequest.class))).thenReturn(paginator);

        ServiceDiscoveryResult result = connector.discover(region, "test-disc-2");

        assertThat(result.status()).isEqualTo(DiscoveryStatus.SUCCESS);
        assertThat(result.resourceCount()).isEqualTo(0);
        assertThat(result.resources()).isEmpty();
    }

    @Test
    @DisplayName("EC2 paginator consumes multiple pages and aggregates all instances")
    void shouldHandleMultiPagePaginationCorrectly() {
        String region = "eu-west-1";
        when(clientFactory.getEc2Client(Region.of(region))).thenReturn(ec2Client);

        Instance inst1 = Instance.builder().instanceId("i-page-1").build();
        DescribeInstancesResponse page1 = DescribeInstancesResponse.builder()
                .reservations(Reservation.builder().instances(inst1).build())
                .build();

        Instance inst2 = Instance.builder().instanceId("i-page-2").build();
        DescribeInstancesResponse page2 = DescribeInstancesResponse.builder()
                .reservations(Reservation.builder().instances(inst2).build())
                .build();

        when(paginator.iterator()).thenReturn(List.of(page1, page2).iterator());
        when(ec2Client.describeInstancesPaginator(any(DescribeInstancesRequest.class))).thenReturn(paginator);

        ServiceDiscoveryResult result = connector.discover(region, "test-disc-3");

        assertThat(result.status()).isEqualTo(DiscoveryStatus.SUCCESS);
        assertThat(result.resourceCount()).isEqualTo(2);
        assertThat(result.resources()).extracting(ResourceMetadata::resourceId)
                .containsExactly("i-page-1", "i-page-2");
    }

    @Test
    @DisplayName("EC2 error returns FAILED with sanitized error category and message")
    void shouldHandleEc2ExceptionAndReturnFailureWithSanitizedError() {
        String region = "ap-south-1";
        when(clientFactory.getEc2Client(Region.of(region))).thenReturn(ec2Client);

        Ec2Exception accessDenied = (Ec2Exception) Ec2Exception.builder()
                .statusCode(403)
                .awsErrorDetails(AwsErrorDetails.builder()
                        .errorCode("UnauthorizedOperation")
                        .errorMessage("You are not authorized to perform this operation.")
                        .build())
                .build();

        when(ec2Client.describeInstancesPaginator(any(DescribeInstancesRequest.class))).thenThrow(accessDenied);

        ServiceDiscoveryResult result = connector.discover(region, "test-disc-4");

        assertThat(result.status()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(result.resourceCount()).isEqualTo(0);
        assertThat(result.errorCategory()).isEqualTo("ACCESS_DENIED");
        assertThat(result.errorMessage()).contains("Check IAM permissions");
    }
}
