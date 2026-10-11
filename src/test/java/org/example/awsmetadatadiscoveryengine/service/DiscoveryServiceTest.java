package org.example.awsmetadatadiscoveryengine.service;

import org.example.awsmetadatadiscoveryengine.connector.AwsResourceConnector;
import org.example.awsmetadatadiscoveryengine.exception.DiscoveryValidationException;
import org.example.awsmetadatadiscoveryengine.model.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DiscoveryServiceTest {

    @Mock
    private AwsResourceConnector ec2Connector;

    @Mock
    private AwsResourceConnector s3Connector;

    private DiscoveryService discoveryService;

    @BeforeEach
    void setUp() {
        when(ec2Connector.getSupportedService()).thenReturn(SupportedService.EC2);
        when(s3Connector.getSupportedService()).thenReturn(SupportedService.S3);

        discoveryService = new DiscoveryService(List.of(ec2Connector, s3Connector));
    }

    @Test
    @DisplayName("Overall status is SUCCESS when all requested services succeed")
    void shouldReturnSuccessWhenAllServicesSucceed() {
        ResourceMetadata ec2Resource = ResourceMetadata.builder()
                .service("EC2").resourceType("ec2:instance").resourceId("i-123").region("ap-south-1")
                .attributes(Map.of("instanceType", "t3.micro")).build();

        ResourceMetadata s3Resource = ResourceMetadata.builder()
                .service("S3").resourceType("s3:bucket").resourceId("b-123").region("ap-south-1")
                .attributes(Map.of("bucketName", "b-123")).build();

        when(ec2Connector.discover(anyString(), anyString()))
                .thenReturn(ServiceDiscoveryResult.success("EC2", List.of(ec2Resource), List.of(), 100));
        when(s3Connector.discover(anyString(), anyString()))
                .thenReturn(ServiceDiscoveryResult.success("S3", List.of(s3Resource), List.of(), 150));

        DiscoveryRequest request = new DiscoveryRequest("ap-south-1", List.of("EC2", "S3"));
        DiscoveryResponse response = discoveryService.discover(request);

        assertThat(response.status()).isEqualTo(DiscoveryStatus.SUCCESS);
        assertThat(response.totalResources()).isEqualTo(2);
        assertThat(response.serviceResults()).containsKeys("EC2", "S3");
        assertThat(response.discoveryId()).isNotBlank();
        assertThat(response.region()).isEqualTo("ap-south-1");
    }

    @Test
    @DisplayName("Overall status is PARTIAL when one service succeeds and another fails")
    void shouldReturnPartialWhenOneServiceSucceedsAndOneFails() {
        ResourceMetadata ec2Resource = ResourceMetadata.builder()
                .service("EC2").resourceType("ec2:instance").resourceId("i-123").region("ap-south-1")
                .attributes(Map.of()).build();

        when(ec2Connector.discover(anyString(), anyString()))
                .thenReturn(ServiceDiscoveryResult.success("EC2", List.of(ec2Resource), List.of(), 80));
        when(s3Connector.discover(anyString(), anyString()))
                .thenReturn(ServiceDiscoveryResult.failure("S3", "ACCESS_DENIED", "Access Denied", List.of(), 90));

        DiscoveryRequest request = new DiscoveryRequest("ap-south-1", List.of("EC2", "S3"));
        DiscoveryResponse response = discoveryService.discover(request);

        assertThat(response.status()).isEqualTo(DiscoveryStatus.PARTIAL);
        assertThat(response.totalResources()).isEqualTo(1);
        assertThat(response.serviceResults().get("EC2").status()).isEqualTo(DiscoveryStatus.SUCCESS);
        assertThat(response.serviceResults().get("S3").status()).isEqualTo(DiscoveryStatus.FAILED);
    }

    @Test
    @DisplayName("Overall status is PARTIAL when a service reports partial result")
    void shouldReturnPartialWhenServiceReportsPartialResult() {
        ResourceMetadata s3Resource = ResourceMetadata.builder()
                .service("S3").resourceType("s3:bucket").resourceId("b-123").region("ap-south-1")
                .attributes(Map.of()).build();

        when(s3Connector.discover(anyString(), anyString()))
                .thenReturn(ServiceDiscoveryResult.partial("S3", List.of(s3Resource), List.of("Bucket tags missing"), "ACCESS_DENIED", "Tags restricted", 50));

        DiscoveryRequest request = new DiscoveryRequest("ap-south-1", List.of("S3"));
        DiscoveryResponse response = discoveryService.discover(request);

        assertThat(response.status()).isEqualTo(DiscoveryStatus.PARTIAL);
        assertThat(response.totalResources()).isEqualTo(1);
        assertThat(response.warnings()).contains("Bucket tags missing");
    }

    @Test
    @DisplayName("Overall status is FAILED when all requested services fail")
    void shouldReturnFailedWhenAllServicesFail() {
        when(ec2Connector.discover(anyString(), anyString()))
                .thenReturn(ServiceDiscoveryResult.failure("EC2", "ACCESS_DENIED", "EC2 denied", List.of(), 50));
        when(s3Connector.discover(anyString(), anyString()))
                .thenReturn(ServiceDiscoveryResult.failure("S3", "ACCESS_DENIED", "S3 denied", List.of(), 60));

        DiscoveryRequest request = new DiscoveryRequest("ap-south-1", List.of("EC2", "S3"));
        DiscoveryResponse response = discoveryService.discover(request);

        assertThat(response.status()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(response.totalResources()).isEqualTo(0);
    }

    @Test
    @DisplayName("Overall status is SUCCESS when service succeeds with zero resources")
    void shouldReturnSuccessWhenZeroResourcesFound() {
        when(ec2Connector.discover(anyString(), anyString()))
                .thenReturn(ServiceDiscoveryResult.success("EC2", List.of(), List.of(), 40));

        DiscoveryRequest request = new DiscoveryRequest("ap-south-1", List.of("EC2"));
        DiscoveryResponse response = discoveryService.discover(request);

        assertThat(response.status()).isEqualTo(DiscoveryStatus.SUCCESS);
        assertThat(response.totalResources()).isEqualTo(0);
    }

    @Test
    @DisplayName("Throws DiscoveryValidationException when unknown service name is requested")
    void shouldThrowValidationExceptionOnUnknownService() {
        DiscoveryRequest request = new DiscoveryRequest("ap-south-1", List.of("EC2", "INVALID_SERVICE"));

        assertThatThrownBy(() -> discoveryService.discover(request))
                .isInstanceOf(DiscoveryValidationException.class)
                .hasMessageContaining("Unsupported AWS service(s): [INVALID_SERVICE]");
    }

    @Test
    @DisplayName("Throws DiscoveryValidationException when region is blank")
    void shouldThrowValidationExceptionOnBlankRegion() {
        DiscoveryRequest request = new DiscoveryRequest("", List.of("EC2"));

        assertThatThrownBy(() -> discoveryService.discover(request))
                .isInstanceOf(DiscoveryValidationException.class)
                .hasMessageContaining("AWS region must not be blank");
    }
}
