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
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.DescribeInstancesRequest;
import software.amazon.awssdk.services.ec2.model.DescribeInstancesResponse;
import software.amazon.awssdk.services.ec2.model.Instance;
import software.amazon.awssdk.services.ec2.model.Reservation;
import software.amazon.awssdk.services.ec2.model.Tag;
import software.amazon.awssdk.services.ec2.paginators.DescribeInstancesIterable;

import java.util.*;

/**
 * Metadata discovery connector for AWS EC2.
 * Discovers EC2 instance metadata with SDK pagination, normalizes fields,
 * and enforces privacy-by-design allowlists.
 */
@Component
public class Ec2Connector implements AwsResourceConnector {

    private static final Logger log = LoggerFactory.getLogger(Ec2Connector.class);
    private static final String RESOURCE_TYPE = "ec2:instance";

    private final AwsClientFactory clientFactory;
    private final PrivacyGuard privacyGuard;

    public Ec2Connector(AwsClientFactory clientFactory, PrivacyGuard privacyGuard) {
        this.clientFactory = clientFactory;
        this.privacyGuard = privacyGuard;
    }

    @Override
    public SupportedService getSupportedService() {
        return SupportedService.EC2;
    }

    @Override
    public ServiceDiscoveryResult discover(String regionName, String discoveryId) {
        long startTime = System.currentTimeMillis();
        Region awsRegion = Region.of(regionName);
        List<ResourceMetadata> discovered = new ArrayList<>();
        List<String> warnings = new ArrayList<>();

        log.info("[discoveryId={}] Starting EC2 discovery in region: {}", discoveryId, regionName);

        try {
            Ec2Client ec2Client = clientFactory.getEc2Client(awsRegion);
            DescribeInstancesRequest request = DescribeInstancesRequest.builder().build();

            DescribeInstancesIterable paginator = ec2Client.describeInstancesPaginator(request);
            int pageCount = 0;

            for (DescribeInstancesResponse response : paginator) {
                pageCount++;
                if (response.hasReservations()) {
                    for (Reservation reservation : response.reservations()) {
                        if (reservation.hasInstances()) {
                            for (Instance instance : reservation.instances()) {
                                ResourceMetadata rawMetadata = mapInstanceToMetadata(instance, regionName);
                                ResourceMetadata sanitized = privacyGuard.filter(rawMetadata);
                                discovered.add(sanitized);
                            }
                        }
                    }
                }
            }

            long duration = System.currentTimeMillis() - startTime;
            log.info("[discoveryId={}] Completed EC2 discovery in {}ms across {} pages. Found {} instances.",
                    discoveryId, duration, pageCount, discovered.size());

            return ServiceDiscoveryResult.success(SupportedService.EC2.name(), discovered, warnings, duration);

        } catch (Exception e) {
            long duration = System.currentTimeMillis() - startTime;
            AwsErrorSanitizer.SanitizedError sanitized = AwsErrorSanitizer.sanitize(e, SupportedService.EC2.name());

            log.warn("[discoveryId={}] EC2 discovery failed: category={}, safeMessage={}",
                    discoveryId, sanitized.category(), sanitized.safeMessage());

            return ServiceDiscoveryResult.failure(
                    SupportedService.EC2.name(),
                    sanitized.category(),
                    sanitized.safeMessage(),
                    warnings,
                    duration
            );
        }
    }

    private ResourceMetadata mapInstanceToMetadata(Instance instance, String region) {
        Map<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("instanceId", instance.instanceId());
        attributes.put("instanceType", instance.instanceTypeAsString());
        attributes.put("instanceState", instance.state() != null ? instance.state().nameAsString() : "unknown");
        attributes.put("region", region);

        if (instance.placement() != null && instance.placement().availabilityZone() != null) {
            attributes.put("availabilityZone", instance.placement().availabilityZone());
        }
        if (instance.vpcId() != null) {
            attributes.put("vpcId", instance.vpcId());
        }
        if (instance.subnetId() != null) {
            attributes.put("subnetId", instance.subnetId());
        }
        if (instance.architectureAsString() != null) {
            attributes.put("architecture", instance.architectureAsString());
        }
        if (instance.platformAsString() != null) {
            attributes.put("platform", instance.platformAsString());
        }
        if (instance.hypervisorAsString() != null) {
            attributes.put("hypervisor", instance.hypervisorAsString());
        }
        if (instance.virtualizationTypeAsString() != null) {
            attributes.put("virtualizationType", instance.virtualizationTypeAsString());
        }
        if (instance.launchTime() != null) {
            attributes.put("launchTime", instance.launchTime().toString());
        }
        if (instance.rootDeviceTypeAsString() != null) {
            attributes.put("rootDeviceType", instance.rootDeviceTypeAsString());
        }
        if (instance.rootDeviceName() != null) {
            attributes.put("rootDeviceName", instance.rootDeviceName());
        }
        if (instance.ebsOptimized() != null) {
            attributes.put("ebsOptimized", instance.ebsOptimized());
        }

        Map<String, String> tags = new LinkedHashMap<>();
        if (instance.hasTags()) {
            for (Tag tag : instance.tags()) {
                if (tag.key() != null) {
                    tags.put(tag.key(), tag.value() != null ? tag.value() : "");
                }
            }
        }

        return ResourceMetadata.builder()
                .service(SupportedService.EC2.name())
                .resourceType(RESOURCE_TYPE)
                .resourceId(instance.instanceId())
                .region(region)
                .arn("arn:aws:ec2:" + region + "::instance/" + instance.instanceId())
                .attributes(attributes)
                .tags(tags)
                .build();
    }
}
