package org.example.awsmetadatadiscoveryengine.service;

import org.example.awsmetadatadiscoveryengine.connector.AwsResourceConnector;
import org.example.awsmetadatadiscoveryengine.exception.DiscoveryValidationException;
import org.example.awsmetadatadiscoveryengine.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * Core orchestrator for AWS metadata discovery.
 * Dispatches requests to registered service connectors, aggregates results,
 * enforces overall outcome semantics (SUCCESS / PARTIAL / FAILED), and safely logs execution facts.
 */
@Service
public class DiscoveryService {

    private static final Logger log = LoggerFactory.getLogger(DiscoveryService.class);
    private static final String MDC_DISCOVERY_ID = "discoveryId";

    private final Map<SupportedService, AwsResourceConnector> connectors = new EnumMap<>(SupportedService.class);

    public DiscoveryService(List<AwsResourceConnector> connectorList) {
        if (connectorList != null) {
            for (AwsResourceConnector connector : connectorList) {
                this.connectors.put(connector.getSupportedService(), connector);
            }
        }
    }

    /**
     * Executes metadata discovery according to the provided request.
     *
     * @param request validated discovery request
     * @return aggregated DiscoveryResponse
     */
    public DiscoveryResponse discover(DiscoveryRequest request) {
        String discoveryId = UUID.randomUUID().toString();
        long totalStartTime = System.currentTimeMillis();

        MDC.put(MDC_DISCOVERY_ID, discoveryId);
        try {
            validateRequest(request);

            // Deduplicate and resolve services
            Set<SupportedService> targetServices = resolveServices(request.services());
            log.info("Initiating discovery for region: {}, services: {}", request.region(), targetServices);

            Map<String, ServiceDiscoveryResult> serviceResults = new LinkedHashMap<>();
            List<String> combinedWarnings = new ArrayList<>();
            int totalResources = 0;
            int successCount = 0;
            int partialCount = 0;
            int failureCount = 0;

            for (SupportedService service : targetServices) {
                AwsResourceConnector connector = connectors.get(service);
                if (connector == null) {
                    throw new IllegalStateException("No registered connector found for service: " + service);
                }

                ServiceDiscoveryResult result = connector.discover(request.region(), discoveryId);
                serviceResults.put(service.name(), result);
                totalResources += result.resourceCount();
                combinedWarnings.addAll(result.warnings());

                switch (result.status()) {
                    case SUCCESS -> successCount++;
                    case PARTIAL -> partialCount++;
                    case FAILED -> failureCount++;
                }
            }

            DiscoveryStatus overallStatus = determineOverallStatus(successCount, partialCount, failureCount);
            long totalDuration = System.currentTimeMillis() - totalStartTime;

            log.info("Completed discovery: status={}, totalResources={}, duration={}ms (success={}, partial={}, failed={})",
                    overallStatus, totalResources, totalDuration, successCount, partialCount, failureCount);

            return new DiscoveryResponse(
                    discoveryId,
                    overallStatus,
                    request.region(),
                    totalResources,
                    totalDuration,
                    serviceResults,
                    combinedWarnings
            );

        } finally {
            MDC.remove(MDC_DISCOVERY_ID);
        }
    }

    private void validateRequest(DiscoveryRequest request) {
        if (request == null) {
            throw new DiscoveryValidationException("Discovery request body cannot be null");
        }
        if (request.region() == null || request.region().isBlank()) {
            throw new DiscoveryValidationException("AWS region must not be blank");
        }
        if (request.services() == null || request.services().isEmpty()) {
            throw new DiscoveryValidationException("At least one AWS service must be specified");
        }
    }

    private Set<SupportedService> resolveServices(List<String> requestedServiceNames) {
        Set<SupportedService> resolved = new LinkedHashSet<>();
        List<String> invalidServices = new ArrayList<>();

        for (String name : requestedServiceNames) {
            if (name == null || name.isBlank()) {
                invalidServices.add("<empty>");
                continue;
            }
            Optional<SupportedService> opt = SupportedService.fromStringOptional(name);
            if (opt.isPresent()) {
                resolved.add(opt.get());
            } else {
                invalidServices.add(name);
            }
        }

        if (!invalidServices.isEmpty()) {
            throw new DiscoveryValidationException(
                    "Unsupported AWS service(s): " + invalidServices + ". Supported services: " + Arrays.toString(SupportedService.values())
            );
        }

        return resolved;
    }

    private DiscoveryStatus determineOverallStatus(int successCount, int partialCount, int failureCount) {
        if (partialCount > 0) {
            return DiscoveryStatus.PARTIAL;
        }
        if (successCount > 0 && failureCount > 0) {
            return DiscoveryStatus.PARTIAL;
        }
        if (successCount > 0 && failureCount == 0) {
            return DiscoveryStatus.SUCCESS;
        }
        return DiscoveryStatus.FAILED;
    }
}
