package org.example.awsmetadatadiscoveryengine.connector;

import org.example.awsmetadatadiscoveryengine.model.ServiceDiscoveryResult;
import org.example.awsmetadatadiscoveryengine.model.SupportedService;

/**
 * Common contract for AWS service-specific metadata discovery connectors.
 */
public interface AwsResourceConnector {

    /**
     * Identifies the AWS service handled by this connector.
     */
    SupportedService getSupportedService();

    /**
     * Executes metadata discovery for the specified region and correlation ID.
     *
     * @param region      the target AWS region identifier
     * @param discoveryId unique correlation/discovery ID
     * @return structured per-service discovery result
     */
    ServiceDiscoveryResult discover(String region, String discoveryId);
}
