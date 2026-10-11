package org.example.awsmetadatadiscoveryengine.config;

import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.s3.S3Client;

/**
 * Factory for creating or retrieving region-scoped AWS service clients.
 */
public interface AwsClientFactory {

    /**
     * Obtains an Ec2Client configured for the specified AWS region.
     *
     * @param region the target AWS region
     * @return Ec2Client instance
     */
    Ec2Client getEc2Client(Region region);

    /**
     * Obtains an S3Client configured for the specified AWS region.
     *
     * @param region the target AWS region
     * @return S3Client instance
     */
    S3Client getS3Client(Region region);
}
