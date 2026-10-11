package org.example.awsmetadatadiscoveryengine.config;

import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.core.retry.RetryMode;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.s3.S3Client;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Default implementation of {@link AwsClientFactory} utilizing AWS SDK v2
 * {@link DefaultCredentialsProvider} (supporting environment variables, IAM roles, ECS task roles,
 * AWS profiles) and maintaining a thread-safe, region-scoped client cache with clean lifecycle shutdown.
 */
@Component
public class DefaultAwsClientFactory implements AwsClientFactory {

    private static final Logger log = LoggerFactory.getLogger(DefaultAwsClientFactory.class);

    private final AwsProperties properties;
    private final AwsCredentialsProvider credentialsProvider;
    private final ConcurrentHashMap<Region, Ec2Client> ec2Clients = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<Region, S3Client> s3Clients = new ConcurrentHashMap<>();

    @Autowired
    public DefaultAwsClientFactory(AwsProperties properties) {
        this.properties = properties;
        this.credentialsProvider = DefaultCredentialsProvider.create();
    }

    // Constructor overload for custom credentials provider (e.g., testing)
    public DefaultAwsClientFactory(AwsProperties properties, AwsCredentialsProvider credentialsProvider) {
        this.properties = properties;
        this.credentialsProvider = credentialsProvider;
    }

    @Override
    public Ec2Client getEc2Client(Region region) {
        return ec2Clients.computeIfAbsent(region, this::buildEc2Client);
    }

    @Override
    public S3Client getS3Client(Region region) {
        return s3Clients.computeIfAbsent(region, this::buildS3Client);
    }

    private Ec2Client buildEc2Client(Region region) {
        log.info("Creating new Ec2Client for region: {}", region.id());
        return Ec2Client.builder()
                .region(region)
                .credentialsProvider(credentialsProvider)
                .overrideConfiguration(buildClientOverrideConfiguration())
                .httpClientBuilder(ApacheHttpClient.builder()
                        .connectionTimeout(Duration.ofSeconds(properties.getApiCallAttemptTimeoutSeconds()))
                        .socketTimeout(Duration.ofSeconds(properties.getApiCallTimeoutSeconds())))
                .build();
    }

    private S3Client buildS3Client(Region region) {
        log.info("Creating new S3Client for region: {}", region.id());
        return S3Client.builder()
                .region(region)
                .credentialsProvider(credentialsProvider)
                .overrideConfiguration(buildClientOverrideConfiguration())
                .httpClientBuilder(ApacheHttpClient.builder()
                        .connectionTimeout(Duration.ofSeconds(properties.getApiCallAttemptTimeoutSeconds()))
                        .socketTimeout(Duration.ofSeconds(properties.getApiCallTimeoutSeconds())))
                .build();
    }

    private ClientOverrideConfiguration buildClientOverrideConfiguration() {
        return ClientOverrideConfiguration.builder()
                .apiCallTimeout(Duration.ofSeconds(properties.getApiCallTimeoutSeconds()))
                .apiCallAttemptTimeout(Duration.ofSeconds(properties.getApiCallAttemptTimeoutSeconds()))
                .retryStrategy(RetryMode.STANDARD)
                .build();
    }

    @PreDestroy
    public void close() {
        log.info("Closing all cached AWS SDK clients during shutdown");
        ec2Clients.values().forEach(client -> {
            try {
                client.close();
            } catch (Exception e) {
                log.warn("Error closing Ec2Client", e);
            }
        });
        ec2Clients.clear();

        s3Clients.values().forEach(client -> {
            try {
                client.close();
            } catch (Exception e) {
                log.warn("Error closing S3Client", e);
            }
        });
        s3Clients.clear();
    }
}
