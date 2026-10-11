package org.example.awsmetadatadiscoveryengine.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.List;

/**
 * Incoming discovery request payload.
 */
public record DiscoveryRequest(
        @NotBlank(message = "AWS region is required")
        @Pattern(
                regexp = "^[a-z]{2}(-[a-z0-9]+)+-[0-9]$",
                message = "Invalid AWS region identifier format (e.g. 'us-east-1', 'ap-south-1')"
        )
        String region,

        @NotEmpty(message = "At least one service must be specified")
        @Size(max = 10, message = "Maximum 10 services can be requested per discovery operation")
        List<String> services
) {
}
