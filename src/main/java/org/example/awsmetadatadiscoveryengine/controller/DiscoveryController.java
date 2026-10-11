package org.example.awsmetadatadiscoveryengine.controller;

import jakarta.validation.Valid;
import org.example.awsmetadatadiscoveryengine.model.DiscoveryRequest;
import org.example.awsmetadatadiscoveryengine.model.DiscoveryResponse;
import org.example.awsmetadatadiscoveryengine.service.DiscoveryService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller exposing endpoints for AWS metadata discovery.
 */
@RestController
@RequestMapping("/api")
public class DiscoveryController {

    private static final Logger log = LoggerFactory.getLogger(DiscoveryController.class);

    private final DiscoveryService discoveryService;

    public DiscoveryController(DiscoveryService discoveryService) {
        this.discoveryService = discoveryService;
    }

    /**
     * Discovers metadata for specified AWS services in a region.
     *
     * @param request validated discovery parameters
     * @return structured metadata discovery response
     */
    @PostMapping("/discover")
    public ResponseEntity<DiscoveryResponse> discover(@Valid @RequestBody DiscoveryRequest request) {
        log.info("Received discovery request for region: {}, services: {}", request.region(), request.services());
        DiscoveryResponse response = discoveryService.discover(request);
        return ResponseEntity.ok(response);
    }
}
