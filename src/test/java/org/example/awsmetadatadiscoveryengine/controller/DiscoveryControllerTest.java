package org.example.awsmetadatadiscoveryengine.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.awsmetadatadiscoveryengine.exception.ApiExceptionHandler;
import org.example.awsmetadatadiscoveryengine.exception.DiscoveryValidationException;
import org.example.awsmetadatadiscoveryengine.model.DiscoveryRequest;
import org.example.awsmetadatadiscoveryengine.model.DiscoveryResponse;
import org.example.awsmetadatadiscoveryengine.model.DiscoveryStatus;
import org.example.awsmetadatadiscoveryengine.service.DiscoveryService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.example.awsmetadatadiscoveryengine.security.SecurityProperties;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;

import static org.hamcrest.Matchers.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(DiscoveryController.class)
@Import({ApiExceptionHandler.class, SecurityProperties.class})
class DiscoveryControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private DiscoveryService discoveryService;

    @Test
    @DisplayName("POST /api/discover returns 200 OK for valid request")
    void shouldReturnOkForValidDiscoveryRequest() throws Exception {
        DiscoveryResponse mockResponse = new DiscoveryResponse(
                "test-uuid-1234",
                DiscoveryStatus.SUCCESS,
                "ap-south-1",
                5,
                120L,
                Map.of(),
                List.of()
        );

        when(discoveryService.discover(any(DiscoveryRequest.class))).thenReturn(mockResponse);

        DiscoveryRequest request = new DiscoveryRequest("ap-south-1", List.of("EC2", "S3"));

        mockMvc.perform(post("/api/discover")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.discoveryId").value("test-uuid-1234"))
                .andExpect(jsonPath("$.status").value("SUCCESS"))
                .andExpect(jsonPath("$.region").value("ap-south-1"))
                .andExpect(jsonPath("$.totalResources").value(5));
    }

    @Test
    @DisplayName("POST /api/discover returns 400 when region is missing")
    void shouldReturnBadRequestWhenRegionIsMissing() throws Exception {
        String payload = """
                {
                    "services": ["EC2"]
                }
                """;

        mockMvc.perform(post("/api/discover")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Validation Failed"))
                .andExpect(jsonPath("$.details", hasItem(containsString("AWS region is required"))))
                .andExpect(jsonPath("$.stackTrace").doesNotExist());
    }

    @Test
    @DisplayName("POST /api/discover returns 400 when region format is invalid")
    void shouldReturnBadRequestWhenRegionFormatIsInvalid() throws Exception {
        DiscoveryRequest request = new DiscoveryRequest("INVALID_REGION_123", List.of("EC2"));

        mockMvc.perform(post("/api/discover")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Validation Failed"))
                .andExpect(jsonPath("$.details", hasItem(containsString("Invalid AWS region identifier format"))));
    }

    @Test
    @DisplayName("POST /api/discover returns 400 when services list is empty")
    void shouldReturnBadRequestWhenServicesListIsEmpty() throws Exception {
        String payload = """
                {
                    "region": "us-east-1",
                    "services": []
                }
                """;

        mockMvc.perform(post("/api/discover")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Validation Failed"))
                .andExpect(jsonPath("$.details", hasItem(containsString("At least one service must be specified"))));
    }

    @Test
    @DisplayName("POST /api/discover returns 400 when unknown service is specified")
    void shouldReturnBadRequestWhenUnknownServiceIsSpecified() throws Exception {
        when(discoveryService.discover(any(DiscoveryRequest.class)))
                .thenThrow(new DiscoveryValidationException("Unsupported AWS service(s): [UNKNOWN_SVC]. Supported services: [EC2, S3]"));

        DiscoveryRequest request = new DiscoveryRequest("ap-south-1", List.of("UNKNOWN_SVC"));

        mockMvc.perform(post("/api/discover")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value(containsString("Unsupported AWS service(s): [UNKNOWN_SVC]")))
                .andExpect(jsonPath("$.stackTrace").doesNotExist())
                .andExpect(jsonPath("$.credentials").doesNotExist());
    }

    @Test
    @DisplayName("POST /api/discover returns 400 on malformed JSON payload")
    void shouldReturnBadRequestOnMalformedJson() throws Exception {
        String badJson = "{ invalid-json }";

        mockMvc.perform(post("/api/discover")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(badJson))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").value("Malformed or unreadable JSON request body"));
    }

    @Test
    @DisplayName("POST /api/discover returns 400 when services list exceeds maximum size (10)")
    void shouldReturnBadRequestWhenServicesListExceedsMaximumSize() throws Exception {
        List<String> tooManyServices = List.of(
                "EC2", "S3", "EC2", "S3", "EC2", "S3", "EC2", "S3", "EC2", "S3", "EC2"
        );
        DiscoveryRequest request = new DiscoveryRequest("ap-south-1", tooManyServices);

        mockMvc.perform(post("/api/discover")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.details", hasItem(containsString("Maximum 10 services"))));
    }
}
