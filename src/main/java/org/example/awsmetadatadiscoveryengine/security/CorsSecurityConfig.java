package org.example.awsmetadatadiscoveryengine.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

/**
 * Cross-Origin Resource Sharing (CORS) security configuration.
 * Restricts cross-origin requests to explicitly configured trusted origins.
 */
@Configuration
public class CorsSecurityConfig implements WebMvcConfigurer {

    private final SecurityProperties securityProperties;

    public CorsSecurityConfig(@org.springframework.beans.factory.annotation.Autowired(required = false) SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        if (securityProperties == null) {
            return;
        }
        List<String> origins = securityProperties.getCors().getAllowedOrigins();
        if (origins == null || origins.isEmpty()) {
            return;
        }

        registry.addMapping("/api/**")
                .allowedOrigins(origins.toArray(String[]::new))
                .allowedMethods(securityProperties.getCors().getAllowedMethods().toArray(String[]::new))
                .allowedHeaders(securityProperties.getCors().getAllowedHeaders().toArray(String[]::new))
                .maxAge(securityProperties.getCors().getMaxAgeSeconds());
    }
}
