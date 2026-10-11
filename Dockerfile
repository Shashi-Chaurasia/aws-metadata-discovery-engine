# Multi-stage Dockerfile for ComplyDP AWS Metadata Discovery Connector
# Build stage
FROM eclipse-temurin:17-jdk-jammy AS builder
WORKDIR /workspace

# Copy build configuration and wrappers
COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .

# Download dependencies (leveraging layer cache)
RUN ./mvnw dependency:go-offline -B || true

# Copy source code and build executable jar
COPY src src
RUN ./mvnw clean package -DskipTests -B

# Runtime stage
FROM eclipse-temurin:17-jre-jammy
WORKDIR /app

# Create non-root system user for security
RUN groupadd -r appgroup && useradd -r -g appgroup -u 1001 appuser

# Copy jar from builder
COPY --from=builder /workspace/target/*.jar app.jar
RUN chown -R appuser:appgroup /app

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/actuator/health || exit 1

ENTRYPOINT ["java", "-XX:+UseContainerSupport", "-XX:MaxRAMPercentage=75.0", "-jar", "app.jar"]
