# ComplyDP AWS Metadata Discovery Connector

A secure, testable, and production-minded Spring Boot 3.x connector designed to discover **AWS resource metadata only** (not customer data) across targeted AWS services. Built for enterprise compliance, privacy-by-design posture evaluation, and seamless extensibility.

---

## 1. Project Purpose and Scope

The **ComplyDP AWS Metadata Discovery Connector** queries customer AWS environments to extract technical infrastructure metadata required for compliance and governance assessments.

### In Scope
- **EC2 Instance Discovery**: Instance ID, instance type, state, region, AZ, network attachment IDs (VPC/subnet), architecture, platform, hypervisor, virtualization type, launch timestamp, root device attributes, EBS optimization flag, and approved operational tag keys (IP addresses and arbitrary tag values excluded by design).
- **S3 Bucket Discovery**: Bucket name, hosting region, creation timestamp, versioning status, server-side encryption, public access block configuration, and approved operational tag keys where permissions allow.
- **Region-scoped querying**: Targets specific AWS regions requested at runtime.
- **Pagination**: Fully consumes multi-page SDK responses.
- **Privacy Allowlisting**: Strict enforcement of approved attributes; rejection of customer payload content and secrets.
- **Resilient Execution**: Independent service failure handling yielding clear `SUCCESS`, `PARTIAL`, or `FAILED` outcomes.

### Out of Scope (By Design)
- Customer IP address harvesting (private and public IP addresses are excluded by design).
- Customer tag values by default (tag values excluded unless explicitly configured).
- Reading S3 object keys, contents, or payloads.
- Reading database rows, tables, or records.
- Reading user data (`UserData`), environment variables, credentials, or secrets.
- Active resource mutation (strictly read-only discovery).
- RDS and IAM discovery (deferred to future connector extensions).

---

## 2. Architecture & Package Responsibilities

The application follows clean architecture principles using constructor injection, immutable Java 17 records, and interface-driven connector isolation:

```
src/main/java/org/example/awsmetadatadiscoveryengine/
├── AwsMetadataDiscoveryEngineApplication.java   # Spring Boot entry point
├── config/
│   ├── AwsProperties.java                       # Configurable timeouts and retries
│   ├── AwsClientFactory.java                    # Factory interface for AWS SDK v2 clients
│   └── DefaultAwsClientFactory.java             # Region-cached clients, DefaultCredentialsProvider, lifecycle shutdown
├── connector/
│   ├── AwsResourceConnector.java                # Extensible connector contract
│   ├── Ec2Connector.java                        # AWS EC2 discovery with SDK paginators
│   └── S3Connector.java                         # AWS S3 discovery with region matching and tag inspection
├── controller/
│   └── DiscoveryController.java                 # POST /api/discover endpoint
├── exception/
│   ├── ApiExceptionHandler.java                 # Centralized, sanitized REST error handling
│   ├── AwsErrorSanitizer.java                   # Redacts provider errors into safe categories
│   └── DiscoveryValidationException.java        # Validation exception
├── model/
│   ├── DiscoveryRequest.java                    # Validated input DTO
│   ├── DiscoveryResponse.java                   # Aggregated response DTO with correlation ID
│   ├── DiscoveryStatus.java                     # SUCCESS | PARTIAL | FAILED
│   ├── ErrorResponse.java                       # Standardized client error contract
│   ├── ResourceMetadata.java                    # Normalized metadata record
│   ├── ServiceDiscoveryResult.java              # Per-service outcome and telemetry
│   └── SupportedService.java                    # Enum registry of supported AWS services
└── privacy/
    └── PrivacyGuard.java                        # Per-resource-type attribute allowlist & tag sanitizer
```

---

## 3. Prerequisites

- **Java**: OpenJDK 17 or higher
- **Maven**: 3.8+ (or use the included `./mvnw` wrapper)
- **Docker**: (Optional) 20.10+ for containerized builds
- **AWS Credentials**: (Optional for local live testing; not required for build/unit tests)

---

## 4. Local Setup & Testing

### Running Tests
All unit tests are fully isolated and **do not require AWS credentials or network connectivity**:
```bash
./mvnw clean test
```

### Running the Application Locally
```bash
./mvnw spring-boot:run
```
The server will start on port `8080` (or the port defined in `application.properties` / `SERVER_PORT`).

Health and liveness endpoints:
```bash
curl http://localhost:8080/actuator/health
```

---

## 5. Supported AWS Credential Sources

Authentication relies on the AWS SDK v2 `DefaultCredentialsProvider` chain. **No access keys or secrets are ever accepted via API requests or committed to code.**

The SDK resolves credentials in the following order:
1. **Java System Properties**: `aws.accessKeyId` and `aws.secretAccessKey`
2. **Environment Variables**: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN`
3. **Web Identity Token**: EKS service accounts or OpenID Connect (OIDC) federation
4. **Shared Credentials & Config Profile**: `~/.aws/credentials` and `~/.aws/config` (or `AWS_PROFILE`)
5. **ECS Container Credentials**: Task execution role provided via container URI
6. **EC2 Instance Metadata Service (IMDSv2)**: Attached IAM role on EC2 instance

---

## 6. Required IAM Permissions

For read-only discovery with minimal privilege, the calling IAM identity requires:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ComplyDPEc2Discovery",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ComplyDPS3MetadataDiscovery",
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketTagging"
      ],
      "Resource": "*"
    }
  ]
}
```

> **Note on Partial Permissions:** If `s3:GetBucketTagging` is denied, the connector does **not** fail the discovery. It includes the bucket, omits the tags, logs an operational warning, and sets the S3 status to `PARTIAL`.

---

## 7. REST API: `POST /api/discover`

### Request Format
```http
POST /api/discover HTTP/1.1
Content-Type: application/json
X-API-Key: <YOUR_API_KEY>

{
  "region": "ap-south-1",
  "services": ["EC2", "S3"]
}
```

> **API Authentication:** Protected `/api/**` endpoints require authentication via `X-API-Key` or `Authorization: Bearer <key>`. Missing or invalid keys return `401 Unauthorized`.

### Validation Rules
- `X-API-Key` or `Authorization: Bearer <token>`: Required when API security is enabled.
- `region`: Required; must follow AWS region naming conventions (e.g., `^[a-z]{2}(-[a-z0-9]+)+-[0-9]$`).
- `services`: Required; must contain at least one valid service name (`EC2`, `S3`) and maximum 10 services per request.
- Unknown services return `400 Bad Request`.

### Example Successful Response (`200 OK`)
```json
{
  "discoveryId": "8f88cb04-b529-41e9-a35b-1c5c56c70146",
  "status": "SUCCESS",
  "region": "ap-south-1",
  "totalResources": 2,
  "durationMs": 420,
  "serviceResults": {
    "EC2": {
      "service": "EC2",
      "status": "SUCCESS",
      "resourceCount": 1,
      "durationMs": 280,
      "resources": [
        {
          "service": "EC2",
          "resourceType": "ec2:instance",
          "resourceId": "i-091a2b3c4d5e6f7a8",
          "region": "ap-south-1",
          "arn": "arn:aws:ec2:ap-south-1::instance/i-091a2b3c4d5e6f7a8",
          "attributes": {
            "instanceId": "i-091a2b3c4d5e6f7a8",
            "instanceType": "t3.medium",
            "instanceState": "running",
            "region": "ap-south-1",
            "availabilityZone": "ap-south-1a",
            "vpcId": "vpc-0abc1234def567890",
            "subnetId": "subnet-0123456789abcdef0",
            "architecture": "x86_64",
            "virtualizationType": "hvm"
          },
          "tags": {
            "Name": "",
            "Environment": "",
            "Project": ""
          }
        }
      ],
      "warnings": []
    },
    "S3": {
      "service": "S3",
      "status": "SUCCESS",
      "resourceCount": 1,
      "durationMs": 140,
      "resources": [
        {
          "service": "S3",
          "resourceType": "s3:bucket",
          "resourceId": "complydp-audit-logs-ap-south-1",
          "region": "ap-south-1",
          "arn": "arn:aws:s3:::complydp-audit-logs-ap-south-1",
          "attributes": {
            "bucketName": "complydp-audit-logs-ap-south-1",
            "region": "ap-south-1",
            "creationDate": "2026-03-15T08:30:00Z"
          },
          "tags": {
            "Environment": "Production",
            "Owner": "SecOps"
          }
        }
      ],
      "warnings": []
    }
  },
  "warnings": []
}
```

---

## 8. Status Semantics

| Status | Condition | Meaning |
| :--- | :--- | :--- |
| `SUCCESS` | All requested services succeeded without permission or execution errors. | Complete inventory metadata captured. Discovered count of `0` is a valid `SUCCESS`. |
| `PARTIAL` | At least one requested service succeeded and one failed, OR optional bucket metadata could not be fetched due to partial IAM permissions. | Incomplete discovery inventory; inspect service-level `warnings` and `errorCategory`. |
| `FAILED` | All requested services failed, or request could not proceed due to invalid authentication or network limits. | No reliable metadata captured. |

---

## 9. Privacy-by-Design & Security Guardrails

1. **Explicit Per-Resource-Type Allowlisting**:
   - `ec2:instance`: Only standard lifecycle and architecture attributes are permitted (`instanceId`, `instanceType`, `instanceState`, `vpcId`, `subnetId`, `architecture`, `platform`, `hypervisor`, `virtualizationType`, `launchTime`, `rootDeviceType`, `rootDeviceName`, `ebsOptimized`). Private IPs (`privateIpAddress`) and public IPs (`publicIpAddress`) are excluded by default.
   - `s3:bucket`: Only bucket names, hosting regions, creation dates, versioning, and encryption attributes are captured.
   - Any unapproved or unknown field (e.g. `userData`, `adminPassword`, `customerPayload`, raw IP addresses) is dropped before serialization.
2. **Safe Operational Tag Filtering**:
   - Only recognized operational tag keys are permitted (`Name`, `Environment`, `Project`, `Owner`, `ManagedBy`, `CostCenter`, `Application`, `Tier`, `Service`, `Component`, `Department`, `Stage`, `Stack`, `Version`).
   - **Default behavior (`include-tag-values=false`)**: Tag values are excluded by default to protect customer confidentiality; approved tag keys are preserved with empty string values (`""`) so schema structure is maintained without disclosing sensitive operational text. Unapproved tag keys are dropped.
   - **When explicitly enabled (`include-tag-values=true`)**: Only structured operational identifiers matching `^[a-zA-Z0-9_.-]{1,64}$` are accepted. If a tag's value fails validation (e.g. arbitrary prose, whitespace, JSON, scripts, IP addresses, credentials, or sensitive keywords), **the entire tag is omitted** from the response. Unapproved tag keys also cause the whole tag to be omitted.
3. **API Key Authentication & Anti-Timing Protections**:
   - Protected `/api/**` endpoints validate incoming keys against `X-API-Key` or `Authorization: Bearer <key>` using constant-time string byte comparison (`MessageDigest.isEqual`) to eliminate timing side-channel attacks.
   - Authentication is enabled by default and fails safely if the secret in `COMPLYDP_SECURITY_API_KEY_SECRET` is absent or blank (HTTP 401).
   - Public monitoring paths (`/actuator/health`, `/actuator/info`) bypass API key requirements for cluster probes.
4. **OWASP HTTP Security Headers**:
   - `X-Content-Type-Options: nosniff` (prevents MIME sniffing)
   - `X-Frame-Options: DENY` (prevents clickjacking)
   - `Strict-Transport-Security: max-age=31536000; includeSubDomains` (enforces TLS)
   - `Cache-Control: no-store, no-cache, must-revalidate, max-age=0` (prevents intermediate caching of infrastructure metadata)
   - `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`
5. **Rate Limiting & Request Throttling**:
   - `RateLimitingFilter` executes at `@Order(2)` before `ApiKeyAuthFilter` (`@Order(3)`), enforcing IP-based rate limiting prior to authentication. Repeated failed authentication attempts are strictly throttled (HTTP 429 Too Many Requests).
   - For authenticated requests, a secondary per-key rate limit is enforced internally using a non-reversible SHA-256 identifier. Raw credentials, bearer tokens, and key hashes are never logged.
   - In-memory rate limits are per application instance. The filter employs automatic expiration cleanup and capacity bounds (10,000 entries) to prevent unbounded memory growth.
   - `X-Forwarded-For` is untrusted by default (`trust-forwarded-for=false`). It is only trusted if enabled AND the immediate connection originates from a configured trusted proxy in `trusted-proxies` (defaults to loopback: `127.0.0.1, 0:0:0:0:0:0:0:1, ::1`).
6. **Safe Operational Logging**:
   - Logs only non-sensitive execution facts: correlation ID (`discoveryId`), service name, region, elapsed time, resource count, and sanitized error categories.
   - Raw stack traces, AWS authorization tokens, API keys, credentials, and credential hashes are never logged or returned in error payloads.

---

## 10. Docker Build and Run

### Build Docker Image
```bash
docker build -t complydp/aws-metadata-discovery-connector:latest .
```

### Run Docker Container
Pass credentials securely via environment variables or volume-mounted AWS configuration:
```bash
docker run -d \
  --name aws-metadata-connector \
  -p 8080:8080 \
  -e AWS_REGION=ap-south-1 \
  -e COMPLYDP_SECURITY_API_KEY_SECRET=<YOUR_SECURE_API_KEY> \
  -v ~/.aws:/home/appuser/.aws:ro \
  complydp/aws-metadata-discovery-connector:latest
```

The container runs with a non-root system user (`appuser`, UID 1001) and includes an active container healthcheck.

---

## 11. Security Limitations & Production Readiness Notice

> **Prototype Notice:** This project demonstrates core security controls and privacy-by-design patterns. Before production deployment in enterprise environments, address the following security considerations:

1. **Per-Instance In-Memory Rate Limiting**: The sliding-window rate limiter is local per application instance (JVM memory). In horizontally scaled multi-pod/container deployments, each instance independently enforces limits; an external shared cache (such as Redis) or API Gateway throttle is required for cluster-wide enforcement.
2. **Key Lifecycle & Rotation**: API keys are symmetric secrets loaded at startup from `COMPLYDP_SECURITY_API_KEY_SECRET`. Production architectures should integrate with dynamic secret managers (AWS Secrets Manager, HashiCorp Vault) or mTLS / OAuth 2.0 JWT bearer authentication.
3. **Reverse Proxy / Ingress Trust**: Forwarded client IP headers (`X-Forwarded-For`) are untrusted by default (`trust-forwarded-for=false`). When deploying behind an AWS ALB or Ingress Controller, configure `complydp.security.rate-limit.trust-forwarded-for=true` and specify CIDRs/IPs in `trusted-proxies` (matching the actual proxy topology).
4. **Transport Security (TLS)**: HSTS headers are enabled, but TLS termination should be provided by an ingress gateway or reverse proxy with valid CA certificates.
5. **Cross-Account & Multi-Region Scanning**: Expanding beyond single-region discovery to AWS Organizations with cross-account STS `AssumeRole` remains an area for future platform integration.
