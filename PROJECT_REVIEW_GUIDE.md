# AWS Metadata Discovery Engine — Reviewer Guide

> **Purpose:** A concise technical guide for reviewers evaluating this project’s design, behavior, security controls, and current scope.
>
> **Current implementation:** Java 17, Spring Boot 3, AWS SDK for Java v2. Implemented discovery connectors: Amazon EC2 and Amazon S3. The application runs locally and exposes a REST API.

## 1. Executive summary

The AWS Metadata Discovery Engine is a small, extensible service that queries selected AWS APIs and returns normalized infrastructure metadata through a REST endpoint. It is designed around a privacy-first principle: collect only explicitly approved metadata fields, avoid reading customer payloads, and keep tag values excluded by default.

The application currently supports EC2 instance discovery and S3 bucket discovery. It does not create, modify, or delete AWS resources. RDS, IAM inventory, cross-account discovery, and broader cloud-provider connectors are not implemented in this version.

## 2. What it demonstrates

- **Connector-based design:** EC2 and S3 discovery are implemented as separate components behind a common connector interface.
- **REST API:** A caller can request discovery for a region and a list of supported services.
- **AWS SDK credential integration:** The AWS SDK v2 default credential provider chain is used, so local profiles and other supported AWS credential sources can be used without embedding credentials in source code.
- **Privacy guard:** Resource attributes are filtered through explicit allowlists. Approved tag keys are retained with empty values by default; unapproved keys are omitted.
- **Independent service outcomes:** Each requested service returns its own status, resource count, duration, warnings, and sanitized error details where applicable.
- **Security controls:** API-key authentication, request rate limiting, security response headers, CORS configuration, centralized API error handling, and sanitized AWS errors are included.
- **Automated tests:** The project’s test suite was run locally and reported 54 tests with zero failures and zero errors.

## 3. Architecture at a glance

```text
HTTP client
   |
   v
DiscoveryController  -- validates the request and returns the API response
   |
   v
DiscoveryService     -- coordinates requested service connectors and aggregates results
   |
   +--------------------------+
   |                          |
   v                          v
Ec2Connector              S3Connector
   |                          |
   +------------+-------------+
                |
                v
           AWS SDK v2
                |
                v
          AWS APIs (read-only)

Connector output --> PrivacyGuard --> normalized resource metadata
                         |
                         v
                 response serialization
```

Key package responsibilities:

| Package / component | Responsibility |
|---|---|
| `controller/DiscoveryController` | Exposes `POST /api/discover`. |
| `service/DiscoveryService` | Coordinates connectors and aggregates per-service results. |
| `connector/AwsResourceConnector` | Shared interface for service connectors. |
| `connector/Ec2Connector` | Uses the EC2 `DescribeInstances` paginator and maps instance metadata. |
| `connector/S3Connector` | Lists buckets, resolves bucket regions, and attempts to retrieve bucket tags. |
| `privacy/PrivacyGuard` | Applies resource attribute and tag allowlists. |
| `config/DefaultAwsClientFactory` | Creates and manages AWS SDK v2 clients. |
| `security/ApiKeyAuthFilter` | Protects API endpoints with API-key authentication. |
| `security/RateLimitingFilter` | Applies request throttling. |
| `security/SecurityHeadersFilter` | Adds defensive HTTP response headers. |
| `exception/AwsErrorSanitizer` | Converts AWS exceptions into safer API error categories/messages. |

## 4. Supported discovery scope

### EC2

The connector queries EC2 instances in the requested region using `DescribeInstances` pagination. The normalized metadata allowlist includes fields such as:

- Instance ID, instance type, and state
- Region and availability zone
- VPC and subnet IDs
- Architecture, platform, hypervisor, and virtualization type
- Launch time and root-device attributes
- EBS-optimized flag

IP addresses and EC2 user data are not part of the connector’s mapped metadata fields.

### S3

The connector lists account buckets, resolves each bucket’s region, and only includes buckets matching the requested region. It maps bucket name, region, and creation date, and attempts to read bucket tags when permitted. Tags are then filtered by the privacy guard.

**Current-scope clarification:** Although the privacy guard’s allowlist contains names for possible S3 versioning/encryption/public-access attributes, the current `S3Connector` does not yet populate those fields. They should not be represented as implemented discovery capabilities until the connector adds the corresponding AWS API calls and tests.

### Not currently implemented

- RDS or IAM resource discovery
- S3 object listing, object keys, object contents, or payload reads
- Database rows or customer records
- EC2 user data, secrets, access keys, or credential collection
- Resource creation, updates, or deletion
- AWS Organizations-wide or cross-account role assumption

## 5. REST API contract

### Endpoint

```http
POST /api/discover
Content-Type: application/json
X-API-Key: <configured-api-key>
```

### Request body

```json
{
  "region": "ap-south-1",
  "services": ["EC2", "S3"]
}
```

- `region` is required and must match the expected AWS region identifier format.
- `services` is required, must not be empty, and can contain up to 10 entries.
- Supported service names in this version are `EC2` and `S3`.
- An unknown service should be rejected as a client validation error.

### Response semantics

The response includes a discovery ID, overall status, region, total resource count, elapsed time, per-service results, and warnings.

| Status | Meaning |
|---|---|
| `SUCCESS` | All requested service operations completed successfully. Zero discovered resources is a valid success. |
| `PARTIAL` | Some metadata was discovered, but one or more optional or service-level operations were incomplete. Review warnings and error categories. |
| `FAILED` | Requested discovery could not reliably complete. Review the sanitized service-level error information. |

### Authentication behavior

The API accepts the configured key through `X-API-Key` or an `Authorization: Bearer <key>` header. Requests with a missing or invalid key return `401 Unauthorized` when API-key protection is enabled.

## 6. Privacy and security model

### Metadata minimization

- Resource attributes are filtered through a per-resource-type allowlist before response serialization.
- Tag keys must match the approved operational-key allowlist.
- `complydp.security.privacy.include-tag-values=false` is the default. Approved tag keys are represented with empty string values; unapproved keys are dropped.
- If tag values are explicitly enabled, the implementation applies a restrictive value pattern and rejects suspicious values, including patterns associated with IP addresses or credentials.
- AWS errors returned through the API are sanitized into categories and safe messages rather than directly exposing raw exception details.

### API and runtime controls

- API-key authentication is enabled by default in configuration.
- The API key is loaded from the `COMPLYDP_SECURITY_API_KEY_SECRET` environment variable; it should not be committed to source control.
- Rate limiting is enabled by default. The current implementation uses in-process state, so limits are per application instance rather than shared across multiple replicas.
- Security headers are added to responses.
- Forwarded client IP headers are not trusted by default.

### Important limitations

This is a demonstration project, not a claim of production certification. Before production use, review secret rotation and storage, TLS termination, distributed rate limiting, proxy configuration, IAM scope, operational monitoring, and deployment-specific threat models. The live test described below used an AWS account with no EC2 instances or S3 buckets, so it verifies successful request execution but does not by itself prove privacy filtering against populated-resource payloads.

## 7. AWS permissions

The implemented connectors use these key read operations:

- EC2: `ec2:DescribeInstances`
- S3: `s3:ListAllMyBuckets`, `s3:GetBucketLocation`, and `s3:GetBucketTagging`

The S3 connector attempts bucket-tag retrieval. If the caller lacks `s3:GetBucketTagging`, discovery of an account with buckets can report partial results/warnings. Use a dedicated least-privilege identity for testing and do not grant broad administrator access just to make the demo pass.

AWS CLI profile example:

```bash
aws configure --profile metadata-demo
aws sts get-caller-identity --profile metadata-demo
export AWS_PROFILE=metadata-demo
```

The application uses the AWS SDK default credential provider chain. Do not put access keys or secret keys in this document, Java source, `application.properties`, or Git.

## 8. Run locally

### Prerequisites

- Java 17 or later
- The included Maven wrapper
- AWS credentials only for live AWS discovery; unit tests do not require AWS resources

### Configure environment variables

In the same terminal used to start the application:

```bash
export AWS_PROFILE=metadata-demo
export COMPLYDP_SECURITY_API_KEY_SECRET='replace-with-a-local-demo-key'
```

Use a unique local demo key. Do not use the example value in a public or production environment.

### Run tests

```bash
./mvnw clean test
```

### Start the application

```bash
./mvnw spring-boot:run
```

### Call the API

```bash
curl -i -X POST http://localhost:8080/api/discover \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: replace-with-your-local-demo-key' \
  -d '{"region":"ap-south-1","services":["EC2","S3"]}'
```

### Authentication smoke test

Without the API-key header, the protected endpoint should return `401 Unauthorized`:

```bash
curl -i -X POST http://localhost:8080/api/discover \
  -H 'Content-Type: application/json' \
  -d '{"region":"ap-south-1","services":["EC2","S3"]}'
```

## 9. Verification performed

The following checks were performed locally during preparation of this reviewer guide:

| Check | Observed result |
|---|---|
| `aws sts get-caller-identity --profile metadata-demo` | Successful; identity was the dedicated `metadata-discovery-demo` IAM user. |
| AWS CLI EC2 `DescribeInstances` in `ap-south-1` | Successful, empty result. |
| AWS CLI S3 `list-buckets` | Successful, empty result. |
| Live `POST /api/discover` with valid API key | HTTP 200; overall `SUCCESS`; EC2 and S3 each `SUCCESS`; zero resources. |
| Request without API key | HTTP 401 Unauthorized. |
| Request with invalid API key | HTTP 401 Unauthorized. |
| `./mvnw clean test` | `BUILD SUCCESS`; 54 tests, 0 failures, 0 errors, 0 skipped. |

The AWS account used for live verification had no EC2 instances or S3 buckets in the tested scope. Therefore, populated-resource mapping should be reviewed alongside the automated connector and privacy tests before treating it as verified against real resource payloads.

## 10. Suggested reviewer walkthrough

1. Read this guide and the repository `README.md` for the setup and endpoint contract.
2. Run `./mvnw clean test` to confirm the automated suite passes.
3. Review `DiscoveryController`, `DiscoveryService`, `Ec2Connector`, and `S3Connector` to follow the request path.
4. Review `PrivacyGuard` to understand exactly which attributes and tag values are returned.
5. Run the API locally and compare valid-key and missing/invalid-key responses.
6. Review the stated limitations and distinguish implemented behavior from future extensions.

## 11. Roadmap

Potential next steps, not claimed as implemented in this version:

- Add and test S3 versioning, encryption, and public-access-block discovery if required.
- Add mocked connector tests that verify mapped metadata for populated EC2/S3 resources and edge cases.
- Add RDS and IAM connectors behind the existing connector interface.
- Add shared rate limiting for multi-instance deployments.
- Add production-grade secret lifecycle integration, deployment TLS, and operational monitoring.
- Add cross-account discovery using explicitly assumed roles and narrowly scoped permissions.

---

**Reviewer note:** This repository is intended to demonstrate connector architecture, metadata minimization, API protection, and testable AWS discovery behavior. Please evaluate implemented features separately from the roadmap items above.
