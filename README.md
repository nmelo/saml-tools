# SAML Tools

A set of Go-based tools for SAML authentication testing and development.

## Components

### SAML Proxy

The SAML proxy sits between Service Providers and Identity Providers, providing enhanced control over the SAML authentication flow.

**Features:**
- Acts as an IdP to Service Providers and as an SP to Identity Providers
- Support for multiple upstream Identity Providers with selection UI
- Support for configurable SP-specific default IdP settings
- Attribute mapping and transformation
- Encrypted SAML assertion handling
- Web-based configuration UI at `/status`
- **Automated IdP Health Checking and Failover:** Periodically checks the health of configured Identity Providers and uses this information to improve reliability and user experience during the authentication process.

#### Automated IdP Health Checking and Failover

The SAML Proxy includes a feature to automatically monitor the health of upstream Identity Providers (IdPs). This helps in situations where an IdP might be temporarily unavailable, allowing the proxy to guide users to healthy alternatives or provide informative error messages.

**Feature Overview:**

*   **Periodic Health Checks:** The proxy periodically sends requests to a configured endpoint for each IdP to determine its health status.
*   **Dynamic Failover:** If a configured default IdP (either Service Provider-specific or global) is found to be unhealthy, the proxy will:
    *   Attempt to select another healthy IdP if one is available (e.g., if only one other healthy IdP exists).
    *   Fall back to the IdP selection page, listing only other healthy IdPs, allowing the user to choose an alternative.
*   **Filtered IdP Selection:** The IdP selection page (`/saml/select-idp`) will only display IdPs that are currently healthy and responsive.
*   **Error Handling:** If no healthy IdPs are available at all, the user will be presented with an error message indicating that the service is temporarily unavailable.

**Configuration:**

Health checking behavior is controlled by global and per-IdP settings in `samlproxy.yaml`:

1.  **Global Health Check Interval:**
    *   `health_check_interval_seconds`: This top-level parameter specifies how often, in seconds, the health check is performed for all configured IdPs.
    *   **Default:** If not specified, it defaults to `60` seconds.
    *   **Example (`samlproxy.yaml`):**
        ```yaml
        # SAML Proxy Configuration
        listen_addr: ":8082"
        base_url: "http://samlproxy:8082"
        # ... other global settings ...
        health_check_interval_seconds: 120 # Check health every 2 minutes
        ```

2.  **Per-IdP Health Check URL:**
    *   `health_check_url`: This parameter can be added to each IdP's configuration within the `identity_providers` list. It specifies a dedicated URL for health checks for that particular IdP.
    *   **Optional:** If this URL is not provided or is left empty, the proxy will use the IdP's `metadata_url` for the health check.
    *   **Example (within an IdP definition in `samlproxy.yaml`):**
        ```yaml
        identity_providers:
          - id: "my-idp-1"
            name: "Main Corporate IdP"
            metadata_url: "https://idp.example.com/saml/metadata"
            sso_url: "https://idp.example.com/saml/sso"
            # Specific health check endpoint for this IdP
            health_check_url: "https://idp.example.com/healthstatus"
          
          - id: "my-idp-2"
            name: "Backup IdP"
            metadata_url: "https://backup-idp.example.com/saml/metadata"
            sso_url: "https://backup-idp.example.com/saml/sso"
            # health_check_url is not specified, so metadata_url will be used.
        ```

**Behavior and Failover Logic:**

*   **Health Determination:** An IdP's health is determined by sending an HTTP GET request to its `health_check_url` (or `metadata_url` if the former is not specified). The proxy expects an HTTP 2xx status code within a default timeout of 10 seconds for the IdP to be considered healthy.
*   **Default IdP Unhealthy:** If an SP's configured default IdP or the global default IdP is unhealthy, the proxy will not attempt to use it directly. Instead, it will:
    *   If only one other healthy IdP is available for the request, it may be chosen automatically.
    *   Otherwise, if multiple healthy IdPs are available, the user will be redirected to the IdP selection page.
*   **IdP Selection Page:** The selection page at `/saml/select-idp` dynamically lists only those IdPs that have passed their latest health check.
*   **No Healthy IdPs:** If all configured IdPs are determined to be unhealthy, any user attempting to log in via the proxy will receive an error page (typically HTTP 503 Service Unavailable) indicating that no identity providers are currently available.

**Monitoring Health Status:**

The current health status of each configured Identity Provider (marked as "Healthy" or "Unhealthy") can be viewed on the SAML Proxy's status and configuration page, typically available at `/status`.

### SAML Identity Provider (IdP)

A simple test Identity Provider that provides predictable SAML responses.

**Features:**
- SAML 2.0 compatible
- Configurable user attributes
- No actual authentication (for testing only)

### SAML Client (SP)

A basic Service Provider implementation for testing.

**Features:**
- SAML 2.0 compatible
- Simple web interface
- Displays authenticated user information and SAML attributes

## Running the Tools

### Local Execution

Build and run all components:

```bash
make build
make run-all
```

Or run components individually:

```bash
# Build all components
make build

# Run the Identity Provider
./bin/samlidp configs/samlidp.yaml

# Run the SAML Proxy
./bin/samlproxy configs/samlproxy.yaml

# Run the SAML Client
./bin/samlclient configs/samlclient.yaml
```

### Using Docker

Start all components with Docker Compose:

```bash
docker-compose up -d
```

This will start:
- SAML Identity Provider on port 8085
- SAML Proxy on port 8082
- SAML Client on port 8080

When all services are running, access:
- SAML Client: http://localhost:8080
- SAML Proxy Status UI: http://localhost:8082/status
- SAML IdP: http://localhost:8085

## Authentication Flow

1. Access the SAML Client at http://localhost:8080
2. Click "Login via SAML"
3. If multiple IdPs are configured and no default is set, the SAML Proxy will show an IdP selection screen
4. Select an Identity Provider (or be automatically redirected if a default is configured)
5. The test IdP will authenticate without password (testing only)
6. You'll be redirected back to the SAML Client with your identity information

## Configuration

Each component has its own YAML configuration file in the `configs` directory:

- `samlclient.yaml`: Configuration for the SAML Client
- `samlproxy.yaml`: Configuration for the SAML Proxy
- `samlidp.yaml`: Configuration for the SAML Identity Provider

The SAML proxy configuration can be modified through the web UI at `/status`, where you can set default IdPs for each Service Provider.

## Default Ports

- SAML Client: 8080
- SAML Proxy: 8082
- SAML IdP: 8085