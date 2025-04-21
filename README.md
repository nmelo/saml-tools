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