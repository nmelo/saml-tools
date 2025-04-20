# Kubernetes Deployment for SAML Tools

This directory contains Kubernetes manifests and scripts to deploy the SAML Tools project to a Kubernetes cluster, specifically optimized for Digital Ocean Kubernetes (DOKS).

## Prerequisites

- Docker installed and running
- `doctl` CLI installed and authenticated
- Access to a Digital Ocean Kubernetes cluster
- Digital Ocean Container Registry setup
- Cloudflare account (for DNS management and DNS-01 challenges)

## Files Overview

- `00-namespace.yaml`: Creates the `saml-tools` namespace
- `01-configmaps.yaml`: ConfigMaps for all three components
- `02-samlidp.yaml`: Deployment and Service for the SAML IdP
- `03-samlproxy.yaml`: Deployment and Service for the SAML Proxy
- `04-samlclient.yaml`: Deployment and Service for the SAML Client
- `05-ingress.yaml`: Ingress resource to expose services over HTTP
- `05-ingress-tls.yaml`: Ingress resource with TLS support
- `generate-certs.sh`: Script to generate certificates and create K8s secrets
- `deploy-to-do.sh`: Script to build, push, and deploy to Digital Ocean
- `setup-dns01-certificates.sh`: Script to set up Let's Encrypt certificates using DNS-01 challenges

## Deployment Steps

### 1. Update Configuration

Edit the following files to customize your deployment:

- `01-configmaps.yaml`: Update configuration settings
- `05-ingress.yaml`: Update hostnames with your actual domains

### 2. Set up Container Registry

Make sure you have a Digital Ocean Container Registry:

```bash
doctl registry create <n> --subscription-tier basic
```

### 3. Update the Deployment Script

Edit `deploy-to-do.sh` and update the following variables:

```bash
REGISTRY_NAME="your-registry-name"  # Your DO registry name
CLUSTER_NAME="k8s-saml-tools"       # Your DO Kubernetes cluster name
```

### 4. Run the Deployment

From the `k8s` directory:

```bash
./deploy-to-do.sh
```

This script will:
1. Build the Docker images
2. Push them to your DO Container Registry
3. Generate certificates and create secrets
4. Deploy all components to your Kubernetes cluster

### 5. Set up TLS with Let's Encrypt (DNS-01 Challenge)

#### Prerequisites for TLS

1. Install cert-manager:
   ```bash
   kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.14.4/cert-manager.yaml
   ```

2. Create a Cloudflare API token:
   - Log in to your Cloudflare account
   - Go to "My Profile" > "API Tokens"
   - Click "Create Token"
   - Use the "Edit zone DNS" template
   - Under "Zone Resources", select "Include" > "Specific zone" > "saml-tester.com"
   - Give the token a name like "cert-manager-dns01"
   - Create the token and copy the value

3. Update the API token in the secret file:
   ```bash
   # Edit cloudflare-api-token-secret.yaml and replace YOUR_CLOUDFLARE_API_TOKEN with the token value
   ```

4. Run the certificate setup script:
   ```bash
   ./setup-dns01-certificates.sh
   ```

This script will:
1. Apply the Cloudflare API token secret
2. Set up the staging Let's Encrypt issuer
3. Update the ingress with TLS configuration
4. Wait for staging certificates to be issued
5. Verify the staging certificates work
6. Switch to production certificates
7. Verify the production certificates

### 6. Access the Services

Once deployed, you can access your services at:

- SAML Client: https://client.saml-tester.com
- SAML Proxy: https://proxy.saml-tester.com
- SAML IdP: https://idp.saml-tester.com

You've already created the necessary DNS A records in Cloudflare pointing to the Kubernetes cluster's load balancer IP address.

## Manual Deployment

If you prefer to deploy manually:

1. Generate certificates:
   ```bash
   ./generate-certs.sh
   ```

2. Create the namespace and secrets:
   ```bash
   kubectl apply -f 00-namespace.yaml
   kubectl apply -f idp-certs-secret.yaml -f proxy-certs-secret.yaml -f client-certs-secret.yaml
   ```

3. Apply ConfigMaps:
   ```bash
   kubectl apply -f 01-configmaps.yaml
   ```

4. Deploy components sequentially:
   ```bash
   kubectl apply -f 02-samlidp.yaml
   kubectl apply -f 03-samlproxy.yaml
   kubectl apply -f 04-samlclient.yaml
   ```

5. Apply Ingress:
   ```bash
   kubectl apply -f 05-ingress.yaml
   ```

6. For TLS setup:
   ```bash
   kubectl apply -f cloudflare-api-token-secret.yaml
   kubectl apply -f letsencrypt-staging-dns01-issuer.yaml
   kubectl apply -f 05-ingress-tls.yaml
   # Wait for certificates, then switch to production issuer
   kubectl apply -f letsencrypt-prod-dns01-issuer.yaml
   ```

## Troubleshooting

To check the status of your deployments:

```bash
kubectl get pods -n saml-tools
```

To view logs for a specific pod:

```bash
kubectl logs -n saml-tools <pod-name>
```

To describe a resource:

```bash
kubectl describe -n saml-tools deployment/<deployment-name>
```

To check certificate status:

```bash
kubectl get certificates -n saml-tools
kubectl describe certificate <cert-name> -n saml-tools
```

To check cert-manager events:

```bash
kubectl get events -n cert-manager
```