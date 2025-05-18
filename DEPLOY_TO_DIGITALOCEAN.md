# Deploy SAML Tools to DigitalOcean

This guide will help you deploy the SAML tools (IdP, Proxy, and Client) to DigitalOcean Kubernetes Service (DOKS) with Container Registry.

## Prerequisites

1. DigitalOcean account with:
   - Kubernetes cluster created
   - Container Registry created
   - Domain name (you'll need to configure DNS)

2. Local tools installed:
   - `doctl` (DigitalOcean CLI) - authenticated
   - `kubectl`
   - `docker`
   - `make`

## Quick Start

### 1. Clone and Build

```bash
# Clone the repository if you haven't already
git clone https://github.com/nmelo/saml-tools.git
cd saml-tools

# Build the applications
make build
```

### 2. Configure DigitalOcean CLI

```bash
# Install doctl if you haven't already
brew install doctl  # On macOS
# or visit: https://docs.digitalocean.com/reference/doctl/how-to/install/

# Authenticate with your DigitalOcean account
doctl auth init
```

### 3. Create DigitalOcean Resources

```bash
# Create a Kubernetes cluster if you don't have one
doctl kubernetes cluster create saml-tools-cluster \
  --region sfo3 \
  --size s-2vcpu-4gb \
  --count 3

# Create a container registry if you don't have one
doctl registry create samltools

# Configure docker to use the registry
doctl registry login
```

### 4. Update Deployment Configuration

Edit `k8s/deploy.sh` and update these variables:

```bash
REGISTRY_NAME="samltools"  # Your registry name from step 3
CLUSTER_NAME="saml-tools-cluster"  # Your cluster name from step 3
```

### 5. Configure Your Domain

You'll need a domain with three subdomains:
- `client.yourdomain.com` - for the SAML client
- `proxy.yourdomain.com` - for the SAML proxy
- `idp.yourdomain.com` - for the SAML IdP

Update the configurations to use your domain:

```bash
# Edit k8s/01-configmaps-https.yaml
# Update all references from saml-tester.com to yourdomain.com

# Edit k8s/05-ingress-prod-tls.yaml
# Update all hostnames to use yourdomain.com
```

### 6. Deploy to DigitalOcean

```bash
# From the project root directory
cd k8s

# Make the deployment script executable
chmod +x deploy.sh

# Run the deployment
./deploy.sh
```

This will:
1. Build Docker images
2. Push them to your DigitalOcean Container Registry
3. Deploy all components to your Kubernetes cluster
4. Set up services and ingress

### 7. Get the Load Balancer IP

```bash
# Get the ingress load balancer external IP
kubectl get ingress -n saml-tools
```

### 8. Configure DNS

In your domain registrar or DNS provider, create A records pointing to the load balancer IP:
- `client.yourdomain.com` → LoadBalancer IP
- `proxy.yourdomain.com` → LoadBalancer IP
- `idp.yourdomain.com` → LoadBalancer IP

### 9. Set up TLS (HTTPS)

You have two options:

#### Option A: Let's Encrypt (Recommended)
```bash
# Install cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.14.4/cert-manager.yaml

# Wait for cert-manager to be ready
kubectl wait --for=condition=available --timeout=300s deployment/cert-manager -n cert-manager

# Apply the Let's Encrypt issuer and TLS ingress
kubectl apply -f k8s/letsencrypt-prod-issuer.yaml
kubectl apply -f k8s/05-ingress-prod-tls.yaml
```

#### Option B: Self-signed certificates
```bash
cd k8s
./generate-certs.sh
kubectl apply -f idp-certs-secret.yaml proxy-certs-secret.yaml client-certs-secret.yaml
kubectl apply -f 05-ingress-tls.yaml
```

### 10. Access Your Services

Once DNS propagates (usually within minutes), you can access:
- https://client.yourdomain.com - SAML Client
- https://proxy.yourdomain.com - SAML Proxy  
- https://idp.yourdomain.com - SAML IdP

## Updating the Deployment

When you make changes to the code:

```bash
# Build and push new images
cd k8s
./deploy.sh

# Or manually update specific components
kubectl rollout restart deployment/samlclient -n saml-tools
kubectl rollout restart deployment/samlproxy -n saml-tools
kubectl rollout restart deployment/samlidp -n saml-tools
```

## Monitoring and Troubleshooting

```bash
# Check deployment status
kubectl get all -n saml-tools

# View pod logs
kubectl logs -n saml-tools deployment/samlclient
kubectl logs -n saml-tools deployment/samlproxy
kubectl logs -n saml-tools deployment/samlidp

# Check certificate status (if using Let's Encrypt)
kubectl get certificates -n saml-tools
kubectl describe certificate -n saml-tools

# Debug pods
kubectl exec -it -n saml-tools deployment/samlclient -- /bin/sh
```

## Clean Up

To remove the deployment:

```bash
# Delete all Kubernetes resources
kubectl delete namespace saml-tools

# Delete the DigitalOcean resources (if desired)
doctl kubernetes cluster delete saml-tools-cluster
doctl registry delete
```

## Cost Optimization

- Use smaller node sizes for testing (s-1vcpu-2gb)
- Use the basic tier for container registry
- Delete resources when not in use
- Consider using a single node for development

## Security Considerations

1. Always use HTTPS in production
2. Update the session secrets in configurations
3. Use strong passwords for test accounts
4. Regularly update dependencies and base images
5. Use Kubernetes secrets for sensitive data
6. Implement proper RBAC in your cluster

## Support

For issues specific to:
- The SAML tools: Check the repository issues
- DigitalOcean: Contact DigitalOcean support
- Kubernetes: Check the Kubernetes documentation
