# Kubernetes Deployment for SAML Tools

This directory contains Kubernetes manifests for deploying the SAML Tools project to AWS EKS with Application Load Balancer (ALB) ingress controller.

## Files Overview

- `00-namespace.yaml`: Creates the `saml-tools` namespace (currently using default namespace)
- `01-configmaps-https.yaml`: ConfigMaps for all three components with HTTPS URLs
- `02-samlidp.yaml`: Deployment and Service for the SAML IdP
- `03-samlproxy.yaml`: Deployment and Service for the SAML Proxy
- `04-samlclient.yaml`: Deployment and Service for the SAML Client
- `05-ingress-idpbridge-https.yaml`: AWS ALB Ingress resource with ACM certificate for idpbridge.com
- `generate-certs.sh`: Script to generate self-signed certificates for local testing

## AWS Deployment

The deployment is configured for:
- AWS EKS cluster with ARM64/Graviton nodes
- AWS Application Load Balancer (ALB) for ingress
- AWS Certificate Manager (ACM) for SSL certificates
- Route53 for DNS management
- Domain: idpbridge.com

### Service URLs

- SAML Client: https://client.idpbridge.com
- SAML Proxy: https://proxy.idpbridge.com
- SAML IdP: https://idp.idpbridge.com

## Deployment Steps

Use the deployment script from the project root:

```bash
# From the project root directory
./deploy-to-aws.sh
```

Or deploy manually:

```bash
# Apply all manifests in order
kubectl apply -f 00-namespace.yaml
kubectl apply -f 01-configmaps-https.yaml
kubectl apply -f 02-samlidp.yaml
kubectl apply -f 03-samlproxy.yaml
kubectl apply -f 04-samlclient.yaml
kubectl apply -f 05-ingress-idpbridge-https.yaml
```

## Monitoring

Check deployment status:
```bash
kubectl get all
kubectl get ingress
```

View logs:
```bash
kubectl logs deployment/samlclient
kubectl logs deployment/samlproxy
kubectl logs deployment/samlidp
```

## Configuration

All service configurations are managed through the ConfigMaps in `01-configmaps-https.yaml`. The services are configured to communicate over HTTPS using the idpbridge.com domain.

## Architecture

- All services run on ARM64 architecture (AWS Graviton)
- Services are exposed through AWS ALB with path-based routing
- SSL termination happens at the ALB using ACM certificates
- Internal communication between services uses HTTPS with the public domain names