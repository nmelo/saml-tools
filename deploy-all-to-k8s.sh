#!/bin/bash
set -e

echo "Building and deploying all SAML tools to Kubernetes..."

# Login to DigitalOcean registry
echo "Logging in to DigitalOcean registry..."
doctl registry login

# Build and push all images
echo "Building Docker images..."

# Build and push samlclient
echo "Building samlclient..."
docker build -f Dockerfile.samlclient -t registry.digitalocean.com/samltools/samlclient:latest .
echo "Pushing samlclient..."
docker push registry.digitalocean.com/samltools/samlclient:latest

# Build and push samlproxy
echo "Building samlproxy..."
docker build -f Dockerfile.samlproxy -t registry.digitalocean.com/samltools/samlproxy:latest .
echo "Pushing samlproxy..."
docker push registry.digitalocean.com/samltools/samlproxy:latest

# Build and push samlidp (even if not changed, for completeness)
echo "Building samlidp..."
docker build -f Dockerfile.samlidp -t registry.digitalocean.com/samltools/samlidp:latest .
echo "Pushing samlidp..."
docker push registry.digitalocean.com/samltools/samlidp:latest

# Get the cluster and configure kubectl
echo "Configuring kubectl..."
CLUSTER_ID=$(doctl k8s cluster list --format ID --no-header)
doctl k8s cluster kubeconfig save $CLUSTER_ID

# Restart all deployments to pull the new images
echo "Restarting deployments..."
kubectl rollout restart deployment/samlclient -n saml-tools
kubectl rollout restart deployment/samlproxy -n saml-tools
kubectl rollout restart deployment/samlidp -n saml-tools

# Wait for rollouts to complete
echo "Waiting for rollouts to complete..."
kubectl rollout status deployment/samlclient -n saml-tools
kubectl rollout status deployment/samlproxy -n saml-tools
kubectl rollout status deployment/samlidp -n saml-tools

echo "All deployments completed successfully!"
echo ""
echo "You can check the status with:"
echo "kubectl get pods -n saml-tools"
echo ""
echo "View logs with:"
echo "kubectl logs -n saml-tools deployment/samlclient"
echo "kubectl logs -n saml-tools deployment/samlproxy"
echo "kubectl logs -n saml-tools deployment/samlidp"