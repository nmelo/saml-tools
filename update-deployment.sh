#!/bin/bash

# Script to update existing SAML tools deployment on DigitalOcean
set -e

# Configuration - Update these with your actual values
REGISTRY="registry.digitalocean.com"
REGISTRY_NAME="${DO_REGISTRY_NAME:-samltools}"
CLUSTER_NAME="${DO_CLUSTER_NAME:-k8s-saml-tools}"
NAMESPACE="saml-tools"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Main update process
print_info "Starting deployment update..."

# Login to DO registry
print_info "Logging in to DigitalOcean Container Registry..."
doctl registry login

# Connect to the Kubernetes cluster
print_info "Connecting to Kubernetes cluster $CLUSTER_NAME..."
doctl kubernetes cluster kubeconfig save $CLUSTER_NAME

# Build and tag the Docker images with the latest code
print_info "Building Docker images with latest changes..."
docker build -t $REGISTRY/$REGISTRY_NAME/samlproxy:latest -f Dockerfile.samlproxy .
docker build -t $REGISTRY/$REGISTRY_NAME/samlidp:latest -f Dockerfile.samlidp .
docker build -t $REGISTRY/$REGISTRY_NAME/samlclient:latest -f Dockerfile.samlclient .

# Push the images to DO registry
print_info "Pushing updated images to registry..."
docker push $REGISTRY/$REGISTRY_NAME/samlproxy:latest
docker push $REGISTRY/$REGISTRY_NAME/samlidp:latest
docker push $REGISTRY/$REGISTRY_NAME/samlclient:latest

# Force pods to pull the new images by deleting them
print_info "Updating deployments with new images..."

# Update the proxy (which has the UI changes)
print_info "Updating SAML Proxy..."
kubectl rollout restart deployment/samlproxy -n $NAMESPACE

# Optionally update other components
read -p "Update IdP and Client as well? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_info "Updating SAML IdP..."
    kubectl rollout restart deployment/samlidp -n $NAMESPACE
    
    print_info "Updating SAML Client..."
    kubectl rollout restart deployment/samlclient -n $NAMESPACE
fi

# Wait for rollouts to complete
print_info "Waiting for deployments to be ready..."
kubectl rollout status deployment/samlproxy -n $NAMESPACE --timeout=300s

if [[ $REPLY =~ ^[Yy]$ ]]; then
    kubectl rollout status deployment/samlidp -n $NAMESPACE --timeout=300s
    kubectl rollout status deployment/samlclient -n $NAMESPACE --timeout=300s
fi

# Show deployment status
print_info "Deployment status:"
kubectl get deployments -n $NAMESPACE

print_info "Pod status:"
kubectl get pods -n $NAMESPACE

print_info "Update completed successfully!"
print_info "Your services should now be running with the latest code."