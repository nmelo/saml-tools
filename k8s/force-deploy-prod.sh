#!/bin/bash

# Script to deploy SAML tools to Digital Ocean Kubernetes with complete reset
set -e

# Variables
REGISTRY="registry.digitalocean.com"
REGISTRY_NAME="samltools"           # Your DO registry name
CLUSTER_NAME="k8s-saml-tools"       # Your DO Kubernetes cluster name
NAMESPACE="saml-tools"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Add a timestamp to built images to force pulling new images
TIMESTAMP=$(date +%Y%m%d%H%M%S)

# Ensure doctl is authenticated
echo "Verifying doctl authentication..."
doctl account get || { echo "Please run 'doctl auth init' to authenticate"; exit 1; }

# Connect to the Kubernetes cluster
echo "Connecting to Kubernetes cluster $CLUSTER_NAME..."
doctl kubernetes cluster kubeconfig save $CLUSTER_NAME

# Check if DO Container Registry is available
if ! doctl registry get > /dev/null 2>&1; then
  echo "Error: DigitalOcean Container Registry not found"
  echo "Please create a registry using: doctl registry create <n>"
  exit 1
fi

# Login to DO container registry
echo "Logging in to DO container registry..."
doctl registry login

# Build and tag the Docker images with timestamp to force pulling new images
echo "Building and tagging Docker images..."
cd "$PROJECT_DIR"
docker build -t $REGISTRY/$REGISTRY_NAME/samlproxy:$TIMESTAMP -f Dockerfile.samlproxy .
docker build -t $REGISTRY/$REGISTRY_NAME/samlidp:$TIMESTAMP -f Dockerfile.samlidp .
docker build -t $REGISTRY/$REGISTRY_NAME/samlclient:$TIMESTAMP -f Dockerfile.samlclient .

# Push the images to DO registry
echo "Pushing images to DO registry..."
docker push $REGISTRY/$REGISTRY_NAME/samlproxy:$TIMESTAMP
docker push $REGISTRY/$REGISTRY_NAME/samlidp:$TIMESTAMP
docker push $REGISTRY/$REGISTRY_NAME/samlclient:$TIMESTAMP

# Create the namespace
echo "Creating Kubernetes namespace..."
kubectl apply -f "$PROJECT_DIR/k8s/00-namespace.yaml"

# Update image names in deployment files with timestamped images to force pulling new images
echo "Updating deployment files with timestamped image names..."
cd "$PROJECT_DIR/k8s"
sed -i "" "s|image: .*samlidp:latest|image: $REGISTRY/$REGISTRY_NAME/samlidp:$TIMESTAMP|g" "$PROJECT_DIR/k8s/02-samlidp.yaml"
sed -i "" "s|image: .*samlproxy:latest|image: $REGISTRY/$REGISTRY_NAME/samlproxy:$TIMESTAMP|g" "$PROJECT_DIR/k8s/03-samlproxy.yaml"
sed -i "" "s|image: .*samlclient:latest|image: $REGISTRY/$REGISTRY_NAME/samlclient:$TIMESTAMP|g" "$PROJECT_DIR/k8s/04-samlclient.yaml"

# Apply ConfigMaps with HTTPS URLs
echo "Applying ConfigMaps with HTTPS URLs..."
kubectl apply -f "$PROJECT_DIR/k8s/01-configmaps-https.yaml"

# COMPLETE RESET - DELETE EVERYTHING
echo "PERFORMING COMPLETE RESET OF ALL RESOURCES"

# Delete the ingress first
echo "Deleting existing ingress..."
kubectl delete ingress -n $NAMESPACE --all --ignore-not-found=true

# Delete all deployments and wait for pods to terminate
echo "Deleting all deployments..."
kubectl delete deployment -n $NAMESPACE --all --ignore-not-found=true
echo "Waiting for all pods to terminate..."
while kubectl get pods -n $NAMESPACE 2>/dev/null | grep -q Running; do
  echo "Pods still running, waiting..."
  sleep 3
done
echo "All pods terminated"

# Deploy the components sequentially
echo "Deploying IdP..."
kubectl apply -f "$PROJECT_DIR/k8s/02-samlidp.yaml"
echo "Waiting for IdP to be ready (max 60s)..."
kubectl wait --for=condition=available --timeout=60s deployment/samlidp -n $NAMESPACE || echo "Warning: Timeout waiting for IdP, continuing anyway"

echo "Deploying Proxy..."
kubectl apply -f "$PROJECT_DIR/k8s/03-samlproxy.yaml"
echo "Waiting for Proxy to be ready (max 60s)..."
kubectl wait --for=condition=available --timeout=60s deployment/samlproxy -n $NAMESPACE || echo "Warning: Timeout waiting for Proxy, continuing anyway"

echo "Deploying Client..."
kubectl apply -f "$PROJECT_DIR/k8s/04-samlclient.yaml"
echo "Waiting for Client to be ready (max 60s)..."
kubectl wait --for=condition=available --timeout=60s deployment/samlclient -n $NAMESPACE || echo "Warning: Timeout waiting for Client, continuing anyway"

# Deploy the Ingress with production TLS certificates
echo "Applying Ingress with production TLS certificates..."
kubectl apply -f "$PROJECT_DIR/k8s/05-ingress-prod-tls.yaml"

# Wait for ingress to be properly configured
echo "Waiting for ingress to be configured..."
sleep 10

# Display info about the ingress
echo "Ingress information:"
kubectl get ingress -n $NAMESPACE -o wide
kubectl describe ingress -n $NAMESPACE saml-tools-ingress | grep -A10 "TLS:"

echo "Deployment complete!"
echo "=================="
echo "You can access the services at:"
echo "- SAML Client: https://client.saml-tester.com"
echo "- SAML Proxy: https://proxy.saml-tester.com"
echo "- SAML IdP: https://idp.saml-tester.com"
echo ""
echo "IMPORTANT: Ensure your DNS records are configured correctly to point to your cluster's ingress controller IP"
echo "=================="
