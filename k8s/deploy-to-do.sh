#!/bin/bash

# Script to deploy SAML tools to Digital Ocean Kubernetes
set -e

# Variables
REGISTRY="registry.digitalocean.com"
REGISTRY_NAME="samltools"           # Your DO registry name
CLUSTER_NAME="k8s-saml-tools"       # Your DO Kubernetes cluster name
NAMESPACE="saml-tools"

# Ensure doctl is authenticated
echo "Verifying doctl authentication..."
doctl account get || { echo "Please run 'doctl auth init' to authenticate"; exit 1; }

# Connect to the Kubernetes cluster
echo "Connecting to Kubernetes cluster $CLUSTER_NAME..."
doctl kubernetes cluster kubeconfig save $CLUSTER_NAME

# Check if DO Container Registry is available
if ! doctl registry get > /dev/null 2>&1; then
  echo "Error: DigitalOcean Container Registry not found"
  echo "Please create a registry using: doctl registry create <name>"
  exit 1
fi

# Login to DO container registry
echo "Logging in to DO container registry..."
doctl registry login

# Build and tag the Docker images
echo "Building and tagging Docker images..."
cd ..
docker build -t $REGISTRY/$REGISTRY_NAME/samlproxy:latest -f Dockerfile.samlproxy .
docker build -t $REGISTRY/$REGISTRY_NAME/samlidp:latest -f Dockerfile.samlidp .
docker build -t $REGISTRY/$REGISTRY_NAME/samlclient:latest -f Dockerfile.samlclient .
cd k8s

# Push the images to DO registry
echo "Pushing images to DO registry..."
docker push $REGISTRY/$REGISTRY_NAME/samlproxy:latest
docker push $REGISTRY/$REGISTRY_NAME/samlidp:latest
docker push $REGISTRY/$REGISTRY_NAME/samlclient:latest

# Create the namespace
echo "Creating Kubernetes namespace..."
kubectl apply -f 00-namespace.yaml

# Generate certificates and create secrets
echo "Generating certificates and creating secrets..."
./generate-certs.sh
kubectl apply -f idp-certs-secret.yaml -f proxy-certs-secret.yaml -f client-certs-secret.yaml

# Update image names in deployment files
echo "Updating deployment files with correct image names..."
sed -i "" "s|image: saml-tools/samlidp:latest|image: $REGISTRY/$REGISTRY_NAME/samlidp:latest|g" 02-samlidp.yaml
sed -i "" "s|image: saml-tools/samlproxy:latest|image: $REGISTRY/$REGISTRY_NAME/samlproxy:latest|g" 03-samlproxy.yaml
sed -i "" "s|image: saml-tools/samlclient:latest|image: $REGISTRY/$REGISTRY_NAME/samlclient:latest|g" 04-samlclient.yaml

# Apply ConfigMaps
echo "Applying ConfigMaps..."
kubectl apply -f 01-configmaps.yaml

# Deploy the components sequentially
echo "Deploying IdP..."
kubectl apply -f 02-samlidp.yaml
echo "Waiting for IdP to be ready..."
kubectl rollout status deployment/samlidp -n $NAMESPACE

echo "Deploying Proxy..."
kubectl apply -f 03-samlproxy.yaml
echo "Waiting for Proxy to be ready..."
kubectl rollout status deployment/samlproxy -n $NAMESPACE

echo "Deploying Client..."
kubectl apply -f 04-samlclient.yaml
echo "Waiting for Client to be ready..."
kubectl rollout status deployment/samlclient -n $NAMESPACE

# Deploy the Ingress
echo "Applying Ingress..."
kubectl apply -f 05-ingress.yaml

echo "Deployment complete!"
echo "=================="
echo "You can access the services at:"
echo "- SAML Client: http://samlclient.example.com"
echo "- SAML Proxy: http://samlproxy.example.com"
echo "- SAML IdP: http://samlidp.example.com"
echo ""
echo "Note: Update the hostnames in 05-ingress.yaml with your actual domains"
echo "and ensure DNS records are configured correctly."
echo "=================="