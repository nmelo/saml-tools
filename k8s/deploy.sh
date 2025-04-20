#!/bin/bash

# Script to deploy SAML tools to Digital Ocean Kubernetes with hard pod reset
set -e

# Variables
REGISTRY="registry.digitalocean.com"
REGISTRY_NAME="samltools"           # Your DO registry name
CLUSTER_NAME="k8s-saml-tools"       # Your DO Kubernetes cluster name
NAMESPACE="saml-tools"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Uncomment and modify these lines if you need to use different domains
# DOMAIN_CLIENT="client.your-domain.com"
# DOMAIN_PROXY="proxy.your-domain.com"
# DOMAIN_IDP="idp.your-domain.com"

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

# Build and tag the Docker images
echo "Building and tagging Docker images..."
cd "$PROJECT_DIR"
docker build -t $REGISTRY/$REGISTRY_NAME/samlproxy:latest -f Dockerfile.samlproxy .
docker build -t $REGISTRY/$REGISTRY_NAME/samlidp:latest -f Dockerfile.samlidp .
docker build -t $REGISTRY/$REGISTRY_NAME/samlclient:latest -f Dockerfile.samlclient .

# Push the images to DO registry
echo "Pushing images to DO registry..."
docker push $REGISTRY/$REGISTRY_NAME/samlproxy:latest
docker push $REGISTRY/$REGISTRY_NAME/samlidp:latest
docker push $REGISTRY/$REGISTRY_NAME/samlclient:latest

# Create the namespace
echo "Creating Kubernetes namespace..."
kubectl apply -f "$PROJECT_DIR/k8s/00-namespace.yaml"

# Check if production certificates exist
echo "Checking for existing production certificates..."
client_cert=$(kubectl get secret client-tls-cert -n $NAMESPACE -o name 2>/dev/null || echo "")
proxy_cert=$(kubectl get secret proxy-tls-cert -n $NAMESPACE -o name 2>/dev/null || echo "")
idp_cert=$(kubectl get secret idp-tls-cert -n $NAMESPACE -o name 2>/dev/null || echo "")

if [ -z "$client_cert" ] || [ -z "$proxy_cert" ] || [ -z "$idp_cert" ]; then
  echo "One or more required TLS certificates are missing."
  echo "Please make sure production certificates have been created and are available in the cluster."
  echo "Required certificates:"
  echo "- client-tls-cert (client.saml-tester.com): ${client_cert:-MISSING}"
  echo "- proxy-tls-cert (proxy.saml-tester.com): ${proxy_cert:-MISSING}"
  echo "- idp-tls-cert (idp.saml-tester.com): ${idp_cert:-MISSING}"
  exit 1
else
  echo "Found all required production TLS certificates."
fi

# Update image names in deployment files
echo "Updating deployment files with correct image names..."
cd "$PROJECT_DIR/k8s"
sed -i "" "s|image: .*samlidp:latest|image: $REGISTRY/$REGISTRY_NAME/samlidp:latest|g" "$PROJECT_DIR/k8s/02-samlidp.yaml"
sed -i "" "s|image: .*samlproxy:latest|image: $REGISTRY/$REGISTRY_NAME/samlproxy:latest|g" "$PROJECT_DIR/k8s/03-samlproxy.yaml"
sed -i "" "s|image: .*samlclient:latest|image: $REGISTRY/$REGISTRY_NAME/samlclient:latest|g" "$PROJECT_DIR/k8s/04-samlclient.yaml"

# Apply ConfigMaps with HTTPS URLs
echo "Applying ConfigMaps with HTTPS URLs..."
kubectl apply -f "$PROJECT_DIR/k8s/01-configmaps-https.yaml"

# HARD RESET DEPLOYMENT STRATEGY
# Delete all deployments first and wait for pods to terminate
echo "Deleting existing deployments..."

# Delete IdP deployment and wait for pods to terminate
echo "Deleting IdP deployment..."
kubectl delete deployment/samlidp -n $NAMESPACE --ignore-not-found=true
echo "Waiting for IdP pods to terminate..."
while kubectl get pods -n $NAMESPACE -l app=samlidp 2>/dev/null | grep -q Running; do
  echo "IdP pods still running, waiting..."
  sleep 3
done
echo "All IdP pods terminated"

# Delete Proxy deployment and wait for pods to terminate
echo "Deleting Proxy deployment..."
kubectl delete deployment/samlproxy -n $NAMESPACE --ignore-not-found=true
echo "Waiting for Proxy pods to terminate..."
while kubectl get pods -n $NAMESPACE -l app=samlproxy 2>/dev/null | grep -q Running; do
  echo "Proxy pods still running, waiting..."
  sleep 3
done
echo "All Proxy pods terminated"

# Delete Client deployment and wait for pods to terminate
echo "Deleting Client deployment..."
kubectl delete deployment/samlclient -n $NAMESPACE --ignore-not-found=true
echo "Waiting for Client pods to terminate..."
while kubectl get pods -n $NAMESPACE -l app=samlclient 2>/dev/null | grep -q Running; do
  echo "Client pods still running, waiting..."
  sleep 3
done
echo "All Client pods terminated"

# Deploy the components sequentially
echo "Deploying IdP..."
kubectl apply -f "$PROJECT_DIR/k8s/02-samlidp.yaml"
echo "Waiting for IdP to be ready..."
kubectl wait --for=condition=available --timeout=120s deployment/samlidp -n $NAMESPACE

echo "Deploying Proxy..."
kubectl apply -f "$PROJECT_DIR/k8s/03-samlproxy.yaml"
echo "Waiting for Proxy to be ready..."
kubectl wait --for=condition=available --timeout=120s deployment/samlproxy -n $NAMESPACE

echo "Deploying Client..."
kubectl apply -f "$PROJECT_DIR/k8s/04-samlclient.yaml"
echo "Waiting for Client to be ready..."
kubectl wait --for=condition=available --timeout=120s deployment/samlclient -n $NAMESPACE

echo "Deployment complete!"
echo "=================="
echo "You can access the services at:"
if [[ -n "$DOMAIN_CLIENT" && -n "$DOMAIN_PROXY" && -n "$DOMAIN_IDP" ]]; then
  echo "- SAML Client: https://$DOMAIN_CLIENT"
  echo "- SAML Proxy: https://$DOMAIN_PROXY"
  echo "- SAML IdP: https://$DOMAIN_IDP"
else
  echo "- SAML Client: https://client.saml-tester.com"
  echo "- SAML Proxy: https://proxy.saml-tester.com"
  echo "- SAML IdP: https://idp.saml-tester.com"
  echo ""
  echo "NOTE: Make sure your DNS records point to your Digital Ocean cluster's ingress IP"
fi
echo ""
echo "IMPORTANT: Ensure your DNS records are configured correctly to point to your cluster's ingress controller IP"
echo "=================="
