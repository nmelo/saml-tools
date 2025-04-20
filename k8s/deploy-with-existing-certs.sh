#!/bin/bash

# Script to deploy SAML tools to Digital Ocean Kubernetes with existing Let's Encrypt certificates
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

# Check if Let's Encrypt certificates exist
echo "Checking for existing Let's Encrypt certificates..."
client_cert=$(kubectl get secret client-tls-cert -n $NAMESPACE -o name 2>/dev/null || echo "")
proxy_cert=$(kubectl get secret proxy-tls-cert -n $NAMESPACE -o name 2>/dev/null || echo "")
idp_cert=$(kubectl get secret idp-tls-cert -n $NAMESPACE -o name 2>/dev/null || echo "")

if [ -z "$client_cert" ] || [ -z "$proxy_cert" ] || [ -z "$idp_cert" ]; then
  echo "One or more required TLS certificates are missing."
  echo "Please make sure Let's Encrypt certificates have been set up using setup-dns01-certificates.sh"
  echo "Missing certificates:"
  [ -z "$client_cert" ] && echo "- client-tls-cert"
  [ -z "$proxy_cert" ] && echo "- proxy-tls-cert"
  [ -z "$idp_cert" ] && echo "- idp-tls-cert"
  exit 1
else
  echo "Found all required TLS certificates."
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

# Deploy the components sequentially with force redeploy
echo "Deploying IdP..."
kubectl apply -f "$PROJECT_DIR/k8s/02-samlidp.yaml"
# Force redeploy by restarting the deployment
kubectl rollout restart deployment/samlidp -n $NAMESPACE
echo "Waiting for IdP to be ready..."
kubectl rollout status deployment/samlidp -n $NAMESPACE

echo "Deploying Proxy..."
kubectl apply -f "$PROJECT_DIR/k8s/03-samlproxy.yaml"
# Force redeploy by restarting the deployment
kubectl rollout restart deployment/samlproxy -n $NAMESPACE
echo "Waiting for Proxy to be ready..."
kubectl rollout status deployment/samlproxy -n $NAMESPACE

echo "Deploying Client..."
kubectl apply -f "$PROJECT_DIR/k8s/04-samlclient.yaml"
# Force redeploy by restarting the deployment
kubectl rollout restart deployment/samlclient -n $NAMESPACE
echo "Waiting for Client to be ready..."
kubectl rollout status deployment/samlclient -n $NAMESPACE

# Update domain names in ingress if specified
INGRESS_FILE="$PROJECT_DIR/k8s/05-ingress-tls.yaml"
if [[ -n "$DOMAIN_CLIENT" && -n "$DOMAIN_PROXY" && -n "$DOMAIN_IDP" ]]; then
  echo "Updating domain names in ingress file..."
  
  # Create a temporary file
  temp_file=$(mktemp)
  
  # Update the ingress hosts
  cat "$INGRESS_FILE" | \
    sed "s/client.saml-tester.com/$DOMAIN_CLIENT/g" | \
    sed "s/proxy.saml-tester.com/$DOMAIN_PROXY/g" | \
    sed "s/idp.saml-tester.com/$DOMAIN_IDP/g" > "$temp_file"
  
  # Replace the original file
  mv "$temp_file" "$INGRESS_FILE"
  
  echo "Domain names updated successfully."
fi

# Deploy the Ingress with TLS
echo "Applying Ingress with TLS..."
kubectl apply -f "$INGRESS_FILE"

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