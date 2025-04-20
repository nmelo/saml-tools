#!/bin/bash

# Script to deploy SAML tools to Digital Ocean Kubernetes
set -e

# Variables
REGISTRY="registry.digitalocean.com"
REGISTRY_NAME="samltools"           # Your DO registry name
CLUSTER_NAME="k8s-saml-tools"       # Your DO Kubernetes cluster name
NAMESPACE="saml-tools"

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
  echo "Please create a registry using: doctl registry create <name>"
  exit 1
fi

# Login to DO container registry
echo "Logging in to DO container registry..."
doctl registry login

# Build and tag the Docker images
echo "Building and tagging Docker images..."
# Navigate to the root directory of the project
cd /Users/nmelo/go/src/github.com/nmelo/saml-tools
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
kubectl apply -f /Users/nmelo/go/src/github.com/nmelo/saml-tools/k8s/00-namespace.yaml

# Generate certificates and create secrets
echo "Generating certificates and creating secrets..."
cd /Users/nmelo/go/src/github.com/nmelo/saml-tools/k8s
chmod +x generate-certs.sh
./generate-certs.sh
kubectl apply -f /Users/nmelo/go/src/github.com/nmelo/saml-tools/k8s/idp-certs-secret.yaml \
              -f /Users/nmelo/go/src/github.com/nmelo/saml-tools/k8s/proxy-certs-secret.yaml \
              -f /Users/nmelo/go/src/github.com/nmelo/saml-tools/k8s/client-certs-secret.yaml

# Update image names in deployment files
echo "Updating deployment files with correct image names..."
cd /Users/nmelo/go/src/github.com/nmelo/saml-tools/k8s
sed -i "" "s|image: saml-tools/samlidp:latest|image: $REGISTRY/$REGISTRY_NAME/samlidp:latest|g" /Users/nmelo/go/src/github.com/nmelo/saml-tools/k8s/02-samlidp.yaml
sed -i "" "s|image: saml-tools/samlproxy:latest|image: $REGISTRY/$REGISTRY_NAME/samlproxy:latest|g" /Users/nmelo/go/src/github.com/nmelo/saml-tools/k8s/03-samlproxy.yaml
sed -i "" "s|image: saml-tools/samlclient:latest|image: $REGISTRY/$REGISTRY_NAME/samlclient:latest|g" /Users/nmelo/go/src/github.com/nmelo/saml-tools/k8s/04-samlclient.yaml

# Apply ConfigMaps
echo "Applying ConfigMaps..."
kubectl apply -f /Users/nmelo/go/src/github.com/nmelo/saml-tools/k8s/01-configmaps.yaml

# Deploy the components sequentially
echo "Deploying IdP..."
kubectl apply -f /Users/nmelo/go/src/github.com/nmelo/saml-tools/k8s/02-samlidp.yaml
echo "Waiting for IdP to be ready..."
kubectl rollout status deployment/samlidp -n $NAMESPACE

echo "Deploying Proxy..."
kubectl apply -f /Users/nmelo/go/src/github.com/nmelo/saml-tools/k8s/03-samlproxy.yaml
echo "Waiting for Proxy to be ready..."
kubectl rollout status deployment/samlproxy -n $NAMESPACE

echo "Deploying Client..."
kubectl apply -f /Users/nmelo/go/src/github.com/nmelo/saml-tools/k8s/04-samlclient.yaml
echo "Waiting for Client to be ready..."
kubectl rollout status deployment/samlclient -n $NAMESPACE

# Update domain names in ingress and configmaps if specified
if [[ -n "$DOMAIN_CLIENT" && -n "$DOMAIN_PROXY" && -n "$DOMAIN_IDP" ]]; then
  echo "Updating domain names in configuration files..."
  
  # Update the ingress hosts
  sed -i "" "s/client.saml-tester.com/$DOMAIN_CLIENT/g" /Users/nmelo/go/src/github.com/nmelo/saml-tools/k8s/05-ingress.yaml
  sed -i "" "s/proxy.saml-tester.com/$DOMAIN_PROXY/g" /Users/nmelo/go/src/github.com/nmelo/saml-tools/k8s/05-ingress.yaml
  sed -i "" "s/idp.saml-tester.com/$DOMAIN_IDP/g" /Users/nmelo/go/src/github.com/nmelo/saml-tools/k8s/05-ingress.yaml
  
  # Update the ConfigMap URLs
  sed -i "" "s|http://client.saml-tester.com|http://$DOMAIN_CLIENT|g" /Users/nmelo/go/src/github.com/nmelo/saml-tools/k8s/01-configmaps.yaml
  sed -i "" "s|http://proxy.saml-tester.com|http://$DOMAIN_PROXY|g" /Users/nmelo/go/src/github.com/nmelo/saml-tools/k8s/01-configmaps.yaml
  sed -i "" "s|http://idp.saml-tester.com|http://$DOMAIN_IDP|g" /Users/nmelo/go/src/github.com/nmelo/saml-tools/k8s/01-configmaps.yaml
  
  echo "Domain names updated successfully."
fi

# Deploy the Ingress
echo "Applying Ingress..."
kubectl apply -f /Users/nmelo/go/src/github.com/nmelo/saml-tools/k8s/05-ingress.yaml

echo "Deployment complete!"
echo "=================="
echo "You can access the services at:"
if [[ -n "$DOMAIN_CLIENT" && -n "$DOMAIN_PROXY" && -n "$DOMAIN_IDP" ]]; then
  echo "- SAML Client: http://$DOMAIN_CLIENT"
  echo "- SAML Proxy: http://$DOMAIN_PROXY"
  echo "- SAML IdP: http://$DOMAIN_IDP"
else
  echo "- SAML Client: http://client.saml-tester.com"
  echo "- SAML Proxy: http://proxy.saml-tester.com"
  echo "- SAML IdP: http://idp.saml-tester.com"
  echo ""
  echo "NOTE: You need to update your DNS records to point these domains to your Digital Ocean cluster's ingress IP"
fi
echo ""
echo "IMPORTANT: Ensure your DNS records are configured correctly to point to your cluster's ingress controller IP"
echo "=================="