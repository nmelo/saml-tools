#!/bin/bash

# Generate certificates for SAML components and create Kubernetes secrets
set -e

# Create temporary directory for certificates
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

echo "Generating certificates for SAML components..."

# Function to generate certificates for a component
generate_cert() {
  local component=$1
  local dir="$TEMP_DIR/$component"
  
  mkdir -p "$dir"
  
  echo "Generating certificate for $component..."
  openssl req -x509 -newkey rsa:2048 -keyout "$dir/key.pem" -out "$dir/cert.pem" \
    -days 365 -nodes -subj "/CN=$component.saml-tools.svc.cluster.local"
    
  echo "Creating Kubernetes secret for $component certificates..."
  kubectl create secret generic "$component-certs" \
    --namespace=saml-tools \
    --from-file="$dir/cert.pem" \
    --from-file="$dir/key.pem" \
    --dry-run=client -o yaml > "$component-certs-secret.yaml"
    
  echo "Certificate secret for $component created as $component-certs-secret.yaml"
}

# Generate certificates for each component
generate_cert "idp"
generate_cert "proxy"
generate_cert "client"

echo "All certificate secrets generated successfully!"