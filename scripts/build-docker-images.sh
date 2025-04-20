#!/bin/bash

# Script to build Docker images for all SAML tools components

set -e

echo "Building SAML Tools Docker images..."

# Create necessary directories
mkdir -p certs/{proxy,idp,client}

# Build the images
echo "Building SAML Proxy image..."
docker build -t saml-tools/samlproxy -f Dockerfile.samlproxy .

echo "Building SAML IdP image..."
docker build -t saml-tools/samlidp -f Dockerfile.samlidp .

echo "Building SAML Client image..."
docker build -t saml-tools/samlclient -f Dockerfile.samlclient .

echo "All images built successfully!"