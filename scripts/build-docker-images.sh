#!/bin/bash

# Script to build Docker images for all SAML tools components
# Usage: 
#   ./build-docker-images.sh         # Build for local development using host architecture
#   ./build-docker-images.sh linux   # Build for Linux/amd64 (for deployment to Digital Ocean)

set -e

# Check if we're building for Linux deployment
PLATFORM_ARG=""
TARGET="local development"

if [ "$1" = "linux" ]; then
  PLATFORM_ARG="--platform=linux/amd64"
  TARGET="Linux deployment"
  
  # Set the GOOS and GOARCH for the build
  export GOOS=linux
  export GOARCH=amd64
else
  # For local development, use the host's native architecture
  unset GOOS
  unset GOARCH
fi

echo "Building SAML Tools Docker images for $TARGET..."

# Create necessary directories
mkdir -p certs/{proxy,idp,client}

# Build the images
echo "Building SAML Proxy image..."
docker build $PLATFORM_ARG -t saml-tools/samlproxy -f Dockerfile.samlproxy.local .

echo "Building SAML IdP image..."
docker build $PLATFORM_ARG -t saml-tools/samlidp -f Dockerfile.samlidp.local .

echo "Building SAML Client image..."
docker build $PLATFORM_ARG -t saml-tools/samlclient -f Dockerfile.samlclient.local .

echo "All images built successfully!"