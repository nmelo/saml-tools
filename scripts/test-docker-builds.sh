#!/bin/bash

set -e

echo "Testing Docker builds to ensure they compile correctly..."

# Change to project root directory
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Try building the Docker images
echo "Building the Docker images..."

echo "Building SAML IdP..."
if ! docker build -t samlidp:test -f Dockerfile.samlidp .; then
  echo "Error: Failed to build SAML IdP image"
  exit 1
fi
echo "✅ SAML IdP built successfully"

echo "Building SAML Proxy..."
if ! docker build -t samlproxy:test -f Dockerfile.samlproxy .; then
  echo "Error: Failed to build SAML Proxy image"
  exit 1
fi
echo "✅ SAML Proxy built successfully"

echo "Building SAML Client..."
if ! docker build -t samlclient:test -f Dockerfile.samlclient .; then
  echo "Error: Failed to build SAML Client image"
  exit 1
fi
echo "✅ SAML Client built successfully"

echo "All Docker images built successfully!"
echo "You can now proceed with the deployment."