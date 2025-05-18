#!/bin/bash
set -e

echo "Updating ConfigMaps in Kubernetes..."

# Configure kubectl
echo "Configuring kubectl..."
CLUSTER_ID=$(doctl k8s cluster list --format ID --no-header)
doctl k8s cluster kubeconfig save $CLUSTER_ID

# Apply the configmap updates
echo "Applying ConfigMap updates..."
kubectl apply -f k8s/01-configmaps-https.yaml

# Restart deployments to pick up the new configurations
echo "Restarting deployments to load new configs..."
kubectl rollout restart deployment/samlclient -n saml-tools
kubectl rollout restart deployment/samlproxy -n saml-tools
kubectl rollout restart deployment/samlidp -n saml-tools

# Wait for rollouts to complete
echo "Waiting for rollouts to complete..."
kubectl rollout status deployment/samlclient -n saml-tools
kubectl rollout status deployment/samlproxy -n saml-tools
kubectl rollout status deployment/samlidp -n saml-tools

echo "ConfigMap updates completed successfully!"
echo ""
echo "You can verify the configs with:"
echo "kubectl get configmap -n saml-tools"
echo "kubectl describe configmap samlproxy-config -n saml-tools"
echo "kubectl describe configmap samlidp-config -n saml-tools"
echo "kubectl describe configmap samlclient-config -n saml-tools"