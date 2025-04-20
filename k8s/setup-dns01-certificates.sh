#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Starting DNS-01 challenge setup for Let's Encrypt certificates...${NC}"

# Ensure cert-manager namespace exists
kubectl get namespace cert-manager &>/dev/null || kubectl create namespace cert-manager

# Apply Cloudflare API token secret
echo -e "${YELLOW}Applying Cloudflare API token secret...${NC}"
kubectl apply -f cloudflare-api-token-secret.yaml
echo -e "${GREEN}Cloudflare API token secret applied.${NC}"

# Apply staging ClusterIssuer
echo -e "${YELLOW}Applying Let's Encrypt staging ClusterIssuer with DNS-01...${NC}"
kubectl apply -f letsencrypt-staging-dns01-issuer.yaml
echo -e "${GREEN}Staging ClusterIssuer applied.${NC}"

# Apply ingress with TLS configuration using staging issuer
echo -e "${YELLOW}Applying ingress with TLS configuration using staging issuer...${NC}"
kubectl apply -f 05-ingress-tls.yaml
echo -e "${GREEN}Ingress with TLS applied.${NC}"

# Wait for staging certificates
echo -e "${YELLOW}Waiting for staging certificates to be issued (this may take a few minutes)...${NC}"
attempts=0
max_attempts=30

while [ $attempts -lt $max_attempts ]; do
  client_ready=$(kubectl get certificate client-tls-cert -n saml-tools -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "NotFound")
  proxy_ready=$(kubectl get certificate proxy-tls-cert -n saml-tools -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "NotFound")
  idp_ready=$(kubectl get certificate idp-tls-cert -n saml-tools -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "NotFound")
  
  if [[ "$client_ready" == "True" && "$proxy_ready" == "True" && "$idp_ready" == "True" ]]; then
    echo -e "${GREEN}All staging certificates have been issued successfully!${NC}"
    break
  fi
  
  echo -e "${YELLOW}Certificates status: client=$client_ready, proxy=$proxy_ready, idp=$idp_ready. Waiting...${NC}"
  sleep 10
  attempts=$((attempts + 1))
done

if [ $attempts -eq $max_attempts ]; then
  echo -e "${RED}Timed out waiting for staging certificates. Check cert-manager logs for issues.${NC}"
  exit 1
fi

# Verify that the staging certificates work
echo -e "${YELLOW}Verifying staging certificates...${NC}"
echo -e "${YELLOW}You can now test your domains with HTTPS. They will show as insecure due to staging certificates.${NC}"
echo -e "${YELLOW}Test URLs:${NC}"
echo -e "${YELLOW}- https://client.saml-tester.com${NC}"
echo -e "${YELLOW}- https://proxy.saml-tester.com${NC}"
echo -e "${YELLOW}- https://idp.saml-tester.com${NC}"

read -p "Do the staging certificates work correctly? (yes/no): " staging_works
if [[ "$staging_works" != "yes" ]]; then
  echo -e "${RED}Exiting without proceeding to production certificates. Please check the logs and configuration.${NC}"
  exit 1
fi

# Apply production ClusterIssuer
echo -e "${YELLOW}Applying Let's Encrypt production ClusterIssuer with DNS-01...${NC}"
kubectl apply -f letsencrypt-prod-dns01-issuer.yaml
echo -e "${GREEN}Production ClusterIssuer applied.${NC}"

# Update ingress to use production issuer
echo -e "${YELLOW}Updating ingress to use production issuer...${NC}"
kubectl patch ingress saml-tools-ingress -n saml-tools -p '{"metadata":{"annotations":{"cert-manager.io/cluster-issuer":"letsencrypt-prod-dns01"}}}'
echo -e "${GREEN}Ingress updated to use production issuer.${NC}"

# Delete existing certificates to trigger reissuance with production issuer
echo -e "${YELLOW}Deleting existing staging certificates to trigger reissuance...${NC}"
kubectl delete certificate client-tls-cert proxy-tls-cert idp-tls-cert -n saml-tools || true
echo -e "${GREEN}Certificates deleted. New production certificates will be issued automatically.${NC}"

# Wait for production certificates
echo -e "${YELLOW}Waiting for production certificates to be issued (this may take a few minutes)...${NC}"
attempts=0

while [ $attempts -lt $max_attempts ]; do
  client_ready=$(kubectl get certificate client-tls-cert -n saml-tools -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "NotFound")
  proxy_ready=$(kubectl get certificate proxy-tls-cert -n saml-tools -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "NotFound")
  idp_ready=$(kubectl get certificate idp-tls-cert -n saml-tools -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "NotFound")
  
  if [[ "$client_ready" == "True" && "$proxy_ready" == "True" && "$idp_ready" == "True" ]]; then
    echo -e "${GREEN}All production certificates have been issued successfully!${NC}"
    break
  fi
  
  echo -e "${YELLOW}Certificates status: client=$client_ready, proxy=$proxy_ready, idp=$idp_ready. Waiting...${NC}"
  sleep 10
  attempts=$((attempts + 1))
done

if [ $attempts -eq $max_attempts ]; then
  echo -e "${RED}Timed out waiting for production certificates. Check cert-manager logs for issues.${NC}"
  exit 1
fi

# Update ConfigMaps to use HTTPS URLs
echo -e "${YELLOW}Updating ConfigMaps to use HTTPS URLs...${NC}"
kubectl apply -f 01-configmaps-https.yaml
echo -e "${GREEN}ConfigMaps updated for HTTPS.${NC}"

# Restart deployments to pick up the new configuration
echo -e "${YELLOW}Restarting deployments to pick up the new configuration...${NC}"
kubectl rollout restart deployment/samlidp deployment/samlproxy deployment/samlclient -n saml-tools
echo -e "${GREEN}Deployments restarted.${NC}"

echo -e "${GREEN}DNS-01 certificate setup complete! Your SAML tools are now secured with valid Let's Encrypt certificates.${NC}"
echo -e "${GREEN}You can access your services at:${NC}"
echo -e "${GREEN}- https://client.saml-tester.com${NC}"
echo -e "${GREEN}- https://proxy.saml-tester.com${NC}"
echo -e "${GREEN}- https://idp.saml-tester.com${NC}"