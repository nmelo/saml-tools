#!/bin/bash
set -e

echo "Deploying updated proxy configuration to Kubernetes..."

# Configure kubectl
echo "Configuring kubectl..."
CLUSTER_ID=$(doctl k8s cluster list --format ID --no-header)
doctl k8s cluster kubeconfig save $CLUSTER_ID

# Create updated ConfigMap for proxy only
cat > k8s/samlproxy-config-update.yaml << 'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: samlproxy-config
  namespace: saml-tools
  annotations:
    description: "Updated with new SSO URL for Secure Access IdP"
data:
  samlproxy.yaml: |
    # SAML Proxy Configuration with Multiple IdPs
    listen_addr: ":8082"
    base_url: "https://proxy.saml-tester.com"
    cert_file: "/app/certs/proxy/cert.pem"
    key_file: "/app/certs/proxy/key.pem"
    session_secret: "proxy-strong-secret-key-here"
    proxy_entity_id: "https://proxy.saml-tester.com/metadata"
    debug: true

    # Service Provider configurations
    service_providers:
      - name: "SAML Client"
        entity_id: "urn:samlclient:sp"
        acs_url: "https://client.saml-tester.com/saml/acs"
        metadata_xml_url: "https://client.saml-tester.com/saml/metadata"
        attribute_map:
          "email": "email"
          "username": "username"
          "firstName": "firstName"
          "lastName": "lastName"
          "userId": "userId"
          "roles": "roles"
          "idpId": "idp_id"
          "idpName": "idp_name"

      - name: "Salesforce"
        entity_id: "https://beyondidentity-dev-ed.develop.my.salesforce.com"
        acs_url: "https://beyondidentity-dev-ed.develop.my.salesforce.com"
        metadata_xml_url: "https://beyondidentity-dev-ed.develop.my.salesforce.com/metadata"
        attribute_map:
          "email": "email"
          "username": "username"
          "firstName": "firstName"
          "lastName": "lastName"
          "userId": "userId"
          "roles": "roles"
          "idpId": "idp_id"
          "idpName": "idp_name"

      - name: "Cloudflare"
        entity_id: "https://nmeloco.cloudflareaccess.com/cdn-cgi/access/callback"
        acs_url: "https://nmeloco.cloudflareaccess.com/cdn-cgi/access/callback"
        metadata_xml_url: "https://nmeloco.cloudflareaccess.com/cdn-cgi/access/d4fe8bad-e654-4ce9-b4ff-fae8bd0e2eeb/saml-metadata"
        attribute_map:
          "email": "email"
          "username": "username"
          "firstName": "firstName"
          "lastName": "lastName"
          "userId": "userId"
          "roles": "roles"
          "idpId": "idp_id"
          "idpName": "idp_name"

    # Identity Provider configurations
    identity_providers:
      - id: "bi-v0-demo"
        name: "Secure Workforce"
        description: "Secure Workforce demo tenant"
        logo_url: "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcRjOPILVZchS8DNurm0v8zXqRS783BNh_Mqyw&s"
        metadata_url: "https://auth.byndid.com/saml/v0/38e2efe8-6891-48cd-a36d-560aa4999918/sso/metadata.xml"
        entity_id: "https://auth.byndid.com/saml/v0/38e2efe8-6891-48cd-a36d-560aa4999918/sso/metadata.xml"
        sso_url: "https://auth.byndid.com/saml/v0/38e2efe8-6891-48cd-a36d-560aa4999918/sso"

      - id: "bi-v1-demo"
        name: "Secure Access"
        description: "Secure Access demo tenant"
        logo_url: "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcRjOPILVZchS8DNurm0v8zXqRS783BNh_Mqyw&s"
        metadata_url: "https://auth-us.beyondidentity.com/v1/tenants/00016b5be85b2cd5/realms/b6bf37e4d930855a/applications/0692eb8e-b547-4c46-b325-026c224b2c25/saml/idp/metadata"
        entity_id: "https://auth-us.beyondidentity.com/v1/tenants/00016b5be85b2cd5/realms/b6bf37e4d930855a/applications/0692eb8e-b547-4c46-b325-026c224b2c25/saml/idp/metadata"
        sso_url: "https://auth-us.beyondidentity.com/v1/tenants/00016b5be85b2cd5/realms/b6bf37e4d930855a/applications/0692eb8e-b547-4c46-b325-026c224b2c25/saml/sp/initiate"

      - id: "demo-okta"
        name: "Okta"
        description: "Okta Demo tenant"
        logo_url: "https://logos-world.net/wp-content/uploads/2021/04/Okta-Emblem.png"
        metadata_url: "https://dev-115454.okta.com/app/exkr2t2cpcWXWtnqN4x7/sso/saml/metadata"
        entity_id: "http://www.okta.com/exkr2t2cpcWXWtnqN4x7"
        sso_url: "https://dev-115454.okta.com/app/dev-115454_samlproxy_1/exkr2t2cpcWXWtnqN4x7/sso/saml"

      - id: "test-idp"
        name: "Test IDP"
        description: "A custom identity provider for testing"
        logo_url: "https://www.pngkey.com/png/detail/46-463151_identity-access-and-management-engine-provides-individuals-privacy.png"
        metadata_url: "https://idp.saml-tester.com/metadata"
        entity_id: "https://idp.saml-tester.com/metadata"
        sso_url: "https://idp.saml-tester.com/sso"
        default_idp: false
EOF

# Apply the updated ConfigMap
echo "Applying updated proxy ConfigMap..."
kubectl apply -f k8s/samlproxy-config-update.yaml

# Restart proxy deployment to pick up the new configuration
echo "Restarting proxy deployment..."
kubectl rollout restart deployment/samlproxy -n saml-tools

# Wait for rollout to complete
echo "Waiting for rollout to complete..."
kubectl rollout status deployment/samlproxy -n saml-tools

echo "Proxy configuration deployed successfully!"
echo ""
echo "Changes applied:"
echo "- Updated SSO URL for Secure Access IdP to use sp/initiate endpoint"
echo ""
echo "You can verify the config with:"
echo "kubectl describe configmap samlproxy-config -n saml-tools"