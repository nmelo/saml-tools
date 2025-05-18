#!/bin/bash

# Simplified deployment script for DigitalOcean
set -e

# Configuration
REGISTRY="registry.digitalocean.com"
REGISTRY_NAME="${DO_REGISTRY_NAME:-samltools}"
CLUSTER_NAME="${DO_CLUSTER_NAME:-saml-tools-cluster}"
NAMESPACE="saml-tools"
DOMAIN="${DO_DOMAIN:-saml-tools.example.com}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Print colored output
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    print_info "Checking prerequisites..."
    
    # Check for required tools
    for cmd in doctl kubectl docker; do
        if ! command -v $cmd &> /dev/null; then
            print_error "$cmd is not installed. Please install it first."
            exit 1
        fi
    done
    
    # Check doctl authentication
    if ! doctl account get &> /dev/null; then
        print_error "doctl is not authenticated. Run 'doctl auth init' first."
        exit 1
    fi
    
    print_info "All prerequisites met!"
}

# Setup DigitalOcean resources
setup_do_resources() {
    print_info "Setting up DigitalOcean resources..."
    
    # Check if cluster exists
    if ! doctl kubernetes cluster get $CLUSTER_NAME &> /dev/null; then
        print_warning "Kubernetes cluster '$CLUSTER_NAME' not found."
        read -p "Create new cluster? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_info "Creating Kubernetes cluster..."
            doctl kubernetes cluster create $CLUSTER_NAME \
                --region sfo3 \
                --size s-2vcpu-4gb \
                --count 3 \
                --wait
        else
            print_error "Kubernetes cluster is required. Exiting."
            exit 1
        fi
    fi
    
    # Connect to cluster
    print_info "Connecting to Kubernetes cluster..."
    doctl kubernetes cluster kubeconfig save $CLUSTER_NAME
    
    # Check if registry exists
    if ! doctl registry get &> /dev/null; then
        print_warning "Container Registry not found."
        read -p "Create new registry? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_info "Creating Container Registry..."
            doctl registry create $REGISTRY_NAME --subscription-tier basic
        else
            print_error "Container Registry is required. Exiting."
            exit 1
        fi
    fi
    
    # Login to registry
    print_info "Logging in to Container Registry..."
    doctl registry login
}

# Build and push Docker images
build_and_push_images() {
    print_info "Building Docker images..."
    
    docker build -t $REGISTRY/$REGISTRY_NAME/samlproxy:latest -f Dockerfile.samlproxy .
    docker build -t $REGISTRY/$REGISTRY_NAME/samlidp:latest -f Dockerfile.samlidp .
    docker build -t $REGISTRY/$REGISTRY_NAME/samlclient:latest -f Dockerfile.samlclient .
    
    print_info "Pushing images to registry..."
    docker push $REGISTRY/$REGISTRY_NAME/samlproxy:latest
    docker push $REGISTRY/$REGISTRY_NAME/samlidp:latest
    docker push $REGISTRY/$REGISTRY_NAME/samlclient:latest
}

# Deploy to Kubernetes
deploy_to_kubernetes() {
    print_info "Deploying to Kubernetes..."
    
    # Create namespace
    kubectl apply -f k8s/00-namespace.yaml
    
    # Update deployment files with correct image names
    for file in k8s/02-samlidp.yaml k8s/03-samlproxy.yaml k8s/04-samlclient.yaml; do
        cp $file $file.tmp
        sed -i.bak "s|image: .*samlidp:latest|image: $REGISTRY/$REGISTRY_NAME/samlidp:latest|g" $file.tmp
        sed -i.bak "s|image: .*samlproxy:latest|image: $REGISTRY/$REGISTRY_NAME/samlproxy:latest|g" $file.tmp
        sed -i.bak "s|image: .*samlclient:latest|image: $REGISTRY/$REGISTRY_NAME/samlclient:latest|g" $file.tmp
    done
    
    # Generate certificates if they don't exist
    if ! kubectl get secret idp-certs -n $NAMESPACE &> /dev/null; then
        print_info "Generating self-signed certificates..."
        cd k8s
        ./generate-certs.sh
        cd ..
    fi
    
    # Apply configurations
    kubectl apply -f k8s/01-configmaps.yaml
    kubectl apply -f k8s/02-samlidp.yaml.tmp
    kubectl apply -f k8s/03-samlproxy.yaml.tmp
    kubectl apply -f k8s/04-samlclient.yaml.tmp
    
    # Clean up temp files
    rm -f k8s/*.tmp k8s/*.bak
    
    # Apply ingress
    kubectl apply -f k8s/05-ingress.yaml
    
    # Wait for deployments
    print_info "Waiting for deployments to be ready..."
    kubectl wait --for=condition=available --timeout=300s deployment/samlidp -n $NAMESPACE
    kubectl wait --for=condition=available --timeout=300s deployment/samlproxy -n $NAMESPACE
    kubectl wait --for=condition=available --timeout=300s deployment/samlclient -n $NAMESPACE
}

# Get ingress IP
get_ingress_info() {
    print_info "Getting ingress information..."
    
    # Wait for load balancer IP
    print_info "Waiting for load balancer IP..."
    while true; do
        LB_IP=$(kubectl get ingress -n $NAMESPACE -o jsonpath='{.items[0].status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)
        if [ -n "$LB_IP" ]; then
            break
        fi
        echo -n "."
        sleep 5
    done
    echo
    
    print_info "Load Balancer IP: $LB_IP"
    echo
    print_warning "Please configure your DNS with these A records:"
    echo "  client.$DOMAIN → $LB_IP"
    echo "  proxy.$DOMAIN → $LB_IP"
    echo "  idp.$DOMAIN → $LB_IP"
    echo
    print_info "Once DNS is configured, your services will be available at:"
    echo "  https://client.$DOMAIN"
    echo "  https://proxy.$DOMAIN"
    echo "  https://idp.$DOMAIN"
}

# Main deployment flow
main() {
    print_info "Starting SAML Tools deployment to DigitalOcean..."
    
    check_prerequisites
    setup_do_resources
    build_and_push_images
    deploy_to_kubernetes
    get_ingress_info
    
    print_info "Deployment completed successfully!"
    print_warning "Remember to configure your DNS records!"
}

# Run main function
main