.PHONY: all build clean test run-all run-proxy run-idp run-client setup-certs docker docker-push aws-deploy aws-deploy-quick

# Variables
REGISTRY ?= docker.io/nmelo
VERSION ?= latest
GO_MODULE = github.com/nmelo/saml-tools

# AWS Variables
AWS_PROFILE ?= default
AWS_REGION ?= us-east-1
AWS_ACCOUNT_ID ?= $(shell aws sts get-caller-identity --profile $(AWS_PROFILE) --query Account --output text)
ECR_REGISTRY ?= $(AWS_ACCOUNT_ID).dkr.ecr.$(AWS_REGION).amazonaws.com
ECR_REPO_PREFIX ?= saml-tools

# Build all components
all: build

build:
	mkdir -p bin
	go build -o bin/samlproxy ./cmd/samlproxy
	go build -o bin/samlidp ./cmd/samlidp
	go build -o bin/samlclient ./cmd/samlclient

# Clean up binaries
clean:
	rm -rf bin/

# Run all tests
test:
	go test ./...

# Run all components
run-all: build
	./bin/samlidp & \
	sleep 5 && \
	./bin/samlproxy & \
	sleep 5 && \
	./bin/samlclient

# Run individual components
run-proxy: build
	./bin/samlproxy

run-idp: build
	./bin/samlidp

run-client: build
	./bin/samlclient

# Generate certificates for testing
setup-certs:
	mkdir -p certs/{proxy,idp,client}
	openssl req -x509 -newkey rsa:2048 -keyout certs/proxy/key.pem -out certs/proxy/cert.pem -days 365 -nodes -subj "/CN=localhost"
	openssl req -x509 -newkey rsa:2048 -keyout certs/idp/key.pem -out certs/idp/cert.pem -days 365 -nodes -subj "/CN=localhost"
	openssl req -x509 -newkey rsa:2048 -keyout certs/client/key.pem -out certs/client/cert.pem -days 365 -nodes -subj "/CN=localhost"

# Build Docker images
docker:
	docker build -t $(REGISTRY)/samlproxy:$(VERSION) -f Dockerfile.samlproxy .
	docker build -t $(REGISTRY)/samlidp:$(VERSION) -f Dockerfile.samlidp .
	docker build -t $(REGISTRY)/samlclient:$(VERSION) -f Dockerfile.samlclient .

# Push Docker images
docker-push:
	docker push $(REGISTRY)/samlproxy:$(VERSION)
	docker push $(REGISTRY)/samlidp:$(VERSION)
	docker push $(REGISTRY)/samlclient:$(VERSION)

# Initialize a new component (usage: make init-component NAME=newcomponent)
init-component:
	mkdir -p cmd/$(NAME) internal/$(NAME)
	echo "package main\n\nimport (\n\t\"$(GO_MODULE)/internal/$(NAME)\"\n)\n\nfunc main() {\n\t// Initialize and run the service\n}" > cmd/$(NAME)/main.go
	echo "package $(NAME)\n\n// Service represents the $(NAME) service\ntype Service struct {\n}\n\n// NewService creates a new $(NAME) service\nfunc NewService() *Service {\n\treturn &Service{}\n}" > internal/$(NAME)/$(NAME).go

# Create documentation
docs:
	mkdir -p docs
	[ -d docs/$(NAME) ] || mkdir -p docs/$(NAME)
	touch docs/$(NAME)/README.md

# Deploy to Kubernetes
k8s-deploy:
	kubectl apply -f k8s/00-namespace.yaml
	kubectl apply -f k8s/01-configmaps.yaml
	kubectl apply -f k8s/02-samlidp.yaml
	kubectl apply -f k8s/03-samlproxy.yaml
	kubectl apply -f k8s/04-samlclient.yaml
	kubectl apply -f k8s/05-ingress.yaml

# Deploy with TLS to Kubernetes
k8s-deploy-tls:
	kubectl apply -f k8s/00-namespace.yaml
	kubectl apply -f k8s/01-configmaps-https.yaml
	kubectl apply -f k8s/02-samlidp.yaml
	kubectl apply -f k8s/03-samlproxy.yaml
	kubectl apply -f k8s/04-samlclient.yaml
	kubectl apply -f k8s/05-ingress-tls.yaml

# AWS ECR login
aws-ecr-login:
	aws ecr get-login-password --profile $(AWS_PROFILE) --region $(AWS_REGION) | docker login --username AWS --password-stdin $(ECR_REGISTRY)

# Build and push Docker images to AWS ECR
aws-docker: aws-ecr-login
	docker build -t $(ECR_REGISTRY)/$(ECR_REPO_PREFIX)/samlproxy:$(VERSION) -f Dockerfile.samlproxy .
	docker build -t $(ECR_REGISTRY)/$(ECR_REPO_PREFIX)/samlidp:$(VERSION) -f Dockerfile.samlidp .
	docker build -t $(ECR_REGISTRY)/$(ECR_REPO_PREFIX)/samlclient:$(VERSION) -f Dockerfile.samlclient .
	docker push $(ECR_REGISTRY)/$(ECR_REPO_PREFIX)/samlproxy:$(VERSION)
	docker push $(ECR_REGISTRY)/$(ECR_REPO_PREFIX)/samlidp:$(VERSION)
	docker push $(ECR_REGISTRY)/$(ECR_REPO_PREFIX)/samlclient:$(VERSION)

# Full AWS deployment (runs the deployment script)
aws-deploy:
	AWS_PROFILE=$(AWS_PROFILE) AWS_REGION=$(AWS_REGION) ./deploy-to-aws.sh

# Quick AWS deployment (assumes infrastructure exists)
aws-deploy-quick: aws-docker
	kubectl apply -f k8s/00-namespace.yaml
	kubectl apply -f k8s/01-configmaps-https.yaml
	@for file in k8s/02-samlidp.yaml k8s/03-samlproxy.yaml k8s/04-samlclient.yaml; do \
		sed "s|image: .*samlidp:latest|image: $(ECR_REGISTRY)/$(ECR_REPO_PREFIX)/samlidp:latest|g; \
		     s|image: .*samlproxy:latest|image: $(ECR_REGISTRY)/$(ECR_REPO_PREFIX)/samlproxy:latest|g; \
		     s|image: .*samlclient:latest|image: $(ECR_REGISTRY)/$(ECR_REPO_PREFIX)/samlclient:latest|g" $$file | kubectl apply -f -; \
	done
	kubectl apply -f k8s/05-ingress-aws-alb.yaml