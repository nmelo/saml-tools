.PHONY: all build clean test run-all run-proxy run-idp run-client setup-certs docker docker-push

# Variables
REGISTRY ?= docker.io/nmelo
VERSION ?= latest
GO_MODULE = github.com/nmelo/saml-tools

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