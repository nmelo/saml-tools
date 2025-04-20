# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands
- Build all: `make build`
- Run tests: `make test`
- Run specific test: `go test ./internal/samlidp -run TestHandleHome`
- Clean: `make clean`
- Setup certificates: `make setup-certs`
- Docker build: `make docker`

## Run Commands
- Run all: `make run-all`
- Run IDP: `make run-idp`
- Run proxy: `make run-proxy`
- Run client: `make run-client`

## Code Style Guidelines
- Imports: standard library first, third-party next, internal last
- Error handling: check immediately and return with context
- Types: use descriptive names, prefer strong typing
- Naming: use camelCase for variables, PascalCase for exported functions/types
- Testing: write unit tests for all components, use table-driven tests
- Documentation: add godoc comments for all exported functions and types
- Structure: follow standard Go project layout (cmd/, internal/, pkg/)