# ====================================================================================
# Setup Project

PROJECT_NAME := provider-mongodb
PROJECT_REPO := github.developer.allianz.io/acp/$(PROJECT_NAME)
GO_SUBDIRS ?= cmd internal

# =================================================================================
# Imports

-include build/makelib/common.mk

GO111MODULE = on

# TODO: Add kubectl download, if required version not installed already
# TODO: Add go download, if required version not installed already
-include build/makelib/golang.mk
-include build/makelib/image.mk

# Base Docker options
DOCKER_REGISTRY=iaactmpreg.azurecr.io

# Options
ORG_NAME=acp
PROVIDER_NAME=provider-mongodb
BASEIMAGE=acp/base-container-image:0.1.4
CONTROLLERBASEIMAGE=$(or $(DOCKER_REGISTRY))$(or $(DOCKER_REPO))/$(BASEIMAGE)

# ====================================================================================
# Utility targets

# Update the submodules, such as the common build scripts.
submodules:
	@$(INFO) git submodule sync/update
	@git submodule sync || $(FAIL)
	@git submodule update --init --recursive || $(FAIL)
	@$(OK) git submodule sync/update

# ====================================================================================
# Main targets

build: generate test
	@$(INFO) go build
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o ./bin/$(PROVIDER_NAME)-controller cmd/provider/main.go || $(FAIL)
	@$(OK) go build

image: generate test
	@$(INFO) docker build
	@docker build . -t $(ORG_NAME)/$(PROVIDER_NAME):latest -f cluster/Dockerfile || $(FAIL)
	@$(OK) docker build

image-push:
	@$(INFO) docker push
	docker push $(ORG_NAME)/$(PROVIDER_NAME):latest || $(FAIL)
	@$(OK) docker push

run: generate
	@run
	@kubectl apply -f package/crds/ -R
	@go run cmd/provider/main.go -d
	@run

crds.clean:
	@$(INFO) crds.clean
	@find package/crds -name *.yaml -exec sed -i.sed -e '1,2d' {} \; || $(FAIL)
	@find package/crds -name *.yaml.sed -delete || $(FAIL)
	@$(OK) crds.clean

generate: crds.clean

lint: $(GOLANGCILINT)
	@$(INFO) golangci-lint
	@golangci-lint run || $(FAIL)
	@$(OK) golangci-lint

tidy:
	@$(INFO) go mod tidy
	@go mod tidy || $(FAIL)
	@$(OK) go mod tidy

test:
	@$(INFO) go test
	@go test -v ./... || $(FAIL)
	@$(OK) go test

generate-clients:
	@go generate ./internal/clients/...

generate-controllers:
	@go generate ./internal/controller/...

all: image image-push

.PHONY: generate tidy lint clean build image all run
