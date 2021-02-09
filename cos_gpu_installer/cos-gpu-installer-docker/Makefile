SHELL := /bin/bash
REPO := $(shell git rev-parse --show-toplevel)
IMAGE := "cos-gpu-installer-github"
REGISTRY := "gcr.io/api-project-421333809285"

.PHONY: all
all:
	DOCKER_BUILDKIT=1 docker build -q --force-rm -t cos-gpu-installer-github:latest .
	docker tag "$(IMAGE):latest" "$(REGISTRY)/$(IMAGE)"
	docker push -q "$(REGISTRY)/$(IMAGE)"
