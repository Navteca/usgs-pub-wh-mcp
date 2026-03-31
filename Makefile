SHELL := /bin/sh

AWS_REGION ?= us-east-1
AWS_PROFILE ?= navteca
IMAGE_URI ?= 607399646027.dkr.ecr.us-east-1.amazonaws.com/navteca/images/usgs-mcp:latest
IMAGE_PLATFORMS ?= linux/amd64,linux/arm64
LOCAL_IMAGE_PLATFORM ?= linux/amd64
BUILDX_BUILDER ?=
CHART_DIR ?= chart
CHART_PACKAGE_DIR ?= dist
CHART_NAME ?= $(shell sed -n 's/^name: //p' $(CHART_DIR)/Chart.yaml | head -n 1)
CHART_VERSION ?= $(shell sed -n 's/^version: //p' $(CHART_DIR)/Chart.yaml | head -n 1)
CHART_REGISTRY ?= oci://607399646027.dkr.ecr.us-east-1.amazonaws.com/navteca/helm
CHART_PACKAGE ?= $(CHART_PACKAGE_DIR)/$(CHART_NAME)-$(CHART_VERSION).tgz

.PHONY: image ecr-login build-image push-image chart-lint chart-package chart-login chart-push chart-release

image: ecr-login push-image

ecr-login:
	@registry="$${IMAGE_URI%%/*}"; \
	printf 'Logging into ECR registry %s with AWS profile %s in region %s\n' "$$registry" "$(AWS_PROFILE)" "$(AWS_REGION)"; \
	aws ecr get-login-password --region "$(AWS_REGION)" --profile "$(AWS_PROFILE)" | \
		docker login --username AWS --password-stdin "$$registry"

build-image:
	@case "$(IMAGE_URI)" in \
		*:* ) ;; \
		* ) printf 'IMAGE_URI must include a tag, for example registry/repo:0.1.2\n' >&2; exit 1 ;; \
	esac; \
	builder_arg=""; \
	if [ -n "$(BUILDX_BUILDER)" ]; then builder_arg="--builder $(BUILDX_BUILDER)"; fi; \
	printf 'Building local image %s with:\n' "$(IMAGE_URI)"; \
	printf 'AWS_PROFILE=%s\n' "$(AWS_PROFILE)"; \
	printf 'AWS_REGION=%s\n' "$(AWS_REGION)"; \
	printf 'LOCAL_IMAGE_PLATFORM=%s\n' "$(LOCAL_IMAGE_PLATFORM)"; \
	docker buildx build $$builder_arg \
		--platform "$(LOCAL_IMAGE_PLATFORM)" \
		-t "$(IMAGE_URI)" \
		--load \
		.

push-image:
	@case "$(IMAGE_URI)" in \
		*:* ) ;; \
		* ) printf 'IMAGE_URI must include a tag, for example registry/repo:0.1.2\n' >&2; exit 1 ;; \
	esac; \
	builder_arg=""; \
	if [ -n "$(BUILDX_BUILDER)" ]; then builder_arg="--builder $(BUILDX_BUILDER)"; fi; \
	printf 'Building and pushing multi-arch image %s with:\n' "$(IMAGE_URI)"; \
	printf 'AWS_PROFILE=%s\n' "$(AWS_PROFILE)"; \
	printf 'AWS_REGION=%s\n' "$(AWS_REGION)"; \
	printf 'IMAGE_PLATFORMS=%s\n' "$(IMAGE_PLATFORMS)"; \
	docker buildx build $$builder_arg \
		--platform "$(IMAGE_PLATFORMS)" \
		-t "$(IMAGE_URI)" \
		--push \
		.

chart-lint:
	@printf 'Linting Helm chart in %s\n' "$(CHART_DIR)"; \
	helm lint "$(CHART_DIR)"

chart-package: chart-lint
	@mkdir -p "$(CHART_PACKAGE_DIR)"; \
	printf 'Packaging Helm chart %s version %s into %s\n' "$(CHART_NAME)" "$(CHART_VERSION)" "$(CHART_PACKAGE_DIR)"; \
	helm package "$(CHART_DIR)" --destination "$(CHART_PACKAGE_DIR)"

chart-login:
	@registry="$$(printf '%s\n' "$(CHART_REGISTRY)" | sed 's#^oci://##' | cut -d/ -f1)"; \
	printf 'Logging Helm into OCI registry %s with AWS profile %s in region %s\n' "$$registry" "$(AWS_PROFILE)" "$(AWS_REGION)"; \
	aws ecr get-login-password --region "$(AWS_REGION)" --profile "$(AWS_PROFILE)" | \
		helm registry login --username AWS --password-stdin "$$registry"

chart-push: chart-package chart-login
	@printf 'Pushing Helm chart %s to %s\n' "$(CHART_PACKAGE)" "$(CHART_REGISTRY)"; \
	helm push "$(CHART_PACKAGE)" "$(CHART_REGISTRY)"

chart-release: chart-push
