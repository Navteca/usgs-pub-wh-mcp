SHELL := /bin/sh

ENV_FILE ?= .env
AWS_REGION ?= us-east-1
AWS_PROFILE ?= navteca
IMAGE_URI ?= 607399646027.dkr.ecr.us-east-1.amazonaws.com/navteca/images/usgs-mcp:latest

.PHONY: image prepare-env print-image-env ecr-login build-image push-image

image: prepare-env ecr-login build-image push-image

prepare-env:
	@touch "$(ENV_FILE)"; \
	api_key="$$(sed -n 's/^USGS_MCP_API_KEY=//p' "$(ENV_FILE)" | tail -n 1)"; \
	bearer_token="$$(sed -n 's/^USGS_MCP_BEARER_TOKEN=//p' "$(ENV_FILE)" | tail -n 1)"; \
	if [ -z "$$api_key" ]; then \
		api_key="$$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 64)"; \
	fi; \
	if [ -z "$$bearer_token" ]; then \
		bearer_token="usgs_$$(LC_ALL=C tr -dc 'A-Za-z0-9_-' </dev/urandom | head -c 64)"; \
	fi; \
	tmp_file="$$(mktemp)"; \
	awk -F= -v api_key="$$api_key" -v bearer_token="$$bearer_token" '\
	BEGIN { api_done=0; bearer_done=0 } \
	$$1 == "USGS_MCP_API_KEY" { print "USGS_MCP_API_KEY=" api_key; api_done=1; next } \
	$$1 == "USGS_MCP_BEARER_TOKEN" { print "USGS_MCP_BEARER_TOKEN=" bearer_token; bearer_done=1; next } \
	{ print } \
	END { \
		if (!api_done) print "USGS_MCP_API_KEY=" api_key; \
		if (!bearer_done) print "USGS_MCP_BEARER_TOKEN=" bearer_token; \
	}' "$(ENV_FILE)" > "$$tmp_file"; \
	mv "$$tmp_file" "$(ENV_FILE)"; \
	printf 'Prepared %s with:\n' "$(ENV_FILE)"; \
	printf 'USGS_MCP_API_KEY=%s\n' "$$api_key"; \
	printf 'USGS_MCP_BEARER_TOKEN=%s\n' "$$bearer_token"

print-image-env: prepare-env
	@sed -n '/^USGS_MCP_API_KEY=/p;/^USGS_MCP_BEARER_TOKEN=/p' "$(ENV_FILE)"

ecr-login:
	@registry="$${IMAGE_URI%%/*}"; \
	printf 'Logging into ECR registry %s with AWS profile %s in region %s\n' "$$registry" "$(AWS_PROFILE)" "$(AWS_REGION)"; \
	aws ecr get-login-password --region "$(AWS_REGION)" --profile "$(AWS_PROFILE)" | \
		docker login --username AWS --password-stdin "$$registry"

build-image: prepare-env
	@case "$(IMAGE_URI)" in \
		*:* ) ;; \
		* ) printf 'IMAGE_URI must include a tag, for example registry/repo:0.1.2\n' >&2; exit 1 ;; \
	esac; \
	api_key="$$(sed -n 's/^USGS_MCP_API_KEY=//p' "$(ENV_FILE)" | tail -n 1)"; \
	bearer_token="$$(sed -n 's/^USGS_MCP_BEARER_TOKEN=//p' "$(ENV_FILE)" | tail -n 1)"; \
	printf 'Building image %s with:\n' "$(IMAGE_URI)"; \
	printf 'AWS_PROFILE=%s\n' "$(AWS_PROFILE)"; \
	printf 'AWS_REGION=%s\n' "$(AWS_REGION)"; \
	printf 'USGS_MCP_API_KEY=%s\n' "$$api_key"; \
	printf 'USGS_MCP_BEARER_TOKEN=%s\n' "$$bearer_token"; \
	docker build \
		--build-arg USGS_MCP_API_KEY="$$api_key" \
		--build-arg USGS_MCP_BEARER_TOKEN="$$bearer_token" \
		-t "$(IMAGE_URI)" \
		.

push-image:
	@printf 'Pushing image %s\n' "$(IMAGE_URI)"; \
	docker push "$(IMAGE_URI)"
