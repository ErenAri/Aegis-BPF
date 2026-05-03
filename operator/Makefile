IMG ?= ghcr.io/erenari/aegisbpf-operator:latest

# Pin controller-gen to the version used to last regenerate the CRDs and
# deepcopy. Bumping this is intentional and should be a separate commit.
CONTROLLER_GEN_VERSION ?= v0.14.0
CONTROLLER_GEN          = $(shell pwd)/bin/controller-gen

.PHONY: build build-fleet docker-build docker-push generate install run fmt vet test \
        controller-gen manifests deepcopy verify-generated

build:
	go build -o bin/aegis-operator ./cmd/operator/

build-fleet:
	go build -o bin/aegisfleet ./cmd/aegisfleet/

docker-build:
	docker build -t $(IMG) .

docker-push:
	docker push $(IMG)

install:
	kubectl apply -f config/crd/

uninstall:
	kubectl delete -f config/crd/

run: build
	./bin/aegis-operator --leader-elect=false

fmt:
	go fmt ./...

vet:
	go vet ./...

test:
	go test ./... -v -count=1

deploy: install
	kubectl apply -f config/rbac/
	kubectl apply -f config/manager/

# controller-gen targets ----------------------------------------------------
#
# `make manifests` regenerates CRD YAML from kubebuilder markers in api/.
# `make deepcopy` regenerates zz_generated.deepcopy.go.
# `make generate` runs both. CI should run `make verify-generated` to fail
# the build if either set of files is stale.
controller-gen:
	@test -x $(CONTROLLER_GEN) || \
		GOBIN=$(shell pwd)/bin go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION)

manifests: controller-gen
	$(CONTROLLER_GEN) crd paths="./api/..." output:crd:artifacts:config=config/crd

deepcopy: controller-gen
	$(CONTROLLER_GEN) object paths="./api/..."

generate: manifests deepcopy

verify-generated: generate
	@git diff --exit-code -- api/ config/crd/ || \
		(echo "ERROR: generated files are out of date. Run 'make generate' and commit the result." && exit 1)
