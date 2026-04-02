IMG ?= ghcr.io/erenari/aegisbpf-operator:latest

.PHONY: build docker-build docker-push generate install run fmt vet test

build:
	go build -o bin/aegis-operator ./cmd/operator/

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
