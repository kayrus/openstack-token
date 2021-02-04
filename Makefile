PKG:=github.com/kayrus/openstack-token
APP_NAME:=token
PWD:=$(shell pwd)
UID:=$(shell id -u)
LDFLAGS:=-w -s

export CGO_ENABLED:=0

build: fmt vet
	GOOS=linux go build -mod=vendor -ldflags="$(LDFLAGS)" -o bin/$(APP_NAME) ./cmd
	GOOS=darwin go build -mod=vendor -ldflags="$(LDFLAGS)" -o bin/$(APP_NAME)_darwin ./cmd
	GOOS=windows go build -mod=vendor -ldflags="$(LDFLAGS)" -o bin/$(APP_NAME).exe ./cmd

docker:
	docker run -ti --rm -e GOCACHE=/tmp -v $(PWD):/$(APP_NAME) -u $(UID):$(UID) --workdir /$(APP_NAME) golang:latest make

fmt:
	gofmt -s -w cmd token

vet:
	go vet -mod=vendor ./cmd/... ./token/...

static:
	staticcheck ./cmd/... ./token/...

mod:
	go mod vendor

.PHONY: test
test:
	go test -count 1 ./token/testing

test-debug:
	go test -v -count 1 ./token/testing -debug
