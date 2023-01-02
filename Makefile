.DEFAULT_GOAL := build

.PHONY: update
update:
	go get -u
	go mod tidy

.PHONY: build
build: test
	go fmt ./...
	go vet ./...
	go build

.PHONY: run
run: build
	./stunner

.PHONY: lint
lint:
	"$$(go env GOPATH)/bin/golangci-lint" run ./...
	go mod tidy

.PHONY: lint-update
lint-update:
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin
	$$(go env GOPATH)/bin/golangci-lint --version

.PHONY: test
test:
	go test -race -cover ./...

.PHONY: tag
tag:
	@[ "${TAG}" ] && echo "Tagging a new version ${TAG}" || ( echo "TAG is not set"; exit 1 )
	git tag -a "${TAG}" -m "${TAG}"
	git push origin "${TAG}"

.PHONY: windows
windows:
	GOOS=windows GOARCH=amd64 go fmt ./...
	GOOS=windows GOARCH=amd64 go vet ./...
	GOOS=windows GOARCH=amd64 go build
