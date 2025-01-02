fmt:
	go fmt ./...

install:
	go install github.com/meetwithabhishek/peeki

lint:
	golangci-lint run --timeout 5m

tidy:
	go mod tidy

vendor: tidy
	go mod vendor

.PHONY: fmt lint install