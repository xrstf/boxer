default: build

build: fix
	go build -v .

test: fix
	go test

fix: *.go
	goimports -l -w .
	gofmt -l -w .
