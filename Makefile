default: build

build: fix
	go build -v .

test: fix
	go test -v

fix: *.go
	goimports -l -w .
	gofmt -l -w .

travis:
	go get golang.org/x/crypto/nacl/secretbox
	go get golang.org/x/crypto/scrypt
	go test -v
