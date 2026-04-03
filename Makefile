.PHONY: test generate build podman-build podman-run

test: generate
	go test -v -coverpkg=./... ./...

generate:
	go generate ./...

build: generate
	go build -o dist/wgxdp ./cmd/wgxdp
	go build -o dist/wgxdp-server ./cmd/wgxdp-server

run-dev:
	CONFIG_FILE=./config.yaml ./dist/wgxdp-server

podman-build:
	podman build --security-opt seccomp=unconfined -f Dockerfile.server -t wgxdp-server .

podman-run:
	podman run --cap-add=NET_ADMIN -p 8337:8337 \
		-v ./config.yaml:/config/config.yaml \
		-v wgxdp-data:/data \
		wgxdp-server
