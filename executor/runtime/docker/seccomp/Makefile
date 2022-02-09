# Rerun this whenever you change your security profiles

all: seccomp.go

test:
	go test -v github.com/Netflix/titus-executor/executor/runtime/docker/seccomp

seccomp.go: default.json fuse-container.json allow-perf-syscalls.json
	python3 -m json.tool default.json >/dev/null
	python3 -m json.tool fuse-container.json >/dev/null
	python3 -m json.tool allow-perf-syscalls.json >/dev/null
	gobin -run github.com/kevinburke/go-bindata/go-bindata@v3.21.0 -pkg seccomp -o seccomp.go default.json fuse-container.json allow-perf-syscalls.json

