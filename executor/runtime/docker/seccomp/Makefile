# Rerun this whenever you change your security profiles

all: seccomp.go

seccomp.go: default.json fuse-container.json
	python3 -m json.tool default.json
	python3 -m json.tool fuse-container.json
	gobin -run github.com/kevinburke/go-bindata/go-bindata@v3.21.0 -pkg seccomp -o seccomp.go default.json fuse-container.json

