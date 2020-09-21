# Rerun this whenever you change your security profiles

all: seccomp.go

seccomp.go: default.json fuse-container.json
	python3 -m json.tool default.json
	python3 -m json.tool fuse-container.json
	gobin -run -m github.com/jteeuwen/go-bindata/go-bindata -pkg seccomp -o seccomp.go default.json fuse-container.json

