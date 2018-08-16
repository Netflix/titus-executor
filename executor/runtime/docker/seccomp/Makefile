# Rerun this whenever you change your security profiles

all: seccomp.go

seccomp.go: default.json nested-container.json fuse-container.json
	go-bindata -pkg seccomp -o seccomp.go default.json nested-container.json fuse-container.json

