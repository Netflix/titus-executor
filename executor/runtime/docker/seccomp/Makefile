# Rerun this whenever you change your security profiles
all: seccomp.go

stock.docker.json:
	wget https://raw.githubusercontent.com/moby/moby/master/profiles/seccomp/default.json -O $@

# Update these json files with these steps:
# 1. (optional) `rm stock.docker.json ; make stock.docker.json` to get a fresh upstream policy from docker
# 2. Edit any of the jsonnet files, even with comments to your heart's content, then run `make patches` to save your diffs
# 3. `make all` to generate final json files and in turn go binary files for titus-executor to use

default.jsonnet: stock.docker.json default.patch
	rm -f $@
	patch stock.docker.json --input=default.patch  --output=$@ --batch

fuse-container.jsonnet: stock.docker.json fuse-container.patch
	rm -f $@
	patch stock.docker.json --input=fuse-container.patch  --output=$@ --batch

allow-perf-syscalls.jsonnet: stock.docker.json allow-perf-syscalls.patch
	rm -f $@
	patch stock.docker.json --input=allow-perf-syscalls.patch  --output=$@ --batch

patches: ## Creates patch files after manual tuning of the json files by hand
	diff -Naur stock.docker.json default.jsonnet > default.patch || true
	diff -Naur stock.docker.json fuse-container.jsonnet > fuse-container.patch || true
	diff -Naur stock.docker.json allow-perf-syscalls.jsonnet > allow-perf-syscalls.patch || true


# These JSON files are machine generated from jsonnet files.
# They are not meant to be human-edited
default.json: default.jsonnet
	jsonnet $? > $@

fuse-container.json: fuse-container.jsonnet
	jsonnet $? > $@

allow-perf-syscalls.json: allow-perf-syscalls.jsonnet
	jsonnet $? > $@

# seccomp.go is machine-generated, and is a golang representation of the data
# included in these json files
seccomp.go: default.json fuse-container.json allow-perf-syscalls.json
	gobin -run github.com/kevinburke/go-bindata/go-bindata@v3.21.0 -pkg seccomp -o $@ $?

clean:
	rm *.json
	rm seccomp.go
	rm *.rej
	rm *.orig
