all: filter/filter.go

filter.o: filter.c
	clang -O2 -emit-llvm -c filter.c -Wall -Werror -o - | llc -march=bpf -filetype=obj -o filter.o

filter/filter.go: filter.o
	gobin -run -m github.com/jteeuwen/go-bindata/go-bindata -pkg filter -o filter/filter.go filter.o
