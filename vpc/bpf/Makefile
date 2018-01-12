all: filter/filter.go

filter.o: filter.c
	clang -O2 -emit-llvm -c filter.c -Wall -Werror -o - | llc -march=bpf -filetype=obj -o filter.o

filter/filter.go: filter.o
	go-bindata -pkg filter -o filter/filter.go filter.o
