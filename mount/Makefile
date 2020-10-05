titus-mount: mount.c
	# musl needs this extra path here
	# so it can pick up our linux headers for syscalls
	C_INCLUDE_PATH=/usr/include/ musl-gcc -std=gnu11 -Wall -static -g -o titus-mount mount.c /usr/lib/x86_64-linux-gnu/libcap.a
