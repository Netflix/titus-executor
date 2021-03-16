all: titus-mount-nfs titus-mount-block-device

titus-mount-nfs: titus-mount-nfs.c scm_rights.c common.h
	# musl needs this extra path here
	# so it can pick up our linux headers for syscalls
	C_INCLUDE_PATH=/usr/include/x86_64-linux-gnu/:/usr/include/:. musl-gcc -std=gnu11 -Wall -static -g -o titus-mount-nfs titus-mount-nfs.c scm_rights.c

titus-mount-block-device: titus-mount-block-device.c scm_rights.c common.h
	gcc -g -static -o titus-mount-block-device titus-mount-block-device.c scm_rights.c


install: titus-mount-nfs titus-mount-block-device
	sudo rsync -a titus-mount-nfs titus-mount-block-device /apps/titus-executor/bin/

clean:
	rm -f titus-mount-nfs titus-mount-block-device

fmt:
	clang-format -i *.c *.h
