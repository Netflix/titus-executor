all: titus-mount titus-mount-block-device

titus-mount: mount.c scm_rights.c
	# musl needs this extra path here
	# so it can pick up our linux headers for syscalls
	C_INCLUDE_PATH=/usr/include/x86_64-linux-gnu/:/usr/include/:. musl-gcc -std=gnu11 -Wall -static -g -o titus-mount mount.c scm_rights.c

titus-mount-block-device: titus-mount-block-device.c scm_rights.c
	gcc -g -static -o titus-mount-block-device titus-mount-block-device.c scm_rights.c


install: titus-mount titus-mount-block-device
	sudo rsync -a titus-mount titus-mount-block-device /apps/titus-executor/bin/

clean:
	rm -f titus-mount titus-mount-block-device

fmt:
	clang-format -i *.c *.h
