all: titus-mount-nfs titus-mount-block-device titus-mount-ceph titus-mount-bind

titus-mount-nfs: titus-mount-nfs.c scm_rights.c common.h
	# musl needs this extra path here
	# so it can pick up our linux headers for syscalls
	C_INCLUDE_PATH=/usr/include/x86_64-linux-gnu/:/usr/include/:. musl-gcc -std=gnu11 -Wall -static -g -o titus-mount-nfs titus-mount-nfs.c scm_rights.c

titus-mount-ceph: titus-mount-ceph.c scm_rights.c common.h
	gcc -g -static -Wall -o titus-mount-ceph titus-mount-ceph.c scm_rights.c

titus-mount-block-device: titus-mount-block-device.c scm_rights.c common.h
	gcc -g -static -o titus-mount-block-device titus-mount-block-device.c scm_rights.c

titus-mount-bind: titus-mount-bind.c
	gcc -g -static -Wall -o titus-mount-bind titus-mount-bind.c
	
install: titus-mount-nfs titus-mount-ceph titus-mount-block-device titus-mount-bind
	sudo rsync -a titus-mount-nfs titus-mount-block-device titus-mount-ceph titus-mount-bind /apps/titus-executor/bin/

clean:
	rm -f titus-mount-nfs titus-mount-block-device titus-mount-ceph titus-mount-bind

fmt:
	# You can install these tools on linux with `sudo apt install clang-format iwyu`
	clang-format -i *.c *.h
	iwyu -I /usr/lib/gcc/x86_64-linux-gnu/9/include -I /usr/include -isystem /usr/lib/gcc/x86_64-linux-gnu/9/include-fixed/ -I include/ titus-mount-bind.c 2>&1  | fix_include --comments
