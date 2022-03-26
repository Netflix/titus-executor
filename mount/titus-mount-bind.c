#define _GNU_SOURCE
#include <errno.h> // for errno
#include <stdio.h> // for perror, fprintf, snprintf, stderr
#include <stdlib.h> // for getenv, exit
/* setns */
#include <assert.h> // for assert
#include <fcntl.h> // for open, openat, AT_FDCWD, AT_RECURSIVE, O_PATH
#include <limits.h> // for PATH_MAX
#include <linux/mount.h> // for MOVE_MOUNT_F_EMPTY_PATH, OPEN_TREE_CLOEXEC
#include <sched.h> // for setns, CLONE_NEWNS
#include <syscall.h> // for __NR_fsopen, __NR_move_mount, __NR_open_tree
#include <unistd.h> // for syscall, pid_t

// Only to make it easier to build on older kernels
#ifndef AT_RECURSIVE
#define AT_RECURSIVE 0x8000
#endif

#define E(x)                                                                   \
	do {                                                                   \
		if ((x) == -1) {                                               \
			perror(#x);                                            \
			exit(1);                                               \
		}                                                              \
	} while (0)

static inline int pidfd_open(pid_t pid, unsigned int flags)
{
	return syscall(__NR_pidfd_open, pid, flags);
}

static inline int fsopen(const char *fs_name, unsigned int flags)
{
	return syscall(__NR_fsopen, fs_name, flags);
}

static inline int move_mount(int from_dfd, const char *from_pathname,
			     int to_dfd, const char *to_pathname,
			     unsigned int flags)
{
	return syscall(__NR_move_mount, from_dfd, from_pathname, to_dfd,
		       to_pathname, flags);
}

static inline int open_tree(int dfd, const char *filename, unsigned int flags)
{
	return syscall(__NR_open_tree, dfd, filename, flags);
}

static void switch_into_mount_namespace(int nsfd)
{
	int mnt_fd;

	mnt_fd = openat(nsfd, "mnt", O_RDONLY);
	assert(mnt_fd != -1);
	E(setns(mnt_fd, CLONE_NEWNS));
}

int main(int argc, char *argv[])
{
	int nsfd, mfd;
	/*
	 * We do this because parsing args is a bigger pain than passing
	 * via environment variable, although passing via environment
	 * variable has a "cost" in that they are limited in size
	 */
	const char *source = getenv("MOUNT_SOURCE");
	char *target = getenv("MOUNT_TARGET");
	const char *pid1dir = getenv("TITUS_PID_1_DIR");
	char pid1_ns_path[PATH_MAX];

	errno = 0;

	if (!(target && source && pid1dir)) {
		fprintf(stderr,
			"Usage: must provide MOUNT_SOURCE, MOUNT_TARGET, and TITUS_PID_1_DIR env vars\n");
		return 1;
	}

	/* This nsfd is used to extract other namespaces to switch to, similar to a pidfd */
	snprintf(pid1_ns_path, PATH_MAX - 1, "%s/ns", pid1dir);
	nsfd = open(pid1_ns_path, O_PATH);
	if (nsfd == -1) {
		perror("pidfd_open");
		return 1;
	}

	mfd = open_tree(AT_FDCWD, source,
			OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_RECURSIVE);
	switch_into_mount_namespace(nsfd);
	E(move_mount(mfd, "", AT_FDCWD, target, MOVE_MOUNT_F_EMPTY_PATH));
	fprintf(stderr,
		"titus-mount-bind: All done, bind mount %s mounted on %s\n",
		source, target);
	return 0;
}
