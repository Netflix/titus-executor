#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
/* getaddrinfo */
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
/* setns */
#include <sched.h>
/* for mount syscalls */
#include <asm-generic/unistd.h>
/* sys/mount MUST be included before linux/mount */
#include <sys/mount.h>

#include <linux/mount.h>
/* fcntl */
#include "scm_rights.h"
#include <assert.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
/* mkdir */
#include <linux/limits.h>
#include <signal.h>
#include <sys/stat.h>

#include "common.h"

#define E(x)                                                                   \
	do {                                                                   \
		if ((x) == -1) {                                               \
			perror(#x);                                            \
			exit(1);                                               \
		}                                                              \
	} while (0)

static void check_messages(int fd)
{
	char buf[4096];
	int err, n;
	err = errno;
	for (;;) {
		n = read(fd, buf, sizeof(buf));
		if (n < 0)
			break;
		n -= 2;
		switch (buf[0]) {
		case 'e':
			fprintf(stderr, "Error: %*.*s\n", n, n, buf + 2);
			break;
		case 'w':
			fprintf(stderr, "Warning: %*.*s\n", n, n, buf + 2);
			break;
		case 'i':
			fprintf(stderr, "Info: %*.*s\n", n, n, buf + 2);
			break;
		}
	}
	errno = err;
}

static __attribute__((noreturn)) void mount_error(int fd, const char *s)
{
	check_messages(fd);
	fprintf(stderr, "titus-mount-bind mount error on '%s': %m\n", s);
	exit(1);
}

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

static inline int sys_open_tree(int dfd, const char *filename,
				unsigned int flags)
{
	return syscall(__NR_open_tree, dfd, filename, flags);
}

static inline int sys_mount_setattr(int dfd, const char *path,
				    unsigned int flags, struct mount_attr *attr,
				    size_t size)
{
	return syscall(__NR_mount_setattr, dfd, path, flags, attr, size);
}

static void switch_namespaces(int nsfd)
{
	int ret;
	int mnt_fd = openat(nsfd, "mnt", O_RDONLY);
	assert(mnt_fd != -1);
	ret = setns(mnt_fd, CLONE_NEWNS);
	if (ret == -1) {
		perror("setns mnt");
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	int ret;
	int nsfd, fsfd;
	long int container_pid;
	unsigned long flags_ul;
	/*
	 * We do this because parsing args is a bigger pain than passing
	 * via environment variable, although passing via environment
	 * variable has a "cost" in that they are limited in size
	 */
	const char *target = getenv("MOUNT_TARGET");
	const char *source = getenv("MOUNT_HOST_PATH");
	const char *flags = getenv("MOUNT_FLAGS");
	const char *pid1dir = getenv("TITUS_PID_1_DIR");

	if (!(target && flags && source && pid1dir)) {
		fprintf(stderr,
			"Usage: must provide MOUNT_TARGET, MOUNT_FLAGS, MOUNT_HOST_PATH, and TITUS_PID_1_DIR env vars");
		return 1;
	}

	errno = 0;
	flags_ul = strtoul(flags, NULL, 10);
	if (errno) {
		perror("flags");
		return 1;
	}

	/* This nsfd is used to extract other namespaces to switch to, similar to a pidfd */
	char pid1_ns_path[PATH_MAX];
	snprintf(pid1_ns_path, PATH_MAX - 1, "%s/ns", pid1dir);
	nsfd = open(pid1_ns_path, O_PATH);
	if (nsfd == -1) {
		perror("pidfd_open");
		return 1;
	}

	/* source_dfd is an fd we use just for the sake of creating an open_tree fd */
	int source_dfd = open(source, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (source_dfd < 0) {
		perror("open");
		return 1;
	}
	/* fd_tree is like a mountfd, which can be manipulated and moved */
	int fd_tree = sys_open_tree(source_dfd, ".",
				    OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC |
					    AT_EMPTY_PATH);
	if (fd_tree < 0) {
		perror("fd_tree open_tree");
		return 1;
	}

	/* Now that we have a mountfd (an open_tree fd really), we can set mount flags */
	sys_mount_setattr(fd_tree, "", AT_EMPTY_PATH, MOUNT_ATTR_RDONLY,
			  MOUNT_ATTR_RDONLY);

	/* Before we mount, we want to switch namespaces so that the move looks correct
	and it will show up in the /proc/mounts of the container */
	switch_namespaces(nsfd);
	close(nsfd);

	mkdir_p(target);
	/* This final procedure moves the fd_tree onto the target directory, "mounting" it */
	int to_dfd = open(source, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (to_dfd < 0) {
		perror("to_fd open");
		exit(1);
	}
	E(move_mount(fd_tree, "", -EBADF, target, MOVE_MOUNT_F_EMPTY_PATH));

	fprintf(stderr, "titus-mount-bind: All done, mounted on %s\n", target);
	return 0;
}
