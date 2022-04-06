#define _GNU_SOURCE
#include <errno.h>        // for EBADF
#include <stdio.h>        // for perror, fprintf, snprintf, stderr, size_t
#include <stdlib.h>       // for exit, getenv, WEXITSTATUS, WIFEXITED
/* setns */
#include <sched.h>        // for setns, CLONE_NEWNS, CLONE_NEWUSER
#include <limits.h>       // for PATH_MAX
#include <sys/socket.h>   // for socketpair, PF_LOCAL, SOCK_SEQPACKET
#include <syscall.h>      // for __NR_fsopen, __NR_mount_setattr, __NR_move_...

#include <linux/mount.h>  // for MOUNT_ATTR_NODEV, MOUNT_ATTR_NOEXEC, MOUNT_...
#include <assert.h>       // for assert
#include <fcntl.h>        // for open, openat, O_RDONLY, AT_EMPTY_PATH, O_CL...
#include <sys/wait.h>     // for waitpid
#include <unistd.h>       // for close, syscall, fork, pid_t

/* fcntl */
#include "scm_rights.h"   // for send_fd, recv_fd
#include "common.h"       // for mkdir_p

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

static int setup_fsfd_in_namespaces(int sk, int src_nsfd, const char *src_path)
{
	int fd_tree, ret;
	int src_dfd;
	int mnt_fd, user_fd;

	user_fd = openat(src_nsfd, "user", O_RDONLY);
	assert(user_fd != -1);
	ret = setns(user_fd, CLONE_NEWUSER);
	if (ret == -1) {
		perror("setns user");
		return 1;
	}

	mnt_fd = openat(src_nsfd, "mnt", O_RDONLY);
	assert(mnt_fd != -1);
	ret = setns(mnt_fd, CLONE_NEWNS);
	if (ret == -1) {
		perror("setns mnt");
		return 1;
	}

	src_dfd = open(src_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (src_dfd < 0) {
		perror("open");
		return 1;
	}

	fd_tree = sys_open_tree(src_dfd, ".",
				OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC |
					AT_EMPTY_PATH);
	if (fd_tree < 0) {
		perror("fd_tree open_tree");
		return 1;
	}
	assert(send_fd(sk, fd_tree) == 0);
	return 0;
}

static int get_fd_tree_from_source(int src_nsfd, const char *src_path)
{
	int sk_pair[2], ret, fsfd, status;
	pid_t worker;

	if (socketpair(PF_LOCAL, SOCK_SEQPACKET, 0, sk_pair) < 0) {
		perror("socketpair");
		exit(1);
	}
	worker = fork();
	if (worker < 0) {
		perror("fork");
		exit(1);
	}
	if (worker == 0) {
		close(sk_pair[0]);
		ret = setup_fsfd_in_namespaces(sk_pair[1], src_nsfd, src_path);
		close(sk_pair[1]);
		exit(ret);
	}
	close(sk_pair[1]);
	fsfd = recv_fd(sk_pair[0]);
	assert(fsfd >= 0);
	if (waitpid(worker, &status, 0) != worker) {
		perror("waitpid");
		exit(1);
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		fprintf(stderr, "worker exited nonzero\n");
		exit(1);
	}
	close(sk_pair[0]);
	return fsfd;
}

int main(int argc, char *argv[])
{
	int src_nsfd, dst_nsfd;
	int src_fd_tree;

	const char *src_pid1dir = getenv("SRC_PID_1_DIR");
	const char *dst_pid1dir = getenv("DST_PID_1_DIR");
	const char *src_path = getenv("SRC_PATH");
	const char *dst_path = getenv("DST_PATH");

	if (!(src_pid1dir && dst_pid1dir && src_path && dst_path)) {
		fprintf(stderr,
			"Usage: must provide SRC_PID_1_DIR, DST_PID_1_DIR, SRC_PATH, and DST_PATH env vars");
		return 1;
	}

	/* This nsfd is used to extract other namespaces to switch to, similar to a pidfd */
	char src_pid1_ns_path[PATH_MAX];
	snprintf(src_pid1_ns_path, PATH_MAX - 1, "%s/ns", src_pid1dir);
	src_nsfd = open(src_pid1_ns_path, O_PATH);
	if (src_nsfd == -1) {
		perror("pidfd_open");
		return 1;
	}

	src_fd_tree = get_fd_tree_from_source(src_nsfd, src_path);

	/* Now that we have a mountfd (an open_tree fd really), we can set mount flags */
	struct mount_attr *attr = &(struct mount_attr){};
	sys_mount_setattr(src_fd_tree, "", AT_EMPTY_PATH, attr, 0);

	/* Before we mount, we want to switch namespaces so that the move looks correct
	and it will show up in the /proc/mounts of the container */
	char dst_pid1_ns_path[PATH_MAX];
	snprintf(dst_pid1_ns_path, PATH_MAX - 1, "%s/ns", dst_pid1dir);
	dst_nsfd = open(dst_pid1_ns_path, O_PATH);
	if (dst_nsfd == -1) {
		perror("pidfd_open");
		return 1;
	}
	switch_namespaces(dst_nsfd);
	close(dst_nsfd);

	mkdir_p(dst_path);
	/* This final procedure moves the fd_tree onto the target directory, "mounting" it */
	int to_dfd = open(dst_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (to_dfd < 0) {
		perror("to_fd open");
		exit(1);
	}
	E(move_mount(src_fd_tree, "", -EBADF, dst_path,
		     MOVE_MOUNT_F_EMPTY_PATH));

	fprintf(stderr, "titus-mount-bind: All done, mounted on %s\n",
		dst_path);
	return 0;
}