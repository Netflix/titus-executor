#define _GNU_SOURCE 1
#include <errno.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Unshare */
#include <sched.h>
#include <unistd.h>

/* syscalls */
#include <sys/syscall.h>

/* Open */
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

/* Mount */
#include <linux/mount.h>

/* dirname */
#include <libgen.h>

#include "shared.h"

#define TITUS_MNT_NS_FD "TITUS_MNT_NS_FD"
#define TITUS_NET_NS_FD "TITUS_NET_NS_FD"

static inline int sys_open_tree(int dfd, const char *filename,
				unsigned int flags)
{
	return syscall(__NR_open_tree, dfd, filename, flags);
}

static inline int sys_move_mount(int from_dirfd, const char *from_pathname,
				 int to_dirfd, const char *to_pathname,
				 unsigned int flags)
{
	return syscall(__NR_move_mount, from_dirfd, from_pathname, to_dirfd,
		       to_pathname, flags);
}

static inline int sys_mkdirat(int dirfd, const char *pathname, mode_t mode)
{
	return syscall(__NR_mkdirat, dirfd, pathname, mode);
}

int main(int argc, char *argv[])
{
	int mntnsfd, netnsfd, wherefd, srctree, dirfd;
	char *mntnsfdstr, *netnsfdstr;
	char dirbuf[PATH_MAX];
	char *dir, *where;
	struct stat64 buf;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s where\n", argv[0]);
		return 1;
	}

	where = argv[1];

	mntnsfdstr = getenv(TITUS_MNT_NS_FD);
	if (!mntnsfdstr) {
		fprintf(stderr, "TITUS_MNT_NS_FD undefined\n");
		return 1;
	}
	mntnsfd = strtol(mntnsfdstr, NULL, 10);

	netnsfdstr = getenv(TITUS_NET_NS_FD);
	if (!netnsfdstr) {
		fprintf(stderr, "TITUS_NET_NS_FD undefined\n");
		return 1;
	}
	netnsfd = strtol(netnsfdstr, NULL, 10);

	BUG_ON_PERROR(setns(mntnsfd, CLONE_NEWNS), "Cannot setns to %d",
		      mntnsfd);

	strncpy(dirbuf, where, sizeof(dir) - 1);
	dir = dirname(dirbuf);
	dirfd = openat(AT_FDCWD, dir, O_DIRECTORY);
	if (dirfd < 0) {
		fprintf(stderr, "Could not open dir %s: %s\n", dir,
			strerror(errno));
		return 1;
	}

	BUG_ON_PERROR(fstat64(dirfd, &buf), "Unable to stat dirfd");
	BUG_ON_PERROR(setegid(buf.st_gid), "Cannot set GID");
	BUG_ON_PERROR(seteuid(buf.st_uid), "Cannot set GID");

	wherefd = open(where, O_RDWR | O_CLOEXEC | O_CREAT, 0755);
	if (wherefd < 0) {
		fprintf(stderr, "Cannot open where %s: %s\n", where,
			strerror(errno));
		return 1;
	}

	BUG_ON_PERROR(seteuid(0), "Cannot reset GID");
	BUG_ON_PERROR(setegid(0), "Cannot reset GID");

	srctree = sys_open_tree(netnsfd, "",
				AT_EMPTY_PATH | OPEN_TREE_CLONE | O_CLOEXEC);
	if (srctree < 0) {
		fprintf(stderr, "Cannot open tree: %s\n", strerror(errno));
		return 1;
	}

	BUG_ON_PERROR(sys_move_mount(srctree, "", wherefd, "",
				     MOVE_MOUNT_F_EMPTY_PATH |
					     MOVE_MOUNT_T_EMPTY_PATH),
		      "Unable to move_mount");

	return 0;
}