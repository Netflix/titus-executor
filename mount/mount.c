#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

/* setns */
#include <sched.h>

/* mount */
#include <sys/mount.h>

/* fcntl */
#include <unistd.h>
#include <fcntl.h>

char nfs4[] = "nfs4";

static char* get_fs_type() {
	char *fs_type = getenv("MOUNT_FS_TYPE");

	if (!fs_type)
		return nfs4;
	/* It's okay to return this since it points to something in the environmenty bits */
	return fs_type;
}

int main() {
	unsigned long flags_ul;
	int mnt_ns_fd;
	int rc;
	/*
	 * We do this because parsing args is a bigger pain than passing
	 * via environment variable, although passing via environment
	 * variable has a "cost" in that they are limited in size
	 */
	const char *mnt_ns = getenv("MOUNT_NS");
	const char *source = getenv("MOUNT_SOURCE");
	const char *target = getenv("MOUNT_TARGET");
	const char *flags = getenv("MOUNT_FLAGS");
	const char *options = getenv("MOUNT_OPTIONS");
	const char *fs_type = get_fs_type();

	if (!(source && target && flags && options))
		return 1;

	errno = 0;
	flags_ul = strtoul(flags, NULL, 10);
	if (errno) {
		perror("flags");
		return 1;
	}
	if (!flags_ul) {
		fprintf(stderr, "Invalid flags\n");
		return 1;
	}

	if (mnt_ns) {
		mnt_ns_fd = strtol(mnt_ns, NULL, 10);
		if (errno) {
			perror("mnt_ns");
			return 1;
		}
		if (mnt_ns_fd == 0) {
			fprintf(stderr, "Unable to get mount NS fd\n");
			return 1;
		}
		/* Validate that we have this file descriptor */
		if (fcntl(mnt_ns_fd, F_GETFD) == -1) {
			perror("mnt_ns: f_getfd");
			return 1;
		}
		rc = setns(mnt_ns_fd, CLONE_NEWNS);
		if (rc) {
			perror("setns");
			return 1;
		}
	}

	/* We don't check for overflow */
	rc = mount(source, target, fs_type, flags_ul, options);
	if (rc) {
		perror("mount");
		return 1;
	}

	return 0;
}
