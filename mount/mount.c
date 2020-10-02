#define _GNU_SOURCE

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

/* getaddrinfo */
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>

/* setns */
#include <sched.h>

/* mount */
#include <sys/mount.h>

/* for mount syscalls */
#include <asm-generic/unistd.h>
#include <linux/mount.h>

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

static int dns_lookup(const char *hostname, struct sockaddr_in *addr)
{
	struct hostent *hp;
	addr->sin_family = AF_INET;

	if (inet_aton(hostname, &addr->sin_addr)) {
		fprintf(stderr, "titus-mount: %s is already an IP. Not doing a DNS lookup\n", hostname);
		return 0;
	}
	fprintf(stderr, "titus-mount: Decoding and resolving dns hostname for %s\n", hostname);
	hp = gethostbyname(hostname);
	if (hp == NULL) {
		int err_ret = h_errno;
		fprintf(stderr, "titus-mount: can't get address for %s: %s\n", hostname, hstrerror(err_ret));
		return -1;
	}
	if (hp->h_length > (int)sizeof(struct in_addr)) {
		fprintf(stderr, "titus-mount: got bad hp->h_length");
		return -1;
	}
	memcpy(&addr->sin_addr, hp->h_addr, hp->h_length);
	return 0;
}

#define E(x) do { if ((x) == -1) { perror(#x); exit(1); } } while(0)

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

static __attribute__((noreturn))
void mount_error(int fd, const char *s)
{
	check_messages(fd);
	fprintf(stderr, "%s: %m\n", s);
	exit(1);
}

static inline int fsopen(const char *fs_name, unsigned int flags)
{
	return syscall(__NR_fsopen, fs_name, flags);
}

static inline int fsmount(int fsfd, unsigned int flags, unsigned int ms_flags)
{
	return syscall(__NR_fsmount, fsfd, flags, ms_flags);
}

static inline int fsconfig(int fsfd, unsigned int cmd,
			   const char *key, const void *val, int aux)
{
	return syscall(__NR_fsconfig, fsfd, cmd, key, val, aux);
}

static inline int move_mount(int from_dfd, const char *from_pathname,
			     int to_dfd, const char *to_pathname,
			     unsigned int flags)
{
	return syscall(__NR_move_mount,
		       from_dfd, from_pathname,
		       to_dfd, to_pathname, flags);
}

bool check_new_mount_api_available() {
	fsopen("", 0);
	return errno != ENOSYS;
}

#define E_fsconfig(fd, cmd, key, val, aux)                              \
        do {                                                            \
                if (fsconfig(fd, cmd, key, val, aux) == -1)             \
                        mount_error(fd, key ?: "create");               \
        } while (0)

void do_fsconfigs(int fsfd, const char *options) {
	// TODO
	// echo "vers=4.1,nosharecache,rsize=1048576,wsize=1048576,timeo=600,retrans=2,addr=100.66.9.206,clientaddr=100.122.62.253,noresvport,fsc=d85f8159aec7" | tr ',' '\n' | sed 's/^/E_fsconfig(fsfd, FSCONFIG_SET_STRING, "/g' | sed 's/=/", "/g' | sed 's/$/", 0);/g'
	E_fsconfig(fsfd, FSCONFIG_SET_STRING, "vers", "4.1", 0);
//	E_fsconfig(fsfd, FSCONFIG_SET_STRING, "nosharecache", "", 0);
//	E_fsconfig(fsfd, FSCONFIG_SET_STRING, "rsize", "1048576", 0);
//	E_fsconfig(fsfd, FSCONFIG_SET_STRING, "wsize", "1048576", 0);
//	E_fsconfig(fsfd, FSCONFIG_SET_STRING, "timeo", "600", 0);
//	E_fsconfig(fsfd, FSCONFIG_SET_STRING, "retrans", "2", 0);
	E_fsconfig(fsfd, FSCONFIG_SET_STRING, "addr", "100.66.9.206", 0);
	E_fsconfig(fsfd, FSCONFIG_SET_STRING, "source", "fs-0208c74b.efs.us-east-1.amazonaws.com:.", 0);
	E_fsconfig(fsfd, FSCONFIG_SET_STRING, "clientaddr", "100.122.62.253", 0);
//	E_fsconfig(fsfd, FSCONFIG_SET_STRING, "noresvport", "",  0);
//	E_fsconfig(fsfd, FSCONFIG_SET_STRING, "fsc", "d85f8159aec7", 0);
	E_fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
//	E_fsconfig(fsfd, FSCONFIG_CMD_RECONFIGURE, NULL, NULL, 0);
}


int do_fsmount(const char *source, const char *target, const char *fs_type, unsigned long flags_ul, const char *options) {
	int fsfd, mfd;

	// Hard coding nfs4 here, the only type we currently support (note: not nfsv4)
	fs_type = "nfs4";

	// Legacy flags start at this MS_MGC_VAL. For the new mount calls we need to subtract it.
	unsigned long flags;
	if (flags_ul >= 0xC0ED0000) {
		flags = flags_ul - 0xC0ED0000;
	} else {
		flags = flags_ul;
	}

	/* First we open a fd for holding the new fs */
	printf("Running fsopen with %s with flags %lu\n", fs_type, flags);
	fsfd = fsopen("nfs4", 0);
	if (fsfd == -1) {
                perror("fsopen");
                exit(1);
	}
	
	printf("Doing fdconfigs with these options: %s\n", options);
	do_fsconfigs(fsfd, options);

	/* Now we can fsmount it into a mount fd (mfd) */
	printf("Calling fsmount with %d with args 0, 0\n", fsfd);
	mfd = fsmount(fsfd, 0, MS_NODEV);
        if (mfd < 0)
                mount_error(fsfd, "fsmount");
        E(close(fsfd));

	/* Last we can move it to the target */
	printf("Calling move_mount to %s\n", target);
        if (move_mount(mfd, "", AT_FDCWD, target, MOVE_MOUNT_F_EMPTY_PATH) < 0) {
                perror("move_mount");
                exit(1);
        }

        E(close(mfd));
	return 0;
}

int main() {
	int mnt_ns_fd, net_ns_fd;
	unsigned long flags_ul;
	int rc;
	/*
	 * We do this because parsing args is a bigger pain than passing
	 * via environment variable, although passing via environment
	 * variable has a "cost" in that they are limited in size
	 */
	const char *mnt_ns = getenv("MOUNT_NS");
	const char *net_ns = getenv("NET_NS");
	const char *source = getenv("MOUNT_SOURCE");
	const char *nfs_mount_hostname = getenv("MOUNT_NFS_HOSTNAME");
	const char *target = getenv("MOUNT_TARGET");
	const char *flags = getenv("MOUNT_FLAGS");
	const char *options = getenv("MOUNT_OPTIONS");
	const char *fs_type = get_fs_type();

	int buf_size = sysconf(_SC_PAGESIZE);
	char final_options [buf_size];
	strcpy(final_options, options);

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

	if (net_ns) {
		net_ns_fd = strtol(net_ns, NULL, 10);
		if (errno) {
			perror("net_ns");
			return 1;
		}
		if (net_ns_fd == 0) {
			fprintf(stderr, "Unable to get net NS fd\n");
			return 1;
		}
		/* Validate that we have this file descriptor */
		if (fcntl(net_ns_fd, F_GETFD) == -1) {
			perror("net_ns: f_getfd");
			return 1;
		}
		rc = setns(net_ns_fd, CLONE_NEWNET);
		if (rc) {
			perror("netns");
			return 1;
		}
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

	/* For NFS, we must do the dns resolution *here* while we are inside net ns */
	if (nfs_mount_hostname) {
		static struct sockaddr_in server_addr;
		char *ip_string;

		if (dns_lookup(nfs_mount_hostname, &server_addr)) {
			fprintf(stderr, "titus-mount: DNS lookup failed for %s. Exiting 1.\n", nfs_mount_hostname);
			return 1;
		}
		ip_string = inet_ntoa(server_addr.sin_addr);
		strcat(final_options, ",addr=");
		strcat(final_options, ip_string);
		fprintf(stderr, "titus-mount: using these nfs mount options: %s\n", final_options);
	}

	if (check_new_mount_api_available()) {
		/* Where possible, we try to use the newer fsmount syscalls for newer kernel support */
		rc = do_fsmount(source, target, fs_type, flags_ul, final_options);
	} else {
		/* Otherwise we use the traditional mount call */
		rc = mount(source, target, fs_type, flags_ul, final_options);
	}

	if (rc) {
		perror("mount");
		return 1;
	}

	return 0;
}
