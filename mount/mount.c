#define _GNU_SOURCE

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

/* fcntl */
#include <unistd.h>
#include <fcntl.h>

/* setfsuid */
#include <sys/fsuid.h>

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

int main() {
	int mnt_ns_fd, net_ns_fd, user_ns_fd;
	unsigned long flags_ul;
	int rc;
	/*
	 * We do this because parsing args is a bigger pain than passing
	 * via environment variable, although passing via environment
	 * variable has a "cost" in that they are limited in size
	 */
	const char *mnt_ns = getenv("MOUNT_NS");
	const char *net_ns = getenv("NET_NS");
	const char *user_ns = getenv("USER_NS");
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

	if (user_ns) {
		user_ns_fd = strtol(user_ns, NULL, 10);
		if (errno) {
			perror("user_ns");
			return 1;
		}
		if (user_ns_fd == 0) {
			fprintf(stderr, "Unable to get user NS fd\n");
			return 1;
		}
		/* Validate that we have this file descriptor */
		if (fcntl(user_ns_fd, F_GETFD) == -1) {
			perror("user_ns: f_getfd");
			return 1;
		}
		rc = setns(user_ns_fd, CLONE_NEWUSER);
		if (rc) {
			perror("setns: user_ns");
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

    if (setuid(0)) {
        perror("setuid");
        return 1;
    }

    if (setgid(0)) {
        perror("setgid");
        return 1;
    }

    if (setfsuid(0)) {
        perror("setfsuid");
        return 1;
    }

    if (setfsgid(0)) {
        perror("setfsgid");
        return 1;
    }

	/* We don't check for overflow */
	rc = mount(source, target, fs_type, flags_ul, final_options);
	if (rc) {
		perror("mount");
		return 1;
	}

	return 0;
}
