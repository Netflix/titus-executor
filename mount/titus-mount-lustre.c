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
#include <linux/mount.h>
/* fcntl */
#include "scm_rights.h"
#include <assert.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"

#define E(x)                                                                   \
	do {                                                                   \
		if ((x) == -1) {                                               \
			perror(#x);                                            \
			exit(1);                                               \
		}                                                              \
	} while (0)

#define IP_ADDRESS_LEN 256

/*
 *Construct lustre device mount options in the format expected by the syscall
 */
static void add_device_options(const char *ipaddress, const char *mount_name,
			       char *final_options)
{
	strcat(final_options, ",device=");
	strcat(final_options, ipaddress);
	strcat(final_options, "@tcp:/");
	strcat(final_options, mount_name);
}

/*
 * Perform a DNS lookup and add to the DNS options. Prefer v6 over v4 
 * (rely on /etc/gai.conf)
 */
static int hostname_to_ip_option(const char *hostname, const char *mount_name,
				 char *final_options)
{
	struct addrinfo *result, *iter;
	int error;
	unsigned char buf[INET6_ADDRSTRLEN];

	error = inet_pton(AF_INET, hostname, buf);
	if (error == 1) {
		fprintf(stderr, "Valid IPv4 address %s - No DNS needed\n",
			hostname);
		add_device_options(hostname, mount_name, final_options);
		return 0;
	}

	error = inet_pton(AF_INET6, hostname, buf);
	if (error == 1) {
		fprintf(stderr, "Valid IPv6 address %s - No DNS needed\n",
			hostname);
		add_device_options(hostname, mount_name, final_options);
		return 0;
	}

	error = getaddrinfo(hostname, NULL, NULL, &result);
	if (error) {
		fprintf(stderr, "Error trying to resolve %s - %s: \n", hostname,
			gai_strerror(error));
		return -1;
	}

	for (iter = result; iter != NULL; iter = iter->ai_next) {
		char ipaddress[IP_ADDRESS_LEN];
		void *ptr_to_ip;
		inet_ntop(iter->ai_family, iter->ai_addr->sa_data, ipaddress,
			  IP_ADDRESS_LEN);
		switch (iter->ai_family) {
		case AF_INET:
			ptr_to_ip =
				&((struct sockaddr_in *)iter->ai_addr)->sin_addr;
			break;
		case AF_INET6:
			ptr_to_ip = &((struct sockaddr_in6 *)iter->ai_addr)
					     ->sin6_addr;
			break;
		}
		inet_ntop(iter->ai_family, ptr_to_ip, ipaddress,
			  IP_ADDRESS_LEN);
		fprintf(stderr, "titus-mount-lustre: Resolved %s to %s\n",
			hostname, ipaddress);
		add_device_options(ipaddress, mount_name, final_options);
		break;
	}
	freeaddrinfo(result);
	return 0;
}

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
	fprintf(stderr, "titus-mount-lustre mount error on '%s': %m\n", s);
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

static inline int fsmount(int fsfd, unsigned int flags, unsigned int ms_flags)
{
	return syscall(__NR_fsmount, fsfd, flags, ms_flags);
}

static inline int fsconfig(int fsfd, unsigned int cmd, const char *key,
			   const void *val, int aux)
{
	return syscall(__NR_fsconfig, fsfd, cmd, key, val, aux);
}

static inline int move_mount(int from_dfd, const char *from_pathname,
			     int to_dfd, const char *to_pathname,
			     unsigned int flags)
{
	return syscall(__NR_move_mount, from_dfd, from_pathname, to_dfd,
		       to_pathname, flags);
}

#define E_fsconfig(fd, cmd, key, val, aux)                                     \
	do {                                                                   \
		if (fsconfig(fd, cmd, key, val, aux) == -1)                    \
			mount_error(fd, key ?: "create");                      \
	} while (0)

static void process_option(char *option, int fsfd)
{
	/* Splits up a k=v string and runs fsconfig on it.
           We supply all the inputs here, so it is safe, but parsing things
           like this is a little dangerous */
	char *key, *value, *saveptr;
	key = strtok_r(option, "=", &saveptr);
	option = NULL;
	value = strtok_r(option, "=", &saveptr);
	fprintf(stderr,
		"titus-mount-lustre: Setting filesystem mount option %s=%s\n",
		key, value);
	E_fsconfig(fsfd, FSCONFIG_SET_STRING, key, value, 0);
}

static void do_fsconfigs(int fsfd, char *options)
{
	char *str1, *token, *saveptr;
	/* Mount options come in in the classic comma-separated key=value pairs
	   we need to split them up and pass them in for fsconfig to handle one at a time */
	for (str1 = options;; str1 = NULL) {
		token = strtok_r(str1, ",", &saveptr);
		if (token == NULL)
			break;
		process_option(token, fsfd);
	}
	/* This last FSCONFIG_CMD_CREATE fsconfig call actually creates the superblock */
	E_fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
}

static int setup_fsfd_in_namespaces(int sk, int nsfd)
{
	int fsfd, ret;
	int usernsfd = openat(nsfd, "user", O_RDONLY);
	int mnt_fd = openat(nsfd, "mnt", O_RDONLY);
	int net_fd = openat(nsfd, "net", O_RDONLY);
	assert(usernsfd != -1);
	assert(mnt_fd != -1);
	assert(net_fd != -1);
	ret = setns(usernsfd, CLONE_NEWUSER);
	if (ret == -1) {
		perror("setns user");
		return 1;
	}
	ret = setns(mnt_fd, CLONE_NEWNS);
	if (ret == -1) {
		perror("setns mnt");
		return 1;
	}
	ret = setns(net_fd, CLONE_NEWNET);
	if (ret == -1) {
		perror("setns net");
		return 1;
	}
	fsfd = fsopen("lustre", 0);
	if (fsfd == -1) {
		perror("fsopen");
		return 1;
	}
	assert(send_fd(sk, fsfd) == 0);
	return 0;
}

static int fork_and_get_fsfd(long int nsfd)
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
		ret = setup_fsfd_in_namespaces(sk_pair[1], nsfd);
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

static void switch_namespaces(int nsfd)
{
	int ret;
	int mnt_fd = openat(nsfd, "mnt", O_RDONLY);
	assert(mnt_fd != -1);
	ret = setns(mnt_fd, CLONE_NEWNS);
	if (ret == -1) {
		perror("setns mount");
		exit(1);
	}
	int net_fd = openat(nsfd, "net", O_RDONLY);
	assert(net_fd != -1);
	ret = setns(net_fd, CLONE_NEWNET);
	if (ret == -1) {
		perror("setns net");
		exit(1);
	}
}

static void mount_and_move(int fsfd, const char *target, unsigned long flags)
{
	int mfd = fsmount(fsfd, 0, flags);
	if (mfd < 0) {
		mount_error(fsfd, "fsmount");
		E(close(fsfd));
	}
	E(move_mount(mfd, "", AT_FDCWD, target, MOVE_MOUNT_F_EMPTY_PATH));
	E(close(mfd));
}

int main(int argc, char *argv[])
{
	int nsfd, fsfd, res = -1;
	unsigned long flags_ul;
	/*
	 * We do this because parsing args is a bigger pain than passing
	 * via environment variable, although passing via environment
	 * variable has a "cost" in that they are limited in size
	 */
	const char *pidDir = getenv("TITUS_PID1_DIR");
	const char *lustre_mount_hostname = getenv("MOUNT_LUSTRE_HOSTNAME");
	const char *lustre_mount_mountname = getenv("MOUNT_LUSTRE_MOUNTNAME");
	const char *target = getenv("MOUNT_TARGET");
	const char *flags = getenv("MOUNT_FLAGS");
	const char *options = getenv("MOUNT_OPTIONS");

	if (!(target && flags && options && pidDir)) {
		fprintf(stderr,
			"Usage: must provide MOUNT_TARGET, MOUNT_FLAGS, TITUS_PID1_DIR, and MOUNT_OPTIONS env vars");
		return 1;
	}

	if (!(lustre_mount_hostname && lustre_mount_mountname)) {
		fprintf(stderr,
			"Usage: must provide MOUNT_LUSTRE_HOSTNAME, MOUNT_LUSTRE_MOUNTNAME env vars");
		return 1;
	}

	int buf_size = sysconf(_SC_PAGESIZE);
	char final_options[buf_size];
	strncpy(final_options, options, buf_size);

	errno = 0;
	flags_ul = strtoul(flags, NULL, 10);
	if (errno) {
		perror("flags");
		return 1;
	}
	/* This nsfd is used to extract other namespaces to switch to, similar to a pidfd */
	char pid1_ns_path[PATH_MAX];
	snprintf(pid1_ns_path, PATH_MAX - 1, "%s/ns", pidDir);
	nsfd = open(pid1_ns_path, O_PATH);
	if (nsfd == -1) {
		perror("pidfd_open");
		return 1;
	}

	/* First we need to get a fsfd, but it must be created inside the user namespace */
	fsfd = fork_and_get_fsfd(nsfd);

	/* Now we can switch net/mount namespaces so we can lookup the ip and eventually mount */
	switch_namespaces(nsfd);
	fprintf(stderr, "titus-mount-lustre: user-inputed options: %s\n",
		options);
	res = hostname_to_ip_option(lustre_mount_hostname,
				    lustre_mount_mountname, final_options);
	if (res != 0) {
		fprintf(stderr,
			"Error resolving hostname to IP address on mount\n");
		return 1;
	}
	fprintf(stderr, "titus-mount-lustre: computed final_options: %s\n",
		final_options);

	/* Now we can do the fs_config calls and actual mount */
	do_fsconfigs(fsfd, final_options);
	mkdir_p(target);
	mount_and_move(fsfd, target, flags_ul);

	fprintf(stderr, "titus-mount-lustre: All done, mounted on %s\n",
		target);
	return 0;
}
