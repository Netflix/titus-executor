#include <stdio.h>
#include <stdlib.h>
#include <linux/limits.h>
#include <errno.h>
#include <string.h>

/* prctl  / waitpid */
#include <sys/prctl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

/* Open */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* Unshare */
#include <sched.h>
#include <unistd.h>

#include "shared.h"

struct namespace {
	int nstype;
	char *name;
};

static struct namespace namespaces[] = {
	{
		.nstype	= CLONE_NEWNS,
		.name	= "mnt",
	},
	{
		.nstype	= CLONE_NEWCGROUP,
		.name 	= "cgroup",
	},
	{
		.nstype	= CLONE_NEWIPC,
		.name	= "ipc",
	},
	{
		.nstype	= CLONE_NEWNET,
		.name	= "net",
	},
	{
		.nstype	= CLONE_NEWUSER,
		.name	= "user",
	},
	{
		.nstype	= CLONE_NEWUTS,
		.name	= "uts",
	},
	/* Order here is intentional. We do pid NS last. */
	{
		.nstype	= CLONE_NEWPID,
		.name	= "pid",
	},
};


int __populate_namespaces(int titus_ns_fd, int namespace_fds[]) {
	int i;


	for (i = 0; i < ARRAY_SIZE(namespaces); i++)
		namespace_fds[i] = -1;

	for (i = 0; i < ARRAY_SIZE(namespaces); i++) {
		namespace_fds[i] = openat(titus_ns_fd, namespaces[i].name, O_RDONLY | O_CLOEXEC);
		if (namespace_fds[i] == -1) {
			fprintf(stderr, "Cannot open NS FD for nstype %s, because: %s\n", namespaces[i].name, strerror(errno));
			goto fail;
		}
	}

	return 0;
fail:
	for (i = 0; i < ARRAY_SIZE(namespaces); i++) {
		if (namespace_fds[i] != -1)
			close(namespace_fds[i]);
	}
	return 1;
}

int populate_namespaces(int titus_pid_1_fd, int namespace_fds[]) {
	int ret, nsdir;

	nsdir = openat(titus_pid_1_fd, "ns", O_RDONLY | O_CLOEXEC);
	if (nsdir == -1) {
		perror("Cannot open ns dirfd");
		return 1;
	}

	ret = __populate_namespaces(nsdir, namespace_fds);
	close(nsdir);
	return ret;
}

static int set_up_apparmor(char apparmor_profile[1024], int apparmor_fd) {
	// This will break on older kernels
	char writebuf[1024];
	int n, ret = 0;

	// we can use dprintf, but this just makes error handling cleaner
	memset(writebuf, 0, sizeof(writebuf));
	n = sprintf(writebuf, "changeprofile %s", apparmor_profile);
	BUG_ON(n < 0 || n >= sizeof(writebuf), "Could not generate exec changehat command");

	if (write(apparmor_fd, writebuf, n) != n) {
		perror("Writing apparmor changeprofile");
		ret = 1;
	}

	close(apparmor_fd);
	return ret;
}

static int __get_apparmor_profile(int titus_pid_1_fd, char apparmor_profile[1024], int *apparmor_fd) {
	int containerfd;
	char buf[1024];
	char *profile;

	memset(buf, 0, sizeof(buf));
	containerfd = openat(titus_pid_1_fd, "attr/current", O_CLOEXEC | O_RDONLY);
	if (containerfd == -1) {
		perror("Open container current");
		return 1;
	}

	if (read(containerfd, buf, sizeof(buf) - 1) == -1) {
		perror("Reading Apparmor profile of container");
		close(containerfd);
		return 1;
	}
	close(containerfd);

	if (strcmp("unconfined", buf) == 0) {
		fprintf(stderr, "Container unconfined, not setting change exec hat profile\n");
		return 0;
	}
	profile = strtok(buf, " ");
	strcpy(apparmor_profile, profile);

	*apparmor_fd = open("/proc/self/attr/current", O_WRONLY);
	if (*apparmor_fd == -1) {
		perror("Open /proc/self/attr/current");
		return 1;
	}

	return 0;
}

int get_apparmor_profile(int titus_pid_1_fd, char apparmor_profile[1024], int *apparmor_fd) {
	char lsm_buf[1024];
	int fd;

	*apparmor_fd = -1;
	memset(lsm_buf, 0, sizeof(lsm_buf));
	fd = open("/sys/kernel/security/lsm", O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		perror("Could not open LSM config file");
		return 1;
	}

	if (read(fd, lsm_buf, sizeof(lsm_buf) - 1) == -1) {
		perror("Reading lsm config file");
		close(fd);
		return 1;
	}
	close(fd);

	// No apparmor profile
	if (!strstr(lsm_buf, "apparmor")) {
		fprintf(stderr, "Apparmor not enabled, not setting it up\n");
		return 0;
	}

	return __get_apparmor_profile(titus_pid_1_fd, apparmor_profile, apparmor_fd);
}

int do_nsenter(int argc, char *argv[], int titus_pid_1_fd) {
	// 1. We see if apparmor is loaded, if so, we read the apparmor hat,
	//    and set our change hat on exec to that.
	// 2. We do the setns thing
	// 3. We drop capabilities
	// 4. We do the seccomp thing
	// 5. We do the execve
	int namespace_fds[ARRAY_SIZE(namespaces)];
	int status, i, apparmor_fd;
	char apparmor_profile[1024];
	pid_t pid;

	struct stat my_user_ns, other_user_ns;

	memset(apparmor_profile, 0, sizeof(apparmor_profile));
	if (get_apparmor_profile(titus_pid_1_fd, apparmor_profile, &apparmor_fd)) {
		return 1;
	}

	if (stat("/proc/self/ns/user", &my_user_ns) == -1) {
		perror("Stat my user ns");
		goto fail_presetns;
	}

	if (populate_namespaces(titus_pid_1_fd, namespace_fds)) {
		goto fail_presetns;
	}

	for (i = 0; i < ARRAY_SIZE(namespaces); i++) {
		if (namespaces[i].nstype == CLONE_NEWUSER) {
			// Make sure we don't join our own user namespace
			if (fstat(namespace_fds[i], &other_user_ns) == -1) {
				perror("Stat other user ns");
				goto fail;
			}
			if (my_user_ns.st_dev == other_user_ns.st_dev && my_user_ns.st_ino == other_user_ns.st_ino)
				goto skip_setns;
		}
		if (setns(namespace_fds[i], namespaces[i].nstype)) {
			fprintf(stderr, "Cannot join namespace type %s, because: %s\n", namespaces[i].name, strerror(errno));
			goto fail;
		}
skip_setns:
		close(namespace_fds[i]);
	}

	if (apparmor_fd != -1)
		BUG_ON(set_up_apparmor(apparmor_profile, apparmor_fd), "Unable to change / setup apparmor profile");


	BUG_ON_PERROR(setgid(0), "Unable to drop GID");
	BUG_ON_PERROR(setuid(0), "Unable to drop UID");

	// Sargun(TODO): Drop capabilities
	// Sargun(TODO): Wire up seccomp
	pid = vfork();

	if (pid == 0) {
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		BUG_ON_PERROR(execvp(argv[1], &argv[1]) == -1, "Could not execute child");
	}

	/* We will only return here once the child finishes */
	waitpid(pid, &status, 0);
	return WEXITSTATUS(status);

fail:
	for (; i < ARRAY_SIZE(namespaces); i++) {
		close(namespace_fds[i]);
	}

fail_presetns:
	close(apparmor_fd);
	return 1;
}

int main(int argc, char *argv[]) {
	char *pid1dir = getenv(TITUS_PID_1_DIR);
	int titus_pid_1_fd;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s child-binary [args]\n", argv[0]);
	}

	if (!pid1dir) {
		fprintf(stderr, "TITUS_PID_1_DIR undefined\n");
		return 1;
	}

	titus_pid_1_fd = open(pid1dir, O_RDONLY | O_CLOEXEC);
	if (titus_pid_1_fd == -1) {
		fprintf(stderr, "Could not open %s: %s", pid1dir, strerror(errno));
		return 1;
	}

	return do_nsenter(argc, argv, titus_pid_1_fd);
}
