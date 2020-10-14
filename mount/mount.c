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
#include <assert.h>
#include <sys/types.h>
#include <sys/wait.h>
char nfs4[] = "nfs4";
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
#define E_fsconfig(fd, cmd, key, val, aux)                              \
        do {                                                            \
                if (fsconfig(fd, cmd, key, val, aux) == -1)             \
                        mount_error(fd, key ?: "create");               \
        } while (0)
void do_fsconfigs(int fsfd, const char *options) {
	// TODO parse this for real
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
	// TODO: This fails if nsenter'd into the userns, works if not (but uid/gid are wrong)
	E_fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
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
	fsfd = fsopen("nfs4", 0);
	if (fsfd == -1) {
                perror("fsopen");
                exit(1);
	}
	printf("Doing fsconfigs with these options: %s\n", options);
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
static int send_fd(int sock, int fd)
{
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	char buf[CMSG_SPACE(sizeof(int))] = {0}, c = 'c';
	struct iovec io = {
		.iov_base = &c,
		.iov_len = 1,
	};
	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	*((int *)CMSG_DATA(cmsg)) = fd;
	msg.msg_controllen = cmsg->cmsg_len;
	if (sendmsg(sock, &msg, 0) < 0) {
		perror("sendmsg");
		return -1;
	}
	return 0;
}
static int recv_fd(int sock)
{
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	char buf[CMSG_SPACE(sizeof(int))] = {0}, c = 'c';
	struct iovec io = {
		.iov_base = &c,
		.iov_len = 1,
	};
	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);
	if (recvmsg(sock, &msg, 0) < 0) {
		perror("recvmsg");
		return -1;
	}
	cmsg = CMSG_FIRSTHDR(&msg);
	return *((int *)CMSG_DATA(cmsg));
}
static int do_work(int sk, int pidfd) {
	char fs_type[] = "nfs4";
	int fsfd, ret;
	ret = setns(pidfd, CLONE_NEWUSER);
	if (ret == -1) {
		perror("setns user");
		return 1;
	}
	ret = setns(pidfd, CLONE_NEWNET);
	if (ret == -1) {
		perror("setns net");
		return 1;
	}
	ret = setns(pidfd, CLONE_NEWNS);
	if (ret == -1) {
		perror("setns mnt");
		return 1;
	}
	fsfd = fsopen("nfs4", 0);
	if (fsfd == -1) {
		perror("fsopen");
		return 1;
	}
	assert(send_fd(sk, fsfd) == 0);
	return 0;
}
int main(int argc, char *argv[]) {
	int pidfd, fsfd, sk_pair[2], status, ret, mfd;
	long int container_pid;
	pid_t worker;

        const char *target = getenv("MOUNT_TARGET");

	if (argc != 2) {
		printf("Usage: %s container_pid", argv[0]);
		return 1;
	}
	errno = 0;
	container_pid = strtol(argv[1], NULL, 10);
	assert(errno == 0);
	if (socketpair(PF_LOCAL, SOCK_SEQPACKET, 0, sk_pair) < 0) {
		perror("socketpair");
		return 1;
	}
	pidfd = pidfd_open(container_pid, 0);
	if (pidfd == -1) {
		perror("pidfd_open");
		return 1;
	}
	worker = fork();
	if (worker < 0) {
		perror("fork");
		return 1;
	}
	if (worker == 0) {
		close(sk_pair[0]);
		ret = do_work(sk_pair[1], pidfd);
		close(sk_pair[1]);
		return ret;
	}
	close(sk_pair[1]);
	fsfd = recv_fd(sk_pair[0]);
	assert(fsfd >= 0);
	if (waitpid(worker, &status, 0) != worker) {
		perror("waitpid");
		return 1;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		fprintf(stderr, "worker exited nonzero\n");
		return 1;
	}
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
//	E_fsconfig(fsfd, FSCONFIG_SET_FLAG, "resvport", "no",  0);
//	E_fsconfig(fsfd, FSCONFIG_SET_STRING, "fsc", "d85f8159aec7", 0);
	// TODO: This fails if nsenter'd into the userns, works if not (but uid/gid are wrong)
	E_fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
	ret = setns(pidfd, CLONE_NEWNS | CLONE_NEWNET);
	if (ret == -1) {
		perror("setns mnt / net");
		return 1;
	}
	mfd = fsmount(fsfd, 0, MS_NODEV);
	if (mfd < 0) {
		mount_error(fsfd, "fsmount");
		E(close(fsfd));
	}
	E(move_mount(mfd, "", AT_FDCWD, target, MOVE_MOUNT_F_EMPTY_PATH));
	E(close(mfd));
//	printf("All done, mounted on %s\n", target);
	return 0;
}
