#include <sys/prctl.h>

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/perf_event.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/capability.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/xattr.h>

#include "seccomp_fd_notify.h"

#define PRINT_WARNING(...)                                                     \
	{                                                                      \
		fprintf(stderr, __VA_ARGS__);                                  \
		fprintf(stderr, "\n");                                         \
	}
#define PRINT_INFO(...)                                                        \
	{                                                                      \
		fprintf(stderr, __VA_ARGS__);                                  \
		fprintf(stderr, "\n");                                         \
	}

bool have_cap_sysadmin()
{
	cap_t current_capabilties = cap_get_proc();
	// cap_get_flag() obtains the current value of the capability flag, flag, of the capability, cap,
	// from the capability state identified by cap_p and places it in the location pointed to by value_p.
	cap_flag_value_t cap_value;
	// Look at our EFFECTIVE current_capabilities for CAP_SYS_ADMIN, and set the result in cap_value
	cap_get_flag(current_capabilties, CAP_SYS_ADMIN, CAP_EFFECTIVE,
		     &cap_value);
	return cap_value == CAP_SET;
}

static int send_fd(int sock, int fd)
{
	struct msghdr msg = { 0 };
	struct cmsghdr *cmsg;
	char buf[CMSG_SPACE(sizeof(int))] = { 0 }, c = 'c';
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

	int sendmsg_return = sendmsg(sock, &msg, 0);
	if (sendmsg_return < 0) {
		PRINT_WARNING("sendmsg failed with return %d", sendmsg_return);
		return -1;
	}
	return 0;
}

static int seccomp(unsigned int operation, unsigned int flags, void *args)
{
	return syscall(__NR_seccomp, operation, flags, args);
}

/* For the x32 ABI, all system call numbers have bit 30 set */
#define X32_SYSCALL_BIT 0x40000000

/* install_notify_filter() install_notify_filter a seccomp filter that generates user-space
   notifications (SECCOMP_RET_USER_NOTIF) when the process calls mkdir(2); the
   filter allows all other system calls.

   The function return value is a file descriptor from which the user-space
   notifications can be fetched. */
static int install_notify_filter(void)
{
	/* If you are debugging this, sometimes it is helpful to inspect what a filter
	actually is, live on a process. Try using this on a container:
	sudo seccomp-tools dump  -l2 -p $pid # where pid is tini
	and seccomp-tools is https://github.com/david942j/seccomp-tools */
	struct sock_filter filter[] = {
		/* X86_64_CHECK_ARCH_AND_LOAD_SYSCALL_NR */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 (offsetof(struct seccomp_data, arch))),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 2),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 (offsetof(struct seccomp_data, nr))),
		BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

		/* Trap perf-related syscalls */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_bpf, 0, 1),
		BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_USER_NOTIF),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_perf_event_open, 0, 1),
		BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_USER_NOTIF),
		/* We only need to trap the 2 perf-related ioctls */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 0, 5),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 (offsetof(struct seccomp_data, args[1]))),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PERF_EVENT_IOC_SET_BPF, 0,
			 1),
		BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_USER_NOTIF),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PERF_EVENT_IOC_QUERY_BPF, 0,
			 1),
		BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_USER_NOTIF),

		/* Every other system call is allowed */
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};

	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
		.filter = filter,
	};

	/* If we don't have CAP_SYSADMIN, we MUST set NO_NEW_PRIVS.
	Why? Read https://unix.stackexchange.com/a/562899/411719
	Or, from the seccomp man page:
	> In order to use the SECCOMP_SET_MODE_FILTER operation, either the caller must have the CAP_SYS_ADMIN
	> capability in its user namespace, or the thread must already have the no_new_privs bit set. */
	if (!have_cap_sysadmin()) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
			PRINT_WARNING(
				"failed doing no new privs, won't be able to setup the seccomp filter");
			return -1;
		}
	}

	/* Install the filter with the SECCOMP_FILTER_FLAG_NEW_LISTENER flag; as
	   a result, seccomp() returns a notification file descriptor. */

	/* Only one listening file descriptor can be established. An attempt to
	   establish a second listener yields an EBUSY error. */

	int notify_fd = seccomp(SECCOMP_SET_MODE_FILTER,
				SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
	if (notify_fd == -1) {
		PRINT_WARNING("seccomp install_notify_filter failed: %s",
			      strerror(errno));
		return -1;
	}
	return notify_fd;
}

void maybe_setup_seccomp_notifer()
{
	char *socket_path;
	socket_path = getenv(TITUS_SECCOMP_NOTIFY_SOCK_PATH);
	if (socket_path) {
		int sock_fd = -1;
		// Sometimes things are not perfect, and the socket is not ready at first
		// Instead of enforcing strict ordering, we can be defensive and retry.
		int attempts = 10;
		for (int i = 1; i <= attempts; i++) {
			sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
			if (sock_fd != -1) {
				break;
			}
			PRINT_INFO(
				"Titus seccomp unix socket not ready on attempt %d/%d, Sleeping 1 second",
				i, attempts);
			sleep(1);
		}
		if (sock_fd == -1) {
			PRINT_WARNING(
				"Unable to open unix socket for seccomp handoff after %d attempts: %s",
				attempts, strerror(errno));
			return;
		}

		struct sockaddr_un addr = { 0 };
		addr.sun_family = AF_UNIX;
		strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
		int result = -1;
		for (int i = 1; i <= attempts; i++) {
			result = connect(sock_fd, (struct sockaddr *)&addr,
					 sizeof(addr));
			if (result != -1) {
				break;
			}
			PRINT_INFO(
				"Titus seccomp unix socket not connectable yet on attempt %d/%d, Sleeping 1 second",
				i, attempts);
			sleep(1);
		}
		if (result == -1) {
			PRINT_WARNING(
				"Unable to connect on unix socket (%s) for seccomp handoff after %d attempts: %s",
				socket_path, attempts, strerror(errno));
			return;
		}

		int notify_fd = -1;
		notify_fd = install_notify_filter();
		if (send_fd(sock_fd, notify_fd) == -1) {
			PRINT_WARNING(
				"Couldn't send fd to the socket at %s: %s",
				socket_path, strerror(errno));
			return;
		} else {
			PRINT_INFO(
				"Sent the notify fd to the seccomp agent socket at %s",
				socket_path)
		}
	}
	return;
}
