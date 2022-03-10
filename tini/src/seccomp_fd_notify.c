#define _GNU_SOURCE  
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
#include <sys/syscall.h>
#include <stddef.h>
#include <sys/capability.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <sys/wait.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <stddef.h>
#include <sched.h>
#include <sys/prctl.h>
#include "seccomp_fd_notify.h"

#ifndef CHILD_SIG
#define CHILD_SIG SIGUSR1
#endif

#define MAX_EVENTS 16
#define EPOLL_IGNORED_VAL 3
/* For the x32 ABI, all system call numbers have bit 30 set */
#define X32_SYSCALL_BIT 0x40000000

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

typedef struct tsa_fds {
	int fd_to_tsa;
	int notify_fd;
} tsa_fds;

pthread_mutex_t wait_to_send = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t ready_to_send = PTHREAD_COND_INITIALIZER;
pthread_cond_t pdeathsig_ready = PTHREAD_COND_INITIALIZER;
int child_pdeathsid_ready = 0;

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

/* install_notify_filter() install_notify_filter a seccomp filter that generates user-space
   notifications (SECCOMP_RET_USER_NOTIF) when the process calls mkdir(2); the
   filter allows all other system calls.

   The function return value is a file descriptor from which the user-space
   notifications can be fetched. 
*/
#define SOCK_TYPE_MASK ~(SOCK_NONBLOCK | SOCK_CLOEXEC)
static int install_notify_filter(void) {
	int notify_fd = -1;
	struct sock_fprog prog = {0};

	struct sock_filter perf_filter[] = {
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

	struct sock_filter net_filter[] = {
		/* X86_64_CHECK_ARCH_AND_LOAD_SYSCALL_NR */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch))),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 2),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
		BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

		/* Trap sendto */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendto, 0, 1),
		BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_USER_NOTIF),
		/* Trap sendmsg */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendmsg, 0, 1),
		BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_USER_NOTIF),
		/* Trap sendmmsg */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendmmsg, 0, 1),
		BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_USER_NOTIF),
		/* Trap connect */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect, 0, 1),
		BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_USER_NOTIF),

		/* Trap socket */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 1, 0),
		BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
		/* Load the first argument */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, args[0]))),

		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET, 2, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET6, 1, 0),
		BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),

		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, args[1]))),
		BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, SOCK_TYPE_MASK & SOCK_DGRAM, 0, 1),
		BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_USER_NOTIF),
		BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, SOCK_TYPE_MASK & SOCK_STREAM, 0, 1),
		BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_USER_NOTIF),

		/* Every other system call is allowed */
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
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

	char *is_handle_net = getenv("TITUS_SECCOMP_AGENT_HANDLE_NET_SYSCALLS");
	char *is_handle_perf = getenv("TITUS_SECCOMP_AGENT_HANDLE_PERF_SYSCALLS");
	if (is_handle_net != NULL) {
		prog.filter = net_filter;
		prog.len = 
			(unsigned short)(sizeof(net_filter) / sizeof(net_filter[0]));
		PRINT_INFO("Networking system calls will be intercepted");
	} else if (is_handle_perf != NULL) {
		prog.filter = perf_filter;
		prog.len = 
			(unsigned short)(sizeof(perf_filter) / sizeof(perf_filter[0]));
		PRINT_INFO("BPF/Perf system calls will be intercepted");
	} else {
		PRINT_INFO("No env variables set, no interception of system calls");
		return -1;
	}

	/* Install the filter with the SECCOMP_FILTER_FLAG_NEW_LISTENER flag; as
	   a result, seccomp() returns a notification file descriptor. */

	/* Only one listening file descriptor can be established. An attempt to
	   establish a second listener yields an EBUSY error. */

	notify_fd = seccomp(SECCOMP_SET_MODE_FILTER,
				SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
	if (notify_fd == -1) {
		PRINT_WARNING("seccomp install_notify_filter failed: %s",
			      strerror(errno));
		return -1;
	}
	
	return notify_fd;
}

static void sigusr_child_handler()
{
	PRINT_WARNING("Parent exited before child before sending notify_fd!");
	exit(EXIT_FAILURE);
}

static int child_send_fd(void *arg)
{
	struct sigaction sa;
	tsa_fds *fds = (tsa_fds *)arg;
	/* Setup a signal handler to catch parent exiting before child */
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = sigusr_child_handler;
	if (sigaction(SIGUSR1, &sa, NULL) == -1) {
		PRINT_WARNING("Failed to setup signal handler on the child");
		return EXIT_FAILURE;
	}

	/* Prevent race of parent exiting before prctl is setup */
	pthread_mutex_lock(&wait_to_send);
	if (prctl(PR_SET_PDEATHSIG, SIGUSR1) == -1) {
        PRINT_WARNING("Failed to setup PR_SET_PDEATHSIG on the child");
		return EXIT_FAILURE;
	}
	child_pdeathsid_ready = 1;
	pthread_cond_signal(&pdeathsig_ready);
	PRINT_WARNING("Setup PR_SET_PDEATHSIG on the child");
	pthread_mutex_unlock(&wait_to_send);

	/* Wait for parent to setup the TSA fds */
	pthread_mutex_lock(&wait_to_send);
	while(fds->notify_fd == -1) {
        pthread_cond_wait(&ready_to_send, &wait_to_send);
    }

	if (send_fd(fds->fd_to_tsa, fds->notify_fd) == -1) {
		PRINT_WARNING(
			"Couldn't send fd to the TSA %s", strerror(errno));
		return -1;
	} else {
		PRINT_INFO(
			"Sent the notify fd to the seccomp agent socket to TSA");
	}
	pthread_mutex_unlock(&wait_to_send);
	return 0;
}

void maybe_setup_seccomp_notifer() {
	char *socket_path;
	const int STACK_SIZE = 64 * 1024;
	const int MAX_ATTEMPTS = 10;
	char *stack;
	char *stack_top;
	int notify_fd = -1;
	int child_pid = -1;
	struct sockaddr_un addr = { 0 };
	int sock_fd = -1;
	int result = -1;
	
	socket_path = getenv(TITUS_SECCOMP_NOTIFY_SOCK_PATH);
	if (!socket_path) {
		/* maybe_setup_seccomp_notifer really means 'maybe', if there is no
		   socket path to connect to at all, we can silently return and not try to
		   do anything else */
		return;
	}

	tsa_fds *fds = malloc(sizeof(tsa_fds));
	if (fds == NULL) {
		PRINT_WARNING("Could not allocate fds");
		return;
	}
	fds->notify_fd = -1;
	fds->fd_to_tsa = -1;
	
	stack = malloc(STACK_SIZE);
	if (stack == NULL) {
		PRINT_WARNING("Failure to setup child for clone");
		return;
	}
	stack_top = stack + STACK_SIZE;
	if (CHILD_SIG != 0 && CHILD_SIG != SIGCHLD) {
		if (signal(CHILD_SIG, SIG_IGN) == SIG_ERR) {
			PRINT_WARNING("signal handlingo of child");
			return;
		}
	}

	/* Set up the client before the seccomp policies are inherited */
	child_pid = clone(child_send_fd, stack_top, 
		CLONE_FILES | CLONE_VM| CHILD_SIG, (void *) fds);
	if (child_pid == -1) {
        PRINT_WARNING("clone failed %s", strerror(errno));
		return;
	}

	/* Wait for the child to finish setting up a handler
	 * to handle the case where the parent exits before the child
	 */
	pthread_mutex_lock(&wait_to_send);
	while (child_pdeathsid_ready == 0) {
		pthread_cond_wait(&pdeathsig_ready, &wait_to_send);
	}
	PRINT_INFO("Child is ready to send");
	pthread_mutex_unlock(&wait_to_send);

	/* Sometimes things are not perfect, and the socket is not ready at first
	 * Instead of enforcing strict ordering, we can be defensive and retry.
	 */ 
	for (int i = 1; i <= MAX_ATTEMPTS; i++) {
		sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (sock_fd != -1) {
			break;
		}
		PRINT_INFO(
			"Titus seccomp unix socket not ready on attempt %d/%d, Sleeping 1 second",
			i, MAX_ATTEMPTS);
		sleep(1);
	}
	if (sock_fd == -1) {
		PRINT_WARNING(
			"Unable to open unix socket for seccomp handoff after %d attempts: %s",
			MAX_ATTEMPTS, strerror(errno));
		kill(child_pid, SIGKILL);
		return;
	}

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
	
	for (int i = 1; i <= MAX_ATTEMPTS; i++) {
		result = connect(sock_fd, (struct sockaddr *)&addr,
					sizeof(addr));
		if (result != -1) {
			break;
		}
		PRINT_INFO(
			"Titus seccomp unix socket not connectable yet on attempt %d/%d, Sleeping 1 second",
			i, MAX_ATTEMPTS);
		sleep(1);
	}
	if (result == -1) {
		PRINT_WARNING(
			"Unable to connect on unix socket (%s) for seccomp handoff after %d attempts: %s",
			socket_path, MAX_ATTEMPTS, strerror(errno));
		kill(child_pid, SIGKILL);
		return;
	}

	/* Sequence the seccomp filter install to happen before sending the notify_fd */
	pthread_mutex_lock(&wait_to_send);
	notify_fd = install_notify_filter();
	if (notify_fd == -1) {
		close(sock_fd);
		kill(child_pid, SIGKILL);
		return;
	}
	fds->fd_to_tsa = sock_fd;
	fds->notify_fd = notify_fd;
	pthread_cond_signal(&ready_to_send);
	PRINT_INFO("Notify fd is valid, can be sent to TSA!");
	pthread_mutex_unlock(&wait_to_send);

	/* Wait for the child to finish sending the notify_fd */
	if (waitpid(-1, NULL, (CHILD_SIG != SIGCHLD) ? __WCLONE : 0) == -1) {
		PRINT_WARNING("waitpid error %s", strerror(errno));
	}
	PRINT_INFO("Child process to send notify_fd to TSA has terminated\n");
}
