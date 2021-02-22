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
#include <sys/ioctl.h>
#include <sys/syscall.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <pthread.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>  
#include <linux/seccomp.h>
#include <linux/filter.h>

#include "seccomp_fd_notify.h"
#define MAX_EVENTS 16
#define EPOLL_IGNORED_VAL 3

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
   notifications can be fetched. 
*/
static int install_notify_filter(void) {
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

struct sock_filter net_perf_filter[] = {
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
		/* Trap connect */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect, 0, 1),
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
	if (is_handle_net != NULL) {
		prog.filter = net_perf_filter;
		prog.len = 
			(unsigned short)(sizeof(net_perf_filter) / sizeof(net_perf_filter[0]));
		PRINT_INFO("Networking system calls will be intercepted");
	} else {
		prog.filter = perf_filter;
		prog.len = 
			(unsigned short)(sizeof(perf_filter) / sizeof(perf_filter[0]));
		PRINT_INFO("BPF/Perf system calls will be intercepted");
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

void set_seccomp_response_to_continue(struct seccomp_notif *req,
				      struct seccomp_notif_resp *resp)
{
	resp->id = req->id;
	resp->val = 0;
	resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
	resp->error = 0;
}

void respond_to_seccomp_client(int notify_fd, struct seccomp_notif_resp *resp)
{
	if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, resp) == -1) {
		if (errno == ENOENT) {
			printf(
				"response failed with ENOENT; perhaps target "
				"process's syscall was interrupted by signal?");
		} else {
			perror("ioctl-SECCOMP_IOCTL_NOTIF_SEND");
		}
	}
}

void * catch_send_fd(void *fd_arg)
{
	struct seccomp_notif *req;
	struct seccomp_notif_resp *resp;
	struct seccomp_notif_sizes sizes;
	struct epoll_event ev;
	struct epoll_event evlist[MAX_EVENTS];
	int epfd = -1, ready = 0;
	int set_break = 0;
	int notify_fd = *(int *)fd_arg;

	if (seccomp(SECCOMP_GET_NOTIF_SIZES, 0, &sizes) == -1) {
        PRINT_WARNING("seccomp-SECCOMP_GET_NOTIF_SIZES not available?");
		return NULL;
	}
	
	req = malloc(sizes.seccomp_notif);
	if (req == NULL) {
		PRINT_WARNING("malloc req error!");
		return NULL;
	}

	resp = malloc(sizes.seccomp_notif_resp);
	if (resp == NULL) {
		PRINT_WARNING("malloc resp error!");
		return NULL;
	}

	epfd = epoll_create(EPOLL_IGNORED_VAL);
	if (epfd == -1) {
		PRINT_WARNING("epoll_create error");
		return NULL;
	}
	ev.events = EPOLLIN;
	ev.data.fd = notify_fd;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, notify_fd, &ev) == -1) {
		perror("epoll_ctl");
		PRINT_WARNING("Unexpected error in adding notify_fd to epoll watch");
		return NULL;
	}
	PRINT_INFO("Listening to networking syscall notifications on %d..", notify_fd);

	for (;;) {
		/* Wait for next notification, returning info in '*req' */
		memset(req, 0, sizeof(*req));
		memset(resp, 0, sizeof(*resp));
		pthread_mutex_lock(&wait_to_send);
		send_notify_fd = 1;
		pthread_cond_signal(&ready_to_send);
		pthread_mutex_unlock(&wait_to_send);
		ready = epoll_wait(epfd, evlist, MAX_EVENTS, -1);
		if (ready == -1) {
			if (errno == EINTR)
				continue; /* Restart if interrupted by signal */
			else {
				perror("epoll_wait");
				PRINT_WARNING("epoll_wait error");
				return NULL;
			}
		}
		PRINT_INFO("  fd=%d; events: %s%s%s", evlist[0].data.fd,
			    (evlist[0].events & EPOLLIN) ? "EPOLLIN " : "",
			    (evlist[0].events & EPOLLHUP) ? "EPOLLHUP " : "",
			    (evlist[0].events & EPOLLERR) ? "EPOLLERR " : "");

		if (evlist[0].events & EPOLLIN) {
			if (ioctl(evlist[0].data.fd, SECCOMP_IOCTL_NOTIF_RECV,
				  req) == -1) {
				PRINT_WARNING(
					"ioctl SECCOMP_IOCTL_NOTIF_RECV error");
				return NULL;
			}
		}
		
		if (evlist[0].events & EPOLLHUP) {
			/* Client has exited */
			char buf[16];
			int r =  read(evlist[0].data.fd, buf, 16);
			if (r < 0) {
				PRINT_INFO("Client exited, draining notification, removing notify fd");
			}
			if (epoll_ctl(epfd, EPOLL_CTL_DEL, notify_fd, &ev) !=
			    0) {
				perror("Could not epoll_del the notifyfd\n");
			} else {
				PRINT_INFO("Removed the notify_fd of client");
			}
			return NULL;
		}
		if (req->data.nr == __NR_sendmsg) {
			PRINT_INFO("Intercepted sendmsg - passthrough!\n");
			set_break = 1;
		} else {
			PRINT_INFO("Intercepted syscall %d - passthrough!\n", req->data.nr);
		}
		set_seccomp_response_to_continue(req, resp);
		respond_to_seccomp_client(notify_fd, resp);
		if (set_break) {
			break;
		}
	}
	PRINT_INFO("Stopped polling notifyfd = %d!", notify_fd);
	return NULL;
}

void maybe_setup_seccomp_notifer() {
	char *socket_path;
	pthread_t thread_id;

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

		pthread_create(&thread_id, NULL, &catch_send_fd, (void *)&notify_fd);		
		pthread_mutex_lock(&wait_to_send);
		while(send_notify_fd == 0) {
			pthread_cond_wait(&ready_to_send, &wait_to_send);
		}
		PRINT_INFO("Can send the notify fd now!");
		pthread_mutex_unlock(&wait_to_send);
		

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
		pthread_join(thread_id, NULL);
	}
	return;
}
