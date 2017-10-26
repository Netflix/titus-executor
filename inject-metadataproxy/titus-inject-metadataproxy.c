#include <stdio.h>
#include <stdlib.h>
#include <linux/limits.h>
#include <errno.h>

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
/* Netlink */
#include <netlink/socket.h>
#include <netlink/route/link.h>
#include <netlink/route/link/veth.h>
#include <netlink/route/addr.h>
#include <linux/if.h>
#include <netlink/route/route.h>
/* Kernel netlink headers */
#include <linux/rtnetlink.h>

#define IN_CONTAINER_INTERFACE_NAME	"metadataservice"
#define IN_PRIVATE_NS_INTERFACE_NAME	"tocontainer"

/*
The metadata proxy injector operates on having a TITUS_PID_1_DIR environment variable set

1. It saves the current namespace
2. It opens the container's network namespace at TITUS_PID_1_DIR/ns/net
3. It calls unshare, and creates an entirely new network namespace.
4. It creates a veth pair on this namespace
5. It adds the IP address 169.254.169.254 to the veth pair
6. It binds to port 80 in the new netns created
7. It moves a side of the veth into the container's network namespace
8. It sets up a route in the container's netns
9. It changes to the PID ns of the container
10. It calls the metadata proxy code
*/

/* Print Error, and Quit */
#define BUG(message, ...)	do { fprintf(stderr, "%s:%s:%d: " message "\n", "BUG", __func__, __LINE__, ##__VA_ARGS__); exit(1); } while(0)
#define BUG_ON(expr, message, ...)	do { if(expr) { fprintf(stderr, "%s:%s:%d: " message "\n", "BUG", __func__, __LINE__, ##__VA_ARGS__); exit(1); } } while(0)
#define BUG_ON_PERROR(expr, message, ...) do { if(expr) { fprintf(stderr, "%s:%s:%d:%s " message "\n", "BUG", __func__, __LINE__, strerror(errno), ##__VA_ARGS__); exit(1); } } while(0)

#define PASSED_FD	169
#define TITUS_PID_1_DIR	"TITUS_PID_1_DIR"

/* This will drop us into the new namespace */
static void setup_namespaces(int *original_ns, int *container_ns, int *new_ns, int *container_pid_ns) {
	char container_ns_path[PATH_MAX];
	char *pid1dir;

	*original_ns = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	BUG_ON_PERROR(*original_ns == -1, "Could not open original network namespace handle");

	pid1dir = getenv(TITUS_PID_1_DIR);
	BUG_ON(!pid1dir, "TITUS_PID_1_DIR unset");

	snprintf(container_ns_path, sizeof(container_ns_path), "%s/ns/net", pid1dir);
	*container_ns = open(container_ns_path, O_RDONLY | O_CLOEXEC);
	BUG_ON_PERROR(*container_ns == -1, "Could not open container network namespace");

	snprintf(container_ns_path, sizeof(container_ns_path), "%s/ns/pid", pid1dir);
	*container_pid_ns = open(container_ns_path, O_RDONLY | O_CLOEXEC);
	BUG_ON_PERROR(*container_pid_ns == -1, "Could not open container PID  namespace");

	BUG_ON_PERROR(unshare(CLONE_NEWNET), "Could not unshare, and setup new namespace");

	*new_ns = open("/proc/self/ns/net", O_RDONLY);
	BUG_ON_PERROR(*new_ns == -1, "Could not open new network namespace handle");
}

static void interface_up(int ns_fd, char *interface_name) {
	struct rtnl_link *link, *changes;
	struct nl_sock *nls;
	int err;

	changes = rtnl_link_alloc();
	BUG_ON(!changes, "Unable to allocate link");

	BUG_ON_PERROR(setns(ns_fd, CLONE_NEWNET), "Unable to switch to Namespace");
	nls = nl_socket_alloc();
	BUG_ON(!nls, "Could not allocate netlink socket");

	err = nl_connect(nls, NETLINK_ROUTE);
	if (err < 0) {
		nl_perror(err, "Unable to connect socket");
		exit(1);
	}

	err = rtnl_link_get_kernel(nls, 0, interface_name, &link);
	BUG_ON(err < 0, "%s: unable to get interface: %s", nl_geterror(err), interface_name);

	rtnl_link_set_flags(changes, IFF_UP);

	err = rtnl_link_change(nls, link, changes, NLM_F_CREATE);
	BUG_ON(err < 0, "%s: unable to set interface up: %s", nl_geterror(err), interface_name);

	rtnl_link_put(link);
	rtnl_link_put(changes);

	nl_close(nls);
	nl_socket_free(nls);
}

void setup_veth(int private_ns_fd, int container_ns_fd) {
	struct rtnl_link *veth, *peer;
	struct nl_sock *nls;
	int err;

	BUG_ON_PERROR(setns(private_ns_fd, CLONE_NEWNET), "Unable to switch to Private Namespace");
	nls = nl_socket_alloc();
	BUG_ON(!nls, "Could not allocate netlink socket");

	err = nl_connect(nls, NETLINK_ROUTE);
	BUG_ON(err < 0, "%s: unable to connect netlink route socket", nl_geterror(err));

	veth = rtnl_link_veth_alloc();
	BUG_ON(!veth, "Could not allocate link\n");

	rtnl_link_set_name(veth, IN_PRIVATE_NS_INTERFACE_NAME);

	peer = rtnl_link_veth_get_peer(veth);
	rtnl_link_set_name(peer, IN_CONTAINER_INTERFACE_NAME);
	rtnl_link_set_ns_fd(peer, container_ns_fd);

	err = rtnl_link_add(nls, veth, NLM_F_CREATE | NLM_F_EXCL);
	BUG_ON(err < 0, "%s: unable to add link", nl_geterror(err));

	rtnl_link_put(peer);
	rtnl_link_put(veth);
	nl_close(nls);
	nl_socket_free(nls);
}

void add_addr(int ns_fd, int af, char *interface_name, char *addrstr) {
	struct rtnl_addr *rtnladdr;
	struct rtnl_link *link;
	struct nl_addr *addr;
	struct nl_sock *nls;
	int err;

	rtnladdr = rtnl_addr_alloc();
	BUG_ON(!rtnladdr, "Unable to allocate rtnladdr");

	BUG_ON_PERROR(setns(ns_fd, CLONE_NEWNET), "Unable to switch to Namespace");

	err = nl_addr_parse(addrstr, af, &addr);
	BUG_ON(err < 0, "%s: unable to parse ip: %s", nl_geterror(err), addrstr);

	nls = nl_socket_alloc();
	BUG_ON(!nls, "Could not allocate netlink socket");

	err = nl_connect(nls, NETLINK_ROUTE);
	BUG_ON(err < 0, "%s: unable to connect netlink route socket", nl_geterror(err));

	err = rtnl_link_get_kernel(nls, 0, interface_name, &link);
	BUG_ON(err < 0, "%s: unable to get interface: %s", nl_geterror(err), interface_name);

	rtnl_addr_set_ifindex(rtnladdr, rtnl_link_get_ifindex(link));
	rtnl_addr_set_local(rtnladdr, addr);
	err = rtnl_addr_add(nls, rtnladdr, 0);
	BUG_ON(err < 0, "%s: unable to add address to interface", nl_geterror(err));

	nl_close(nls);
	nl_socket_free(nls);
	rtnl_link_put(link);
	rtnl_addr_put(rtnladdr);
	nl_addr_put(addr);
}

void add_route(int ns_fd, int af, char *dst, char *gateway, char *interface_name) {
	struct nl_addr *gateway_addr, *dst_addr;
	struct rtnl_link *interface;
	struct rtnl_route *route;
	struct rtnl_nexthop *nh;
	struct nl_sock *nls;
	int err;

	nls = nl_socket_alloc();
	BUG_ON(!nls, "Could not allocate netlink socket");
	route = rtnl_route_alloc();
	BUG_ON(!route, "Unable to allocate route");
	nh = rtnl_route_nh_alloc();
	BUG_ON(!nh, "Unable to allocate next hop");
	rtnl_route_set_type(route, RTN_UNICAST);

	BUG_ON_PERROR(setns(ns_fd, CLONE_NEWNET), "Unable to switch to Namespace");

	err = nl_addr_parse(dst, af, &dst_addr);
	BUG_ON(err < 0, "%s: unable to parse ip: %s", nl_geterror(err), dst);
	err = nl_addr_parse(gateway, af, &gateway_addr);
	BUG_ON(err < 0, "%s: unable to parse ip: %s", nl_geterror(err), gateway);
	err = rtnl_route_set_dst(route, dst_addr);
	BUG_ON(err < 0, "%s: unable to set route destination", nl_geterror(err));
	rtnl_route_nh_set_gateway(nh, gateway_addr);

	err = nl_connect(nls, NETLINK_ROUTE);
	BUG_ON(err < 0, "%s: unable to connect netlink route socket", nl_geterror(err));

	err = rtnl_link_get_kernel(nls, 0, interface_name, &interface);
	BUG_ON(err < 0, "%s: unable to get interface: %s", nl_geterror(err), interface_name);
	rtnl_route_nh_set_ifindex(nh, rtnl_link_get_ifindex(interface));
	rtnl_link_put(interface);

	/* The route now owns the next hop object */
	rtnl_route_add_nexthop(route, nh);
	err = rtnl_route_add(nls, route, RTM_NEWROUTE | NLM_F_EXCL);
	BUG_ON(err < 0, "%s: unable to add route", nl_geterror(err));

	nl_close(nls);
	nl_socket_free(nls);

	rtnl_route_put(route);
	nl_addr_put(dst_addr);
	nl_addr_put(gateway_addr);
}

void do_reexec(char *argv[], int container_pid_ns, int new_ns, int host_ns, struct stat *container_stat) {
	struct sockaddr_in sin = {
		.sin_family	= AF_INET,
		.sin_port	= htons(80),
		.sin_addr	= {
			.s_addr	= 0,
		}
	};
	int sock, status;
	pid_t pid;

	/* Setup the bound socket in the namespace with the metadata proxy addr */
	BUG_ON_PERROR(setns(new_ns, CLONE_NEWNET), "Unable to switch to Namespace");
	sock = socket(AF_INET, SOCK_STREAM, 0);
	BUG_ON_PERROR(sock < 0, "Could not create socket in namespace");
	BUG_ON_PERROR(bind(sock, (const struct sockaddr*)&sin, sizeof(sin)), "Could not bind to port");
	BUG_ON_PERROR(dup2(sock, PASSED_FD) == -1, "Could not duplicate file descriptor");
	BUG_ON_PERROR(listen(PASSED_FD, 100) == -1, "Could not set socket in passive mode");

	/* Switch back to the host network namespace, so we can connect to the real world */
	BUG_ON_PERROR(setns(host_ns, CLONE_NEWNET), "Unable to switch to Namespace");

	/* This should still be safe to do, even now that the container can look
	 * at our /proc entry, because we haven't dropped privileges yet
	 */
	BUG_ON_PERROR(setns(container_pid_ns, CLONE_NEWPID), "Unable to switch to Namespace");

	pid = vfork();

	if (pid == 0) {
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		BUG_ON_PERROR(setgid(container_stat->st_gid), "Unable to drop GID");
		BUG_ON_PERROR(setuid(container_stat->st_uid), "Unable to drop UID");
		BUG_ON_PERROR(execvp(argv[1], &argv[1]) == -1, "Could not execute child");
	}
	/* We will only return here once the child finishes */
	waitpid(pid, &status, 0);
	exit(WEXITSTATUS(status));
}

int main(int argc, char *argv[]) {
	int original_ns, container_ns, new_ns, container_pid_ns;
	char environ_path[PATH_MAX];
	struct stat container_stat;

	BUG_ON(argc < 2, "Usage %s child-binary [args]", argv[0]);
	setup_namespaces(&original_ns, &container_ns, &new_ns, &container_pid_ns);

	/* Cheating a bit, but setup_namespace has ensured getenv(TITUS_PID_1_DIR) will resolve */
	snprintf(environ_path, sizeof(environ_path), "%s/environ", getenv(TITUS_PID_1_DIR));
	BUG_ON_PERROR(stat(environ_path, &container_stat) == -1, "Unable to stat container environ file");

	interface_up(new_ns, "lo");
	setup_veth(new_ns, container_ns);
	interface_up(new_ns, IN_PRIVATE_NS_INTERFACE_NAME);
	interface_up(container_ns, IN_CONTAINER_INTERFACE_NAME);
	add_addr(new_ns, AF_INET, IN_PRIVATE_NS_INTERFACE_NAME, "169.254.169.254/31");
	add_addr(container_ns, AF_INET, IN_CONTAINER_INTERFACE_NAME, "169.254.169.255/31");
	add_route(new_ns, AF_INET, "0.0.0.0/0", "169.254.169.255", IN_PRIVATE_NS_INTERFACE_NAME);

	/* re exec dance */
	do_reexec(argv, container_pid_ns, new_ns, original_ns, &container_stat);

	return 0;
}
