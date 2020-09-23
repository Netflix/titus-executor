#include <assert.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/tcp.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>

int main() {
	int fd, val;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	assert(fd != -1);

	val = 1;
	assert(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) == 0);

	val = 1;
	assert(setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val)) == 0);

	assert(SOL_PACKET == 263);
	assert(setsockopt(fd, SOL_PACKET, -1, 0, 0) == -1);
	assert(errno != -EPERM);

	assert(PACKET_VNET_HDR == 15);
	assert(setsockopt(fd, -1, PACKET_VNET_HDR, 0, 0) == -1);
	assert(errno != -EPERM);

	return 0;
}
