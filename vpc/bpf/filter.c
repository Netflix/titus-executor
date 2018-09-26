/*
 * Compilation instructions:
 * clang -O2 -emit-llvm -c filter.c -o - | llc -march=bpf -filetype=obj -o filter.o
 */
#include <stdint.h>
#include <asm/types.h>

#include <linux/bpf.h>
#include <linux/pkt_sched.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>

#ifndef __section
# define __section(x)  __attribute__((section(x), used))
#endif

struct eth_hdr {
	unsigned char   h_dest[ETH_ALEN];
	unsigned char   h_source[ETH_ALEN];
	unsigned short  h_proto;
};


#define METADATA_SERVICE_IP 0xA9FEA9FE /* 169.254.169.254 */

__section("classifier_egress")
int classifier_egress_filter(struct __sk_buff *skb) {
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct eth_hdr *eth = data;
	struct iphdr *iph = data + sizeof(*eth);

	if (data + sizeof(*eth) + sizeof(*iph) > data_end)
		return TC_ACT_SHOT;

	if (eth->h_proto == __constant_htons(ETH_P_IP) && iph->daddr == __constant_htonl(METADATA_SERVICE_IP))
		return TC_ACT_SHOT;

	/* See explanation behind this in setup_container_linux.go, under setupIFBClasses */
	if (eth->h_proto == __constant_htons(ETH_P_IP))
		skb->tc_classid = TC_H_MAKE(1 << 16, __builtin_bswap32(iph->saddr) & 0xffff);

	return TC_ACT_OK;
}

__section("classifier_ingress")
int classifier_ingress_filter(struct __sk_buff *skb) {
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct eth_hdr *eth = data;
	struct iphdr *iph = data + sizeof(*eth);

	if (data + sizeof(*eth) + sizeof(*iph) > data_end)
		return TC_ACT_SHOT;

	if (eth->h_proto == __constant_htons(ETH_P_IP))
		skb->tc_classid = TC_H_MAKE(1 << 16, __builtin_bswap32(iph->daddr) & 0xffff);
	return TC_ACT_OK;
}

/*
 * Although Apache 2.0 considers itself to be GPL compatible, it's not by the kernel,
 * we don't use any GPL-only functionality. If we do, we may consider moving to
 * "GPL and additional rights"
 */

char __license[] __section("license") = "Apache 2.0";
