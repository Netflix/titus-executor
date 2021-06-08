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
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <string.h>
#include "bpf_api.h"

struct ipv4_key {
	__u32		vlan_tci;
	__be32		addr;
};

struct bpf_elf_map __section_maps ipv4_map = {
        .type           = BPF_MAP_TYPE_HASH,
        .size_key       = sizeof(struct ipv4_key),
        .size_value     = sizeof(__u16),
        .pinning        = PIN_GLOBAL_NS,
        .max_elem       = 10240,
};


struct ipv6_key {
	__u32		vlan_tci;
	struct in6_addr	addr;
};

struct bpf_elf_map __section_maps ipv6_map = {
        .type           = BPF_MAP_TYPE_HASH,
        .size_key       = sizeof(struct ipv6_key),
        .size_value     = sizeof(__u16),
        .pinning        = PIN_GLOBAL_NS,
        .max_elem       = 10240,
};


#define METADATA_SERVICE_IP 0xA9FEA9FE /* 169.254.169.254 */

static inline int classifier_egress_filter_v4(struct __sk_buff *skb) {
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *iph = data + sizeof(struct ethhdr);
	struct ipv4_key key;
	__u32 *handle;


	if ((void*)iph + sizeof(struct iphdr) > data_end)
		return TC_ACT_SHOT;

	if (iph->daddr == __constant_htonl(METADATA_SERVICE_IP))
		return TC_ACT_SHOT;

	key.vlan_tci = skb->vlan_tci;
	memcpy(&key.addr, &iph->saddr, sizeof(__be32));


	handle = map_lookup_elem(&ipv4_map, &key);
	if (handle)
		skb->tc_classid = TC_H_MAKE(1 << 16, (*handle) & 0xffff);

	return TC_ACT_OK;
}

static inline int classifier_egress_filter_v6(struct __sk_buff *skb) {
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ipv6hdr *iph = data + sizeof(struct ethhdr);
	struct ipv6_key key;
	__u32 *handle;

	if ((void*)iph + sizeof(struct ipv6hdr) > data_end)
		return TC_ACT_SHOT;

	if (iph->daddr.in6_u.u6_addr8[0] == 0xfd &&
	    iph->daddr.in6_u.u6_addr8[1] == 0x00 &&
	    iph->daddr.in6_u.u6_addr8[2] == 0x0e &&
	    iph->daddr.in6_u.u6_addr8[3] == 0xc2 &&
	    iph->daddr.in6_u.u6_addr8[4] == 0x00 &&
	    iph->daddr.in6_u.u6_addr8[5] == 0x00 &&
	    iph->daddr.in6_u.u6_addr8[6] == 0x00 &&
	    iph->daddr.in6_u.u6_addr8[7] == 0x00 &&
	    iph->daddr.in6_u.u6_addr8[8] == 0x00 &&
	    iph->daddr.in6_u.u6_addr8[9] == 0x00 &&
	    iph->daddr.in6_u.u6_addr8[10] == 0x00 &&
	    iph->daddr.in6_u.u6_addr8[11] == 0x00 &&
	    iph->daddr.in6_u.u6_addr8[12] == 0x00 &&
	    iph->daddr.in6_u.u6_addr8[13] == 0x00 &&
	    iph->daddr.in6_u.u6_addr8[14] == 0x02 &&
	    iph->daddr.in6_u.u6_addr8[15] == 0x54)
		return TC_ACT_SHOT;

	key.vlan_tci = skb->vlan_tci;
	memcpy(&key.addr, &iph->saddr, sizeof(struct in6_addr));


	handle = map_lookup_elem(&ipv6_map, &key);
	if (handle)
		skb->tc_classid = TC_H_MAKE(1 << 16, (*handle) & 0xffff);

	return TC_ACT_OK;
}

__section("classifier_egress")
int classifier_egress_filter(struct __sk_buff *skb) {
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct ethhdr *eth = data;

	if (data + sizeof(*eth) > data_end)
		return TC_ACT_SHOT;

	/* TODO: Verify that the dst mac is the mac returned from bpf_fib_lookup
	   to prevent anyone trying to bypass hairpin routing.
	 */
	switch (eth->h_proto) {
	case __constant_htons(ETH_P_IP):
		return classifier_egress_filter_v4(skb);
	case __constant_htons(ETH_P_IPV6):
		return classifier_egress_filter_v6(skb);
	case __constant_htons(ETH_P_ARP):
		return TC_ACT_OK;
	default:
		return TC_ACT_SHOT;
	}
}

static inline int classifier_ingress_filter_v4(struct __sk_buff *skb) {
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct iphdr *iph = data + sizeof(struct ethhdr);
	struct ipv4_key key;
	__u32 *handle;

	if ((void*)iph + sizeof(*iph) > data_end)
		return TC_ACT_SHOT;

	key.vlan_tci = skb->vlan_tci;
	memcpy(&key.addr, &iph->daddr, sizeof(__be32));


	handle = map_lookup_elem(&ipv4_map, &key);
	if (handle)
		skb->tc_classid = TC_H_MAKE(1 << 16, (*handle) & 0xffff);

	return TC_ACT_OK;
}

static inline int classifier_ingress_filter_v6(struct __sk_buff *skb) {
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ipv6hdr *iph = data + sizeof(struct ethhdr);
	struct ipv6_key key;
	__u32 *handle;

	if ((void*)iph + sizeof(struct ipv6hdr) > data_end)
		return TC_ACT_SHOT;

	key.vlan_tci = skb->vlan_tci;
	memcpy(&key.addr, &iph->daddr, sizeof(struct in6_addr));


	handle = map_lookup_elem(&ipv6_map, &key);
	if (handle)
		skb->tc_classid = TC_H_MAKE(1 << 16, (*handle) & 0xffff);

	return TC_ACT_OK;
}

__section("classifier_ingress")
int classifier_ingress_filter(struct __sk_buff *skb) {
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct ethhdr *eth = data;

	if (data + sizeof(*eth) > data_end)
		return TC_ACT_SHOT;

	switch (eth->h_proto) {
	case __constant_htons(ETH_P_IP):
		return classifier_ingress_filter_v4(skb);
	case __constant_htons(ETH_P_IPV6):
		return classifier_ingress_filter_v6(skb);
	case __constant_htons(ETH_P_ARP):
		return TC_ACT_OK;
	default:
		return TC_ACT_SHOT;
	}
}

/*
 * Although Apache 2.0 considers itself to be GPL compatible, it's not by the kernel,
 * we don't use any GPL-only functionality. If we do, we may consider moving to
 * "GPL and additional rights"
 */

// #BPF_LICENSE("Apache 2.0");
BPF_LICENSE("GPL");
