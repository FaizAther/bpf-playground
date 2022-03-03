#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "tc.h"


//#include <linux/if_ether.h>
#define ETH_P_IP	0x0800
#define ETH_P_ARP	0x0806


//#include <linux/pkt_cls.h>
#define TC_ACT_OK	0
#define TC_ACT_SHOT	2

#define htons	bpf_htons
#define ntohs	bpf_ntohs
#define ntohl	bpf_ntohl

pid_t mpid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 32 * 1024);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 10);
	__type(value, u16);
	__type(key, u32);
} ports SEC(".maps");

struct iphdr *
is_ipv4(struct ethhdr *eth, void *data_end)
{
	struct iphdr *iph = NULL;
	if (!eth || !data_end) {
		return NULL;
	}
	if ((void *)eth + sizeof(*eth) + sizeof(*iph) > data_end) {
		return NULL;
	}
	if (eth->h_proto == htons(ETH_P_IP)) {
		iph = (struct iphdr *)((void *)eth + sizeof(*eth));
	}
	return iph;
}

struct udphdr *
is_udp(void *iph, u8 hdr_sz, void *data_end)
{
	struct udphdr *udph = NULL;
	if (!iph || !data_end) {
		return NULL;
	}
	if ((void *)(iph + hdr_sz + sizeof(*udph)) > data_end) {
		return NULL;
	}

	int proto = -1;
	if (hdr_sz == sizeof(struct iphdr)) {
		struct iphdr *v4 = (struct iphdr *)iph;
		proto = v4->protocol;
	} else if (hdr_sz == sizeof(struct ipv6hdr)) {
		struct ipv6hdr *v6 = (struct ipv6hdr *)iph;
		proto = v6->nexthdr;
	}
	if (proto == IPPROTO_UDP) {
		udph = (struct udphdr *)((void *)iph + hdr_sz);
	}
	return udph;
}

struct arphdr *is_arp(struct ethhdr *eth, void *data_end)
{
	struct arphdr *arp = NULL;
	if (!eth || !data_end) {
		return NULL;
	}
	if ((void *)eth + sizeof(*eth) + sizeof(*arp) > data_end) {
		return NULL;
	}
	if (eth->h_proto == htons(ETH_P_ARP)) {
		arp = (struct arphdr *)((void *)eth + sizeof(*eth));
	}
	return arp;
}

SEC("tc")
int
handle_egress(struct __sk_buff *skb)
{
	int decision = TC_ACT_SHOT;
	struct task_struct *t = \
		(struct task_struct *)bpf_get_current_task();
	if (t == NULL) {
		bpf_printk("ERROR: bpf_get_current_task\n");
		goto rb_err;
	}
	pid_t tgid = BPF_CORE_READ(t, tgid);
	pid_t  pid = BPF_CORE_READ(t, pid);

	if (tgid == mpid) {
		decision = TC_ACT_OK;
		bpf_printk("ALERT: Kernel socket\n");
		return decision;
	}

	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = (struct ethhdr *)(void *)(long)skb->data;
	struct iphdr *iph = is_ipv4(eth, data_end);
	struct arphdr *arp = is_arp(eth, data_end);

	struct tc_evt *evt = NULL;
	evt = bpf_ringbuf_reserve(&rb, sizeof(*evt), 0);
	if (!evt) {
		bpf_printk("ERROR: bpf_ringbuf_reserve\n");
		goto rb_err;
	}
	__builtin_memset(evt, 0, sizeof(*evt));

	evt->eth_type = htons(BPF_CORE_READ(eth, h_proto));
	bpf_probe_read_kernel_str(evt->comm, TASK_SIZ, \
		BPF_CORE_READ(t, group_leader, comm));
	evt->tgid = tgid;
	evt->pid = pid;
	bpf_printk("comm={%s}, eth_type={%04x}", evt->comm, evt->eth_type);

//--
	if (iph) {
		u8 hdr_sz = sizeof(*iph);
		struct udphdr *udph = is_udp(iph, hdr_sz, data_end);

		u32 daddr = iph->daddr;
		if (udph) {
			bpf_printk("dest_ip={%08x}", ntohl(daddr));
		} else {
			goto err;
		}

		bpf_probe_read_kernel(&evt->ip.addr.ip4_addr, \
			sizeof(evt->ip.addr.ip4_addr), &daddr);
		if (udph) {
			bpf_printk("GOT: udp (%d -> %d)", \
				htons(udph->source), htons(udph->dest));
			evt->ip.port = ntohs(udph->dest);
		}
	} else if (arp) {
		bpf_probe_read_kernel(&evt->arp, sizeof(evt->arp), arp);
		bpf_printk("GOT: arp");
	}
//--
	decision = TC_ACT_SHOT;
	if (evt->eth_type == ETH_P_ARP) decision = TC_ACT_OK;
	bpf_printk("%d\n", evt->ip.port);
	switch (decision)
	{
		case TC_ACT_SHOT:
			evt->state = BLOCKED;
			break;
		default:
			evt->state = ALLOWED;
	}
	bpf_ringbuf_submit(evt, 0);
	evt = NULL;
err:
	if (evt) bpf_ringbuf_discard(evt, 0);
rb_err:
	return (decision);
}

char LICENSE[] SEC("license") = "GPL";
