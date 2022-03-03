#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <stdint.h>
#include <net/if_arp.h>
#include <sys/resource.h>
#include <signal.h>
#include <unistd.h>

#include <linux/pkt_sched.h>

#include <bpf/bpf.h>

#include "tc.h"
#include "tc.skel.h"

#define ETH_P_IP	0x0800

static volatile bool
exiting = false;

static void
sig_handler(int s_val)
{
	exiting = true;
}

//static void
//bump_memlock_rlimit(void)
//{
//	struct rlimit rlim_n = {
//		.rlim_cur = RLIM_INFINITY,
//		.rlim_max = RLIM_INFINITY
//	};
//
//	if (setrlimit(RLIMIT_MEMLOCK, &rlim_n)) {
//		fprintf(stderr, "ERROR: setrlimit %s\n", strerror(errno));
//		exit(EXIT_FAILURE);
//	}
//}

static int
handle_evt(void *ctx, void *data, size_t sz)
{
	struct tc_evt *evt = data;
	printf("PAKT\n");
	if (evt->state == ALLOWED) printf("ALLOWD ");
	else printf("BLKED ");

	if (evt->eth_type == ETH_P_IP)
	{
		printf("comm={%s}\n", evt->comm);
		printf("tgid={%d}, pid={%d}\n", evt->tgid, evt->pid);
		if (evt->ip.ipp == UDP_V4) {
			char addr[15];
			memset(addr, 0, sizeof(addr));
			snprintf(addr, sizeof(addr), "%d.%d.%d.%d", \
				evt->ip.addr.ip4_addr[0], \
				evt->ip.addr.ip4_addr[1], \
				evt->ip.addr.ip4_addr[2], \
				evt->ip.addr.ip4_addr[3]);
		} else {
			printf("NOT: udp\n");
		}
	} else {
		printf("NOT: eth\n");
	}

	fflush(stdout);
	return 0;
}

int
main(int argc, char *argv[])
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, \
		.ifindex = 2, .attach_point = BPF_TC_EGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, \
		.handle = 1, .priority = 1);

//	bump_memlock_rlimit();

	signal(SIGTERM, sig_handler);
	signal(SIGINT, sig_handler);

	struct tc *skel = tc__open_and_load();
	skel->bss->mpid = getpid();

	bpf_tc_hook_create(&hook);
	hook.attach_point = BPF_TC_CUSTOM;
	hook.parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS);
	opts.prog_fd = bpf_program__fd(skel->progs.handle_egress);
	opts.prog_id = 0;
	opts.flags = BPF_TC_F_REPLACE;

	bpf_tc_attach(&hook, &opts);

	int map_fd = bpf_map__fd(skel->maps.ports);
	for (int i = 0; i < argc; i++) {
		int port = atoi(argv[i]);
		//allow_port(map_fd, port);
	}

	struct ring_buffer *rb = ring_buffer__new(\
		bpf_map__fd(skel->maps.rb), handle_evt, NULL, NULL);

	while (!exiting) {
		ring_buffer__poll(rb, 1000);
	}

	opts.flags = opts.prog_id = opts.prog_fd = 0;
	int dtch = bpf_tc_detach(&hook, &opts);
	int dstr = bpf_tc_hook_destroy(&hook);

	printf("USRS: dtch={%d}, dstr={%d}\n", dtch, dstr);

	return 0;
}

