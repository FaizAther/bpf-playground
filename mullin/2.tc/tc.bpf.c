#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "tc.h"

#define TC_ACT_SHOT	2

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

SEC("tc")
int
handle_egress(struct __sk_buff *skb)
{
	int decision = TC_ACT_SHOT;
	struct task_struct *ts = \
		(struct task_struct *)bpf_get_current_task();
	pid_t tgid = BPF_CORE_READ(ts, tgid);
	pid_t  pid = BPF_CORE_READ(ts, pid);

	struct tc_evt *evt = NULL;
	evt = bpf_ringbuf_reserve(&rb, sizeof(*evt), 0);
	if (!evt) {
		bpf_printk("ERROR: bpf_ringbuf_reserve\n");
		goto rb_err;
	}
	__builtin_memset(evt, 0, sizeof(*evt));

	bpf_ringbuf_submit(evt, 0);
	evt = NULL;
	(void)skb;
err:
	if (evt) bpf_ringbuf_discard(evt, 0);
rb_err:
	return (decision);
}

char LICENSE[] SEC("license") = "GPL";
