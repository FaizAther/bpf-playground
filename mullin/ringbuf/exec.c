#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/resource.h>

#include "exec.skel.h"
#include "exec.h"

static void
bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "ERROR: setrlimit %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
}

static int
handle_evt(void *ctx, void *data, size_t sz)
{
	const struct exec_evt *evt = data;

	fprintf(stdout, \
		"tgid={%d}, pid={%d}, comm={%s}, file={%s}\n", \
		evt->tgid, evt->pid, evt->comm, evt->file);

	return 0;
}

int
main(void)
{
	bump_memlock_rlimit();
	struct exec *skel = exec__open();
	exec__load(skel);
	exec__attach(skel);
	
	int fd = bpf_map__fd(skel->maps.rb);
	if (fd < 0) {
		fprintf(stderr, "ERROR: bpf_map__fd %d %s\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	struct ring_buffer *rb = ring_buffer__new( \
		fd, handle_evt, NULL, NULL);

	for(;;) {
		ring_buffer__poll(rb, 1000);
	}

	return EXIT_SUCCESS;
}
