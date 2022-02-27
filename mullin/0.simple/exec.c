#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/resource.h>

#include "exec.skel.h"

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

int
main(void)
{
	bump_memlock_rlimit();
	struct exec *skel = exec__open();
	exec__load(skel);
	exec__attach(skel);

	for(;;) {}

	return EXIT_SUCCESS;
}
