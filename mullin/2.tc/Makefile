APP=tc

.PHONY: $(APP)
$(APP): skel
	clang tc.c -Wno-unsequenced -lbpf -lelf -o $(APP)

.PHONY: vmlinux
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: bpf
bpf: vmlinux
	clang -g -O3 -target bpf -D__TARGET_ARCH_x86_64 -c tc.bpf.c -o tc.bpf.o

.PHONY: skel
skel: bpf
	bpftool gen skeleton tc.bpf.o name tc > tc.skel.h

.PHONY: run
run: $(APP)
	sudo ./$(APP) 8080

.PHONY: block
block:
	sudo ./$(APP)

.PHONY: clean
clean:
	rm -rf *.o *.skel.h vmlinux.h $(APP)
