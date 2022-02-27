APP=exec

.PHONY: exec
exec: skel
	clang exec.c -lbpf -o exec

.PHONY: vmlinux
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: bpf
bpf: vmlinux
	clang -g -O2 -target bpf -c exec.bpf.c -o exec.bpf.o

.PHONY: skel
skel: bpf
	bpftool gen skeleton exec.bpf.o name exec > exec.skel.h
	rm -rf exec.bpf.o

.PHONY: run
run: $(APP)

clean:
	rm -rf *.o vmlinux.h $(APP) exec.skel.h
