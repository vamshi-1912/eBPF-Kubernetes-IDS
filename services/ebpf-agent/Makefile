# Builds the libbpf CO-RE eBPF object, its skeleton and the C loader.
CLANG   ?= clang
BPFTOOL ?= bpftool
CC      ?= gcc
UNAME_M := $(shell uname -m)
ARCH    := $(shell echo $(UNAME_M) | sed 's/x86_64/x86/;s/aarch64/arm64/')
OUT     := build

all: $(OUT)/ids_loader

$(OUT):
	mkdir -p $(OUT)

$(OUT)/ids.bpf.o: bpf/ids.bpf.c bpf/ids.h | $(OUT)
	$(CLANG) -g -O2 -Wall -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I/usr/include/$(UNAME_M)-linux-gnu -c $< -o $@

$(OUT)/ids.skel.h: $(OUT)/ids.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(OUT)/ids_loader: loader/ids_loader.c $(OUT)/ids.skel.h bpf/ids.h
	$(CC) -O2 -Wall -I$(OUT) $< -lbpf -lelf -lz -o $@

clean:
	rm -rf $(OUT)

.PHONY: all clean
