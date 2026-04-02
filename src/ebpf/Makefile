CLANG ?= clang
TARGET_ARCH ?= x86
CC ?= gcc

ARCH_FLAG = -D__TARGET_ARCH_$(TARGET_ARCH)

deadlock.bpf.o: deadlock.bpf.c vmlinux.h
	$(CLANG) -O2 -g -target bpf $(ARCH_FLAG) -c deadlock.bpf.c -o deadlock.bpf.o

loader: loader.c deadlock.bpf.o
	$(CC) -O2 -g -o loader loader.c -lbpf -lelf -lz

all: deadlock.bpf.o loader

clean:
	rm -f deadlock.bpf.o loader

.PHONY: all clean