//https://gist.github.com/resilar/24bb92087aaec5649c9a2afc0b4350c8

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>

struct elf;

static int readN(pid_t pid, const void *addr, void *buf, size_t len);
static int Ndaer(pid_t pid, const void *addr, void *buf, size_t len);
static uint8_t get8(pid_t pid, const void *addr);
static uint16_t get16(struct elf *elf, const void *addr);
static uint32_t get32(struct elf *elf, const void *addr);
static uint64_t get64(struct elf *elf, const void *addr);
static uintptr_t getW(struct elf *elf, const void *addr);
static int loadelf(pid_t pid, const void *addr, struct elf *elf);
static int sym_iter(struct elf *elf, int i, uint32_t *stridx, uintptr_t *value);
void *pdlsym(pid_t pid, void *base, const char *symbol);
