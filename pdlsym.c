//https://gist.github.com/resilar/24bb92087aaec5649c9a2afc0b4350c8

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

int fd = 0;

struct elf {
    pid_t pid;
    uintptr_t base;
    uint8_t class, data;
    uint16_t type;
    int W;

    int (*getN)(pid_t pid, const void *addr, void *buf, size_t len);

    struct {
        uintptr_t offset;
        uint16_t size, num;
    } phdr;

    uintptr_t symtab, syment;
    uintptr_t strtab, strsz;
};

static int readN(pid_t pid, const void *addr, void *buf, size_t len)
{
    if (fd == 0){
	    char file[64];
	    sprintf(file, "/proc/%ld/mem", (long)pid);
	    fd = open(file, O_RDWR);
    }

    pread(fd, buf, len, (long)(addr));

    return !0;
}

static int Ndaer(pid_t pid, const void *addr, void *buf, size_t len)
{
    int ok = readN(pid, addr, buf, len);
    if (ok) {
        char *p, *q;
        for (p = buf, q = p + len-1; p < q; *p ^= *q, *q ^= *p, *p++ ^= *q--);
    }
    return ok;
}

static uint8_t get8(pid_t pid, const void *addr)
{
    uint8_t ret;
    return readN(pid, addr, &ret, sizeof(uint8_t)) ? ret : 0;
}
static uint16_t get16(struct elf *elf, const void *addr)
{
    uint16_t ret;
    return elf->getN(elf->pid, addr, &ret, sizeof(uint16_t)) ? ret : 0;
}
static uint32_t get32(struct elf *elf, const void *addr)
{
    uint32_t ret;
    return elf->getN(elf->pid, addr, &ret, sizeof(uint32_t)) ? ret : 0;
}
static uint64_t get64(struct elf *elf, const void *addr)
{
    uint64_t ret;
    return elf->getN(elf->pid, addr, &ret, sizeof(uint64_t)) ? ret : 0;
}

static uintptr_t getW(struct elf *elf, const void *addr)
{
    return (elf->class == 0x01) ? (uintptr_t)get32(elf, addr)
                                : (uintptr_t)get64(elf, addr);
}

static int loadelf(pid_t pid, const void *addr, struct elf *elf)
{
    uint32_t magic;
    int i, j, loads;
    const char *base = addr;

    /*
     * ELF header.
     */
    elf->pid = pid;
    elf->base = (uintptr_t)base;
    readN(pid, base, &magic, 4);
    if ((!memcmp(&magic, "\x7F" "ELF", 4) && (elf->class = get8(pid, base+4)) == 1 || elf->class == 2)
            && ((elf->data = get8(pid, base+5)) == 1 || elf->data == 2)
            && get8(pid, base+6) == 1) {
        union { uint16_t value; char buf[2]; } data;
        data.value = (uint16_t)0x1122;
        elf->getN = (data.buf[0] & elf->data) ? Ndaer : readN;
        elf->type = get16(elf, base + 0x10);
        elf->W = (2 << elf->class);
    } else {
	printf("! BAD ELF\n");
        /* Bad ELF */
        return 0;
    }

    /*
     * Program headers.
     */
    loads = 0;
    elf->strtab = elf->strsz = elf->symtab = elf->syment = 0;
    elf->phdr.offset = getW(elf, base + 0x18 + elf->W);
    elf->phdr.size = get16(elf, base + 0x18 + elf->W*3 + 0x6);
    elf->phdr.num = get16(elf, base + 0x18 + elf->W*3 + 0x8);
    for (i = 0; i < elf->phdr.num; i++) {
        uintptr_t offset, vaddr, filesz, memsz;
        const char *ph = base + elf->phdr.offset + i*elf->phdr.size;
        uint32_t phtype = get32(elf, ph);
        if (phtype == 0 /* PT_NULL */)
            break;
        if (phtype != 1 /* PT_LOAD */ && phtype != 2 /* PT_DYNAMIC */)
            continue;

        offset = getW(elf, ph + elf->W);
        vaddr  = getW(elf, ph + elf->W*2);
        filesz = getW(elf, ph + elf->W*4);
        memsz  = getW(elf, ph + elf->W*5);
        if (vaddr < offset || memsz < filesz)
            return 0;

        if (phtype == 1) { /* PT_LOAD */
            if (elf->type == 2) { /* ET_EXEC */
                if (vaddr - offset < elf->base) {
                    /* This is not the lowest base of the ELF */
                    errno = EFAULT;
                    return 0;
                }
            }
            loads++;
        } else if (phtype == 2) { /* PT_DYNAMIC */
            uintptr_t type, value;
            const char *tag = (char *)((elf->type == 2) ? 0 : base) + vaddr;
            for (j = 0; 2*j*elf->W < memsz; j++) {
                if ((type = getW(elf, tag + 2*elf->W*j))) {
                    value = getW(elf, tag + 2*elf->W*j + elf->W);
                    switch (type) {
                    case 5: elf->strtab = value; break; /* DT_STRTAB */
                    case 6: elf->symtab = value; break; /* DT_SYMTAB */
                    case 10: elf->strsz = value; break; /* DT_STRSZ */
                    case 11: elf->syment = value; break; /* DT_SYMENT */
                    default: break;
                    }
                } else {
                    /* DT_NULL */
                    break;
                }
            }
        }
    }

    /* Check that we have all program headers required for dynamic linking */
    if (!loads || !elf->strtab || !elf->strsz || !elf->symtab || !elf->syment)
        return 0;

    /* String table (immediately) follows the symbol table */
    if (!(elf->symtab < elf->strtab))
        return 0;

    /* Symbol entry size is a non-zero integer that divides symtab size */
    if ((elf->strtab - elf->symtab) % elf->syment)
        return 0;

    /* All OK! */
    return 1;
}

static int sym_iter(struct elf *elf, int i, uint32_t *stridx, uintptr_t *value)
{
    if (i*elf->syment < elf->strtab - elf->symtab) {
        const char *sym = (char *)elf->symtab + i*elf->syment;
        if (elf->symtab < elf->base)
            sym += elf->base;
        if ((*stridx = get32(elf, sym)) < elf->strsz) {
            if ((*value = getW(elf, sym + elf->W)) && elf->type != 2)
                *value += elf->base;
            return 1;
        }
    }
    return 0;
}

void *pdlsym(pid_t pid, void *base, const char *symbol)
{
    struct elf elf;
    uintptr_t value = 0;
    if (loadelf((pid == getpid()) ? 0 : pid, base, &elf)) {
        int i;
        uint32_t stridx;
        const char *strtab;
        size_t size = strlen(symbol) + 1;
        strtab = (char *)elf.strtab + ((elf.strtab < elf.base) ? elf.base : 0);
        for (i = 0; sym_iter(&elf, i, &stridx, &value); value = 0, i++) {
            if (value && stridx+size <= elf.strsz) {
                size_t j = 0;
                while (j < size) {
                    char buf[sizeof(long)];
                    int n = ((uintptr_t)strtab + stridx+j) % sizeof(buf);
                    n = (size-j < sizeof(buf)) ? (size-j) : (sizeof(buf) - n);
                    if (!readN(elf.pid, strtab + stridx+j, &buf, n))
                        break;
                    if (memcmp(&symbol[j], &buf, n))
                        break;
                    j += n;
                }
                if (j == size)
                    break;
            }
        }
    }
    if(fd != 0){
	    close(fd);
	    fd = 0;
    }
    return (void *)value;
}
