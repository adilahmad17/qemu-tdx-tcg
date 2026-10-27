/*
 * Emulated TDX guest memory test (tdx-emu): the shared bit in the page
 * tables, MapGPA, TDG.MEM.PAGE.ACCEPT and the #VE for pending pages and for
 * MMIO. Runs with strict=off and sept-ve-disable=off so that what would stop
 * a strict TD is a #VE the test can count; tdx-mem-strict.c checks the stop.
 *
 * Copyright (C) 2026 The ASTERISC Research Lab
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <inttypes.h>
#include <stdbool.h>
#include <minilib.h>

#define TDG_VP_VMCALL           0
#define TDG_VP_VEINFO_GET       3
#define TDG_MEM_PAGE_ACCEPT     6

#define TDX_SUCCESS                     0x0000000000000000ULL
#define TDX_OPERAND_INVALID             0xC000010000000000ULL
#define TDX_PAGE_ALREADY_ACCEPTED       0x00000B0A00000000ULL
#define TDX_PAGE_SIZE_MISMATCH          0xC0000B0B00000000ULL

#define EXIT_REASON_CPUID       10
#define EXIT_REASON_IO          30
#define EXIT_REASON_MSR_READ    31
#define EXIT_REASON_EPT         48

#define TDVMCALL_MAP_GPA                0x10001
#define TDVMCALL_STATUS_GPA_INUSE       0x8000000000000001ULL

#define SHARED_BIT      (1ULL << 47)    /* the default TD: GPAW 48 */
#define WIDE_BIT        (1ULL << 51)    /* beyond GPAW 48 (phys-bits=52) */
#define REGION_A        0x4000000ULL    /* 64 MiB: a shared 2 MiB region */
#define REGION_B        0x4200000ULL    /* 66 MiB: made private again */
#define REGION_C        0x4400000ULL    /* 68 MiB: accepted as 2 MiB */
#define REGION_D        0x4600000ULL    /* 70 MiB: mapped with bit 51 */
#define IOAPIC          0xfec00000ULL
#define HPET            0xfed00000ULL

struct tdcall_regs {
    uint64_t rax, rcx, rdx, r8, r9, r10, r11, r12, r13, r14, r15;
};

static void tdcall(struct tdcall_regs *r)
{
    register uint64_t r8 asm("r8") = r->r8;
    register uint64_t r9 asm("r9") = r->r9;
    register uint64_t r10 asm("r10") = r->r10;
    register uint64_t r11 asm("r11") = r->r11;
    register uint64_t r12 asm("r12") = r->r12;
    register uint64_t r13 asm("r13") = r->r13;
    register uint64_t r14 asm("r14") = r->r14;
    register uint64_t r15 asm("r15") = r->r15;
    uint64_t rax = r->rax, rcx = r->rcx, rdx = r->rdx;

    asm volatile(".byte 0x66, 0x0f, 0x01, 0xcc"
                 : "+a"(rax), "+c"(rcx), "+d"(rdx), "+r"(r8), "+r"(r9),
                   "+r"(r10), "+r"(r11), "+r"(r12), "+r"(r13), "+r"(r14),
                   "+r"(r15)
                 : : "memory");
    r->rax = rax; r->rcx = rcx; r->rdx = rdx;
    r->r8 = r8; r->r9 = r9; r->r10 = r10; r->r11 = r11;
    r->r12 = r12; r->r13 = r13; r->r14 = r14; r->r15 = r15;
}

static uint64_t tdvmcall(struct tdcall_regs *r, uint64_t leaf)
{
    r->rax = TDG_VP_VMCALL;
    r->rcx = 0xfc00;
    r->r10 = 0;
    r->r11 = leaf;
    tdcall(r);
    return r->rax != TDX_SUCCESS ? r->rax : r->r10;
}

static uint64_t map_gpa(uint64_t gpa, uint64_t size)
{
    struct tdcall_regs r = { .r12 = gpa, .r13 = size };

    return tdvmcall(&r, TDVMCALL_MAP_GPA);
}

static uint64_t accept(uint64_t gpa, unsigned level)
{
    struct tdcall_regs r = { .rax = TDG_MEM_PAGE_ACCEPT, .rcx = gpa | level };

    tdcall(&r);
    return r.rax;
}

/* console output straight through TDG.VP.VMCALL<Instruction.IO> (no #VE) */
static __attribute__((unused)) void early_print(const char *s)
{
    for (; *s; s++) {
        struct tdcall_regs r = { .r12 = 1, .r13 = 1, .r14 = 0xe9, .r15 = (uint8_t)*s };

        tdvmcall(&r, EXIT_REASON_IO);
    }
}

/* ---- #VE handler: console I/O, MMIO through the VMM, pending pages ---- */

struct ve_regs {
    uint64_t r11, r10, r9, r8, rdi, rsi, rbp, rbx, rdx, rcx, rax;
    uint64_t rip, cs, rflags, rsp, ss;
};

static unsigned ve_counts[64];
static unsigned ve_unexpected;
static unsigned ve_pending;         /* #VE for pending pages, accepted here */
static uint64_t ve_last_gpa, ve_last_gla, ve_last_qual;
static uint32_t ve_last_category;

void ve_handler_c(struct ve_regs *regs);

void ve_handler_c(struct ve_regs *regs)
{
    struct tdcall_regs r = { .rax = TDG_VP_VEINFO_GET | (1 << 16) };
    uint32_t reason;

    tdcall(&r);
    if (r.rax != TDX_SUCCESS) {
        ve_unexpected++;
        return;
    }
    reason = r.rcx;
    ve_last_category = r.rcx >> 32;
    ve_last_qual = r.rdx;
    ve_last_gla = r.r8;
    ve_last_gpa = r.r9;
    if (reason < 64) {
        ve_counts[reason]++;
    }

    switch (reason) {
    case EXIT_REASON_IO: {
        uint64_t qual = r.rdx;
        unsigned size = (qual & 7) + 1;
        bool in = qual & (1 << 3);
        struct tdcall_regs io = { .r12 = size, .r13 = in ? 0 : 1,
                                  .r14 = qual >> 16, .r15 = regs->rax };

        tdvmcall(&io, EXIT_REASON_IO);
        if (in) {
            regs->rax = (regs->rax & ~0xffULL) | (io.r11 & 0xff);
        }
        regs->rip += (uint32_t)r.r10;
        break;
    }
    case EXIT_REASON_EPT: {
        const uint8_t *insn = (const uint8_t *)regs->rip;

        if (ve_last_category == 1) {
            /* a pending private page: accept it, the access restarts */
            ve_pending++;
            accept(ve_last_gpa & ~0xfffULL, 0);
            break;
        }
        /* MMIO: the test uses "mov (%rbx), %eax" and "mov %eax, (%rbx)" */
        if (insn[0] == 0x8b && insn[1] == 0x03) {
            struct tdcall_regs m = { .r12 = 4, .r13 = 0, .r14 = ve_last_gpa };

            tdvmcall(&m, EXIT_REASON_EPT);
            regs->rax = (uint32_t)m.r11;
            regs->rip += 2;
        } else if (insn[0] == 0x89 && insn[1] == 0x03) {
            struct tdcall_regs m = { .r12 = 4, .r13 = 1, .r14 = ve_last_gpa,
                                     .r15 = (uint32_t)regs->rax };

            tdvmcall(&m, EXIT_REASON_EPT);
            regs->rip += 2;
        } else {
            ve_unexpected++;
            regs->rip += 2;
        }
        break;
    }
    case EXIT_REASON_CPUID:
    case EXIT_REASON_MSR_READ:
        /* the topology check: counted, zeros returned */
        regs->rax = regs->rdx = 0;
        if (reason == EXIT_REASON_CPUID) {
            regs->rbx = regs->rcx = 0;
        }
        regs->rip += (uint32_t)r.r10;
        break;
    default:
        ve_unexpected++;
        regs->rip += (uint32_t)r.r10;
        break;
    }
}

static __attribute__((naked)) void ve_entry(void)
{
    asm volatile(
        "push %rax\n    push %rcx\n    push %rdx\n    push %rbx\n    push %rbp\n"
        "push %rsi\n    push %rdi\n    push %r8\n    push %r9\n    push %r10\n"
        "push %r11\n"
        "mov %rsp, %rdi\n"
        "mov %rsp, %rbx\n"
        "and $-16, %rsp\n"
        "call ve_handler_c\n"
        "mov %rbx, %rsp\n"
        "pop %r11\n    pop %r10\n    pop %r9\n    pop %r8\n    pop %rdi\n    pop %rsi\n"
        "pop %rbp\n    pop %rbx\n    pop %rdx\n    pop %rcx\n    pop %rax\n"
        "iretq\n");
}

static __attribute__((naked)) void fault_entry(void)
{
    asm volatile(
        "mov $0x41, %eax\n"
        "out %al, $0xf4\n"
        "1:  hlt\n"
        "jmp 1b\n");
}

struct idt_entry {
    uint16_t off0, sel;
    uint8_t ist, type;
    uint16_t off1;
    uint32_t off2, rsvd;
} __attribute__((packed));

static struct idt_entry idt[48] __attribute__((aligned(16)));

static void set_gate(int vec, void (*fn)(void))
{
    uint64_t a = (uint64_t)fn;
    uint16_t cs;

    asm volatile("mov %%cs, %0" : "=r"(cs));
    idt[vec].off0 = a;
    idt[vec].sel = cs;
    idt[vec].type = 0x8e;
    idt[vec].off1 = a >> 16;
    idt[vec].off2 = a >> 32;
}

static void idt_init(void)
{
    struct { uint16_t limit; uint64_t base; } __attribute__((packed)) idtr = {
        sizeof(idt) - 1, (uint64_t)idt };

    for (int v = 0; v < 48; v++) {
        set_gate(v, fault_entry);
    }
    set_gate(20, ve_entry);
    asm volatile("lidt %0" : : "m"(idtr));
}

/* ---- page tables: boot.S maps 0-4 GiB with 2 MiB pages (PML4 -> PDPT -> PD) */

static uint64_t *pd_entry(uint64_t gpa)
{
    uint64_t cr3, *pml4, *pdpt, *pd;

    asm volatile("mov %%cr3, %0" : "=r"(cr3));
    pml4 = (uint64_t *)(cr3 & ~0xfffULL);
    pdpt = (uint64_t *)(pml4[(gpa >> 39) & 0x1ff] & 0x000ffffffffff000ULL);
    pd = (uint64_t *)(pdpt[(gpa >> 30) & 0x1ff] & 0x000ffffffffff000ULL);
    return &pd[(gpa >> 21) & 0x1ff];
}

static void map_bit(uint64_t gpa, uint64_t bit, bool set)
{
    uint64_t *pde = pd_entry(gpa);

    if (set) {
        *pde |= bit;
    } else {
        *pde &= ~bit;
    }
    /* the whole 2 MiB mapping: flush its first page and the TLB with CR3 */
    asm volatile("mov %%cr3, %%rax; mov %%rax, %%cr3" : : : "rax", "memory");
}

static void map_shared_bit(uint64_t gpa, bool shared)
{
    map_bit(gpa, SHARED_BIT, shared);
}

static uint32_t mmio_read(uint64_t addr)
{
    uint32_t v;

    asm volatile("mov (%%rbx), %%eax" : "=a"(v) : "b"(addr) : "memory");
    return v;
}

static void mmio_write(uint64_t addr, uint32_t v)
{
    asm volatile("mov %%eax, (%%rbx)" : : "a"(v), "b"(addr) : "memory");
}

static int failures;
#define CHECK(cond, ...) do { \
    if (cond) { ml_printf("ok   " __VA_ARGS__); ml_printf("\n"); } \
    else { ml_printf("FAIL " __VA_ARGS__); ml_printf("\n"); failures++; } } while (0)

int main(void)
{
    volatile uint64_t *a = (volatile uint64_t *)(REGION_A + 0x100);
    volatile uint64_t *b = (volatile uint64_t *)(REGION_B + 0x1000);
    uint64_t st;
    unsigned before;
    uint32_t v;

#ifdef TDX_EARLY_VE_TEST
    /*
     * A #VE before the TD has an IDT (boot.S loads one without gates): the
     * delivery faults, the #DF too, and the vCPU triple-faults: the VM
     * resets, as on real TDX hardware (-no-reboot: QEMU exits).
     */
    early_print("tdx-early-ve: RDMSR 0x802 before an IDT: the TD must triple-fault\n");
    {
        uint32_t lo, hi;

        asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(0x802));
    }
    early_print("tdx-early-ve: FAIL the TD went on\n");
    return 1;
#endif
    idt_init();
#ifdef TDX_MEM_STRICT_TEST
    ml_printf("tdx-mem-strict: an access to a pending page must stop the VM\n");
    map_gpa(REGION_B | SHARED_BIT, 0x200000);
    map_gpa(REGION_B, 0x200000);
    *b = 1;                             /* not reached: the VM stops */
    ml_printf("tdx-mem-strict: FAIL the VM went on\n");
    return 1;
#endif
    ml_printf("tdx-mem: emulated TDX memory test\n");

    /* the default TD: no topology enumeration (MSR 0x802 and CPUID.0xB are a #VE) */
    {
        uint32_t lo, hi, a, b, c, d;

        before = ve_counts[EXIT_REASON_MSR_READ];
        asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(0x802));
        asm volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                     : "a"(0xb), "c"(0));
        CHECK(ve_counts[EXIT_REASON_MSR_READ] == before + 1 &&
              ve_counts[EXIT_REASON_CPUID] == 1 && ve_last_category == 0x10,
              "enum-topology (default off): MSR 0x802 and CPUID.0xB raise a #VE");
    }

    /* a shared region: MapGPA, then mapped with the shared bit */
    st = map_gpa(REGION_A | SHARED_BIT, 0x200000);
    CHECK(st == 0, "MapGPA of region A to shared");
    map_shared_bit(REGION_A, true);
    before = ve_counts[EXIT_REASON_EPT];
    *a = 0x1122334455667788ULL;
    CHECK(*a == 0x1122334455667788ULL && ve_counts[EXIT_REASON_EPT] == before,
          "a shared page through a shared mapping: no #VE, data kept");
    map_shared_bit(REGION_A, false);
    v = mmio_read(REGION_A + 0x100);        /* the VMM reads the shared page */
    CHECK(ve_counts[EXIT_REASON_EPT] == before + 1 && ve_last_category == 0 &&
          !(ve_last_gpa & SHARED_BIT) && v == 0x55667788,
          "a shared page through a private mapping: #VE (strict would stop)");
    map_shared_bit(REGION_A, true);
    st = map_gpa(0xffff0000 | SHARED_BIT, 0x10000);
    CHECK(st == TDVMCALL_STATUS_GPA_INUSE, "MapGPA of the firmware image: GPA_INUSE");

    /* back to private: pending until accepted, the #VE accepts a page */
    st = map_gpa(REGION_B | SHARED_BIT, 0x200000);
    st |= map_gpa(REGION_B, 0x200000);
    CHECK(st == 0, "MapGPA of region B to shared and to private again");
    before = ve_counts[EXIT_REASON_EPT];
    *b = 42;
    CHECK(ve_pending == 1 && ve_counts[EXIT_REASON_EPT] == before + 1 &&
          ve_last_category == 1 && (ve_last_gpa & ~0xfffULL) == REGION_B + 0x1000,
          "a pending page: #VE of category 1 with its GPA, accepted, restarted");
    CHECK(*b == 42 && ve_counts[EXIT_REASON_EPT] == before + 1,
          "the accepted page is usable without another #VE");
    st = accept(REGION_B + 0x1000, 0);
    CHECK(st == TDX_PAGE_ALREADY_ACCEPTED, "ACCEPT again: PAGE_ALREADY_ACCEPTED");
    st = accept(REGION_B, 1);
    CHECK(st == (TDX_PAGE_SIZE_MISMATCH | 1), "ACCEPT 2 MiB over mixed pages: PAGE_SIZE_MISMATCH");
    st = accept(REGION_B + 0x2000, 0);
    CHECK(st == TDX_SUCCESS && *(volatile uint64_t *)(REGION_B + 0x2000) == 0,
          "ACCEPT of a pending page: success, the page is zero");

    /* a whole 2 MiB region */
    *(volatile uint64_t *)(REGION_C + 8) = 7;
    st = map_gpa(REGION_C | SHARED_BIT, 0x200000);
    st |= map_gpa(REGION_C, 0x200000);
    st |= accept(REGION_C, 1);
    CHECK(st == TDX_SUCCESS && *(volatile uint64_t *)(REGION_C + 8) == 0,
          "ACCEPT of 2 MiB: success, zero-filled");
    st = accept(REGION_C, 1);
    CHECK(st == (TDX_PAGE_ALREADY_ACCEPTED | 1), "ACCEPT of 2 MiB again: PAGE_ALREADY_ACCEPTED (level 1)");
    st = accept(REGION_C + 0x1000, 1);
    CHECK(st == (TDX_OPERAND_INVALID | 1), "ACCEPT of a misaligned 2 MiB: OPERAND_INVALID");
    st = accept(IOAPIC, 0);
    CHECK(st == (TDX_OPERAND_INVALID | 1), "ACCEPT of MMIO: OPERAND_INVALID");
    st = accept(REGION_A, 0);
    CHECK(st == TDX_SUCCESS, "ACCEPT of a shared page: converted (strict would stop)");

    /*
     * A mapping with bit 51, the shared bit of a TD that takes it from a
     * 52-bit width instead of GPAW 48: a GPA beyond GPAW, a #VE (the TD is
     * not stopped, strict or not).
     */
    map_bit(REGION_D, WIDE_BIT, true);
    before = ve_counts[EXIT_REASON_EPT];
    v = mmio_read(REGION_D + 0x40);
    CHECK(ve_counts[EXIT_REASON_EPT] == before + 1 && ve_last_category == 0 &&
          ve_last_gpa == ((REGION_D + 0x40) | WIDE_BIT),
          "an access to a GPA beyond GPAW: #VE with that GPA (%" PRIx64 ")", ve_last_gpa);
    map_bit(REGION_D, WIDE_BIT, false);

    /* MMIO through a shared mapping: the IOAPIC */
    map_shared_bit(IOAPIC, true);
    before = ve_counts[EXIT_REASON_EPT];
    mmio_write(IOAPIC, 1);                  /* IOREGSEL = version */
    v = mmio_read(IOAPIC + 0x10);           /* IOWIN */
    {
        uint64_t qual = ve_last_qual, gpa = ve_last_gpa, gla = ve_last_gla;
        unsigned category = ve_last_category;

        CHECK(ve_counts[EXIT_REASON_EPT] == before + 2 && category == 0 &&
              gpa == ((IOAPIC + 0x10) | SHARED_BIT) && gla == IOAPIC + 0x10,
              "MMIO through a shared mapping: #VE with the GPA (shared bit) and GLA");
        CHECK((v & 0xff) == 0x20 || (v & 0xff) == 0x11, "IOAPIC version read through the VMM: %x", v);
        CHECK((qual & 0x87) == 0x81, "MMIO read qualification: read, GLA valid (%" PRIx64 ")", qual);
    }

    /* MMIO through a private mapping (the HPET shares the IOAPIC's 2 MiB): a #VE too */
    map_shared_bit(IOAPIC, false);
    before = ve_counts[EXIT_REASON_EPT];
    v = mmio_read(HPET);
    {
        uint64_t gpa = ve_last_gpa;

        CHECK(ve_counts[EXIT_REASON_EPT] == before + 1 && !(gpa & SHARED_BIT) && gpa == HPET,
              "MMIO through a private mapping: #VE without the shared bit (strict would stop)");
    }

    CHECK(ve_unexpected == 0, "no unexpected #VE");
    ml_printf("tdx-mem: %d failures\n", failures);

    /* chipset power management for the ACPI power-off of the exit path */
    asm volatile("outl %0, %1" : : "a"(0x8000f840u), "Nd"((uint16_t)0xcf8));
    asm volatile("outl %0, %1" : : "a"(0x00000601u), "Nd"((uint16_t)0xcfc));
    asm volatile("outl %0, %1" : : "a"(0x8000f844u), "Nd"((uint16_t)0xcf8));
    asm volatile("outb %0, %1" : : "a"((uint8_t)0x80), "Nd"((uint16_t)0xcfc));
    return failures ? 1 : 0;
}
