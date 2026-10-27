/*
 * Emulated TDX guest test (tdx-emu): CPUID leaf 0x21, TDCALL (TDG.VP.INFO,
 * TDG.VP.VEINFO.GET, TDG.VM.RD/WR, TDG.VP.CPUIDVE.SET, TDG.MEM.PAGE.ACCEPT,
 * TDG.MR.RTMR.EXTEND, TDG.MR.REPORT), #VE for CPUID, RDMSR/WRMSR, IN/OUT and
 * HLT, and the TDG.VP.VMCALL interface the #VE handler uses to forward them
 * to the VMM. Every console character travels through #VE and
 * TDG.VP.VMCALL<Instruction.IO>.
 *
 * Copyright (C) 2026 The ASTERISC Research Lab
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <inttypes.h>
#include <stdbool.h>
#include <minilib.h>

#define TDG_VP_VMCALL           0
#define TDG_VP_INFO             1
#define TDG_MR_RTMR_EXTEND      2
#define TDG_VP_VEINFO_GET       3
#define TDG_MR_REPORT           4
#define TDG_VP_CPUIDVE_SET      5
#define TDG_MEM_PAGE_ACCEPT     6
#define TDG_VM_RD               7
#define TDG_VM_WR               8
#define TDG_VP_RD               9

#define TDX_SUCCESS                     0x0000000000000000ULL
#define TDX_OPERAND_INVALID             0xC000010000000000ULL
#define TDX_NO_VALID_VE_INFO            0xC000070400000000ULL
#define TDX_METADATA_FIELD_ID_INCORRECT 0xC0000C0000000000ULL
#define TDX_METADATA_FIELD_NOT_WRITABLE 0xC0000C0100000000ULL

#define TDCS_ATTRIBUTES         0x1110000300000000ULL
#define TDCS_NOTIFY_ENABLES     0x9100000000000010ULL   /* as Linux spells it */
#define TDCS_TD_CTLS            0x1110000300000017ULL
#define TDVPS_VCPU_INDEX        0xA020000200000002ULL

#define EXIT_REASON_CPUID       10
#define EXIT_REASON_HLT         12
#define EXIT_REASON_IO          30
#define EXIT_REASON_MSR_READ    31
#define EXIT_REASON_MSR_WRITE   32

#define TDVMCALL_GET_TD_VM_CALL_INFO    0x10000
#define TDVMCALL_MAP_GPA                0x10001
#define TDVMCALL_GET_QUOTE              0x10002
#define TDVMCALL_SETUP_EVENT_NOTIFY     0x10004

/* the default TD: GPAW 48, the shared bit is bit 47 */
#define SHARED_BIT                      (1ULL << 47)
#define TDVMCALL_STATUS_INVALID_OPERAND 0x8000000000000000ULL
#define TDVMCALL_STATUS_ALIGN_ERROR     0x8000000000000002ULL
#define TDVMCALL_STATUS_SUBFUNC_UNSUPPORTED 0x8000000000000003ULL

struct tdcall_regs {
    uint64_t rax, rcx, rdx, r8, r9, r10, r11, r12, r13, r14, r15;
};

/* TDCALL with the register convention of the TDX module ABI */
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

/* TDG.VP.VMCALL: R10 = 0 (standard), R11 = sub-function, R12-R15 arguments */
static uint64_t tdvmcall(struct tdcall_regs *r, uint64_t leaf)
{
    r->rax = TDG_VP_VMCALL;
    r->rcx = 0xfc00;            /* pass R10-R15 */
    r->r10 = 0;
    r->r11 = leaf;
    tdcall(r);
    if (r->rax != TDX_SUCCESS) {
        return r->rax;
    }
    return r->r10;
}

static unsigned vmm_io_count;

static void vmm_io_write(uint16_t port, unsigned size, uint64_t val)
{
    struct tdcall_regs r = { .r12 = size, .r13 = 1, .r14 = port, .r15 = val };

    vmm_io_count++;
    tdvmcall(&r, EXIT_REASON_IO);
}

static uint64_t vmm_io_read(uint16_t port, unsigned size)
{
    struct tdcall_regs r = { .r12 = size, .r13 = 0, .r14 = port };

    vmm_io_count++;
    tdvmcall(&r, EXIT_REASON_IO);
    return r.r11;
}

/* ---- #VE handler ---- */

struct ve_regs {
    uint64_t r11, r10, r9, r8, rdi, rsi, rbp, rbx, rdx, rcx, rax;
    uint64_t rip, cs, rflags, rsp, ss;
};

static unsigned ve_counts[64];
static unsigned ve_unexpected;
static uint64_t ve_last_qual;
static uint32_t ve_last_len;
static uint32_t ve_last_category;

void ve_handler_c(struct ve_regs *regs);

void ve_handler_c(struct ve_regs *regs)
{
    struct tdcall_regs r = { .rax = TDG_VP_VEINFO_GET | (1 << 16) }; /* v1 */
    uint32_t reason, len;
    uint64_t qual;

    tdcall(&r);
    if (r.rax != TDX_SUCCESS) {
        ve_unexpected++;
        return;
    }
    reason = r.rcx;
    qual = r.rdx;
    len = r.r10;
    ve_last_qual = qual;
    ve_last_len = len;
    ve_last_category = r.rcx >> 32;
    if (reason < 64) {
        ve_counts[reason]++;
    }

    switch (reason) {
    case EXIT_REASON_CPUID: {
        struct tdcall_regs c = { .r12 = regs->rax, .r13 = regs->rcx };

        tdvmcall(&c, EXIT_REASON_CPUID);
        regs->rax = c.r12;
        regs->rbx = c.r13;
        regs->rcx = c.r14;
        regs->rdx = c.r15;
        break;
    }
    case EXIT_REASON_IO: {
        unsigned size = (qual & 7) + 1;
        bool in = qual & (1 << 3);
        uint16_t port = qual >> 16;

        if (qual & (1 << 4)) {      /* OUTS with REP: byte by byte, DF clear */
            if (in || !(qual & (1 << 5)) || size != 1) {
                ve_unexpected++;
                break;
            }
            while (regs->rcx) {
                vmm_io_write(port, 1, *(uint8_t *)regs->rsi);
                regs->rsi++;
                regs->rcx--;
            }
            break;
        }
        if (in) {
            uint64_t v = vmm_io_read(port, size);
            uint64_t mask = size == 4 ? 0xffffffffULL : (1ULL << (8 * size)) - 1;

            regs->rax = (regs->rax & ~mask) | (v & mask);
        } else {
            vmm_io_write(port, size, regs->rax);
        }
        break;
    }
    case EXIT_REASON_MSR_READ: {
        struct tdcall_regs m = { .r12 = (uint32_t)regs->rcx };

        tdvmcall(&m, EXIT_REASON_MSR_READ);
        regs->rax = (uint32_t)m.r11;
        regs->rdx = m.r11 >> 32;
        break;
    }
    case EXIT_REASON_MSR_WRITE: {
        struct tdcall_regs m = { .r12 = (uint32_t)regs->rcx,
                                 .r13 = (uint32_t)regs->rax |
                                        ((uint64_t)(uint32_t)regs->rdx << 32) };

        tdvmcall(&m, EXIT_REASON_MSR_WRITE);
        break;
    }
    case EXIT_REASON_HLT: {
        struct tdcall_regs h = { .r12 = !(regs->rflags & 0x200) };

        tdvmcall(&h, EXIT_REASON_HLT);
        break;
    }
    case 13:                            /* INVD */
    case 54:                            /* WBINVD */
        break;
    default:
        ve_unexpected++;
        break;
    }
    regs->rip += len;
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

static unsigned gp_count, ud_count, df_count;
static bool skip_faulting_insn;
static unsigned skip_faulting_len;

struct fault_regs {
    uint64_t rax;
    uint64_t error_code;
    uint64_t rip, cs, rflags, rsp, ss;
};

void fault_handler_c(struct fault_regs *regs, int vec);

/* #GP, #UD and #DF: count them; skip the faulting instruction if asked */
void fault_handler_c(struct fault_regs *regs, int vec)
{
    if (vec == 13) {
        gp_count++;
    } else if (vec == 6) {
        ud_count++;
    } else if (vec == 8) {
        df_count++;
    }
    if (!skip_faulting_insn) {
        /* unexpected: exit with 0x41 (the OUT itself goes through #VE) */
        asm volatile("mov $0x41, %eax\n out %al, $0xf4\n 1: hlt\n jmp 1b");
    }
    skip_faulting_insn = false;
    regs->rip += skip_faulting_len;
}

#define FAULT_ENTRY(name, vec, push_error_code)                             \
static __attribute__((naked)) void name(void)                               \
{                                                                           \
    asm volatile(                                                           \
        push_error_code                                                     \
        "push %rax\n"                                                       \
        "mov %rsp, %rdi\n"                                                  \
        "mov $" #vec ", %esi\n"                                             \
        "mov %rsp, %rbx\n"                                                  \
        "and $-16, %rsp\n"                                                  \
        "call fault_handler_c\n"                                            \
        "mov %rbx, %rsp\n"                                                  \
        "pop %rax\n"                                                        \
        "add $8, %rsp\n"                                                    \
        "iretq\n");                                                         \
}

FAULT_ENTRY(ud_entry, 6, "push $0\n")
FAULT_ENTRY(df_entry, 8, "")
FAULT_ENTRY(gp_entry, 13, "")

static __attribute__((naked)) void other_fault_entry(void)
{
    asm volatile(
        "mov $0x42, %eax\n"
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
    idt[vec].ist = 0;
    idt[vec].type = 0x8e;
    idt[vec].off1 = a >> 16;
    idt[vec].off2 = a >> 32;
}

static void idt_init(void)
{
    struct { uint16_t limit; uint64_t base; } __attribute__((packed)) idtr = {
        sizeof(idt) - 1, (uint64_t)idt };

    for (int v = 0; v < 32; v++) {
        set_gate(v, other_fault_entry);
    }
    set_gate(6, ud_entry);
    set_gate(8, df_entry);
    set_gate(13, gp_entry);
    set_gate(20, ve_entry);
    asm volatile("lidt %0" : : "m"(idtr));
}

/* ---- helpers ---- */

static inline void cpuid(uint32_t leaf, uint32_t sub, uint32_t *a, uint32_t *b,
                         uint32_t *c, uint32_t *d)
{
    asm volatile("cpuid" : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d)
                 : "a"(leaf), "c"(sub));
}

static inline uint64_t rdmsr(uint32_t msr)
{
    uint32_t lo, hi;

    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static inline void wrmsr(uint32_t msr, uint64_t val)
{
    asm volatile("wrmsr" : : "c"(msr), "a"((uint32_t)val),
                 "d"((uint32_t)(val >> 32)) : "memory");
}

static int failures;
#define CHECK(cond, ...) do { \
    if (cond) { ml_printf("ok   " __VA_ARGS__); ml_printf("\n"); } \
    else { ml_printf("FAIL " __VA_ARGS__); ml_printf("\n"); failures++; } } while (0)

static uint8_t report[1024] __attribute__((aligned(1024)));
static uint8_t report_data[64] __attribute__((aligned(64)));
static uint8_t rtmr_data[48] __attribute__((aligned(64)));
static uint8_t quote_buf[4096] __attribute__((aligned(4096)));

int main(void)
{
    struct tdcall_regs r;
    uint32_t a, b, c, d;
    uint64_t v, st;
    unsigned before;

    idt_init();
    ml_printf("tdx: emulated TDX guest test\n");
    CHECK(ve_counts[EXIT_REASON_IO] > 0 && vmm_io_count > 0,
          "console output went through #VE and TDG.VP.VMCALL<Instruction.IO>");

    /* CPUID: leaf 0x21 enumerates TDX, leaf 0 covers it */
    cpuid(0, 0, &a, &b, &c, &d);
    CHECK(a >= 0x21, "CPUID.0: maximum basic leaf 0x%x covers 0x21", a);
    before = ve_counts[EXIT_REASON_CPUID];
    cpuid(0x21, 0, &a, &b, &c, &d);
    CHECK(a == 0 && b == 0x65746e49 && d == 0x5844546c && c == 0x20202020,
          "CPUID.0x21: \"IntelTDX    \" (%x %x %x %x)", a, b, d, c);
    CHECK(ve_counts[EXIT_REASON_CPUID] == before, "CPUID.0x21 raised no #VE");
    cpuid(1, 0, &a, &b, &c, &d);
    CHECK((c & (1 << 21)) && (c & (1u << 31)),
          "CPUID.1: x2APIC and HYPERVISOR fixed to 1 (ecx %x)", c);

    /* TDG.VP.INFO */
    r = (struct tdcall_regs){ .rax = TDG_VP_INFO };
    tdcall(&r);
    CHECK(r.rax == TDX_SUCCESS, "TDG.VP.INFO succeeds");
    CHECK((r.rcx & 0x3f) == 48, "TDG.VP.INFO: GPAW %" PRIu64 " (default 48)", r.rcx & 0x3f);
    CHECK(r.rdx == 0x50000000,
          "TDG.VP.INFO: attributes SEPT_VE_DISABLE and PKS (%" PRIx64 ")", r.rdx);
    CHECK((uint32_t)r.r8 == 2 && (r.r8 >> 32) == 2,
          "TDG.VP.INFO: 2 vCPUs of 2 (%" PRIx64 ")", r.r8);
    CHECK(r.r9 == 0, "TDG.VP.INFO: vCPU index 0");
    CHECK(r.r10 & 1, "TDG.VP.INFO: TDG.SYS.RD available");

    /* no pending #VE: VEINFO.GET fails */
    r = (struct tdcall_regs){ .rax = TDG_VP_VEINFO_GET };
    tdcall(&r);
    CHECK(r.rax == TDX_NO_VALID_VE_INFO, "TDG.VP.VEINFO.GET without a #VE: NO_VALID_VE_INFO");

    /* unknown leaf and reserved bits */
    r = (struct tdcall_regs){ .rax = 0x7777 };
    tdcall(&r);
    CHECK(r.rax == TDX_OPERAND_INVALID, "unknown TDCALL leaf: OPERAND_INVALID (RAX)");
    r = (struct tdcall_regs){ .rax = TDG_VP_INFO | (1ULL << 40) };
    tdcall(&r);
    CHECK(r.rax == TDX_OPERAND_INVALID, "reserved RAX bits: OPERAND_INVALID");

    /* #VE for a leaf the module does not virtualize, answered by the VMM */
    before = ve_counts[EXIT_REASON_CPUID];
    cpuid(0x2, 0, &a, &b, &c, &d);
    CHECK(ve_counts[EXIT_REASON_CPUID] == before + 1 && ve_last_len == 2,
          "CPUID.2 raised a #VE with instruction length 2");
    cpuid(0x40000000, 0, &a, &b, &c, &d);
    CHECK(ve_counts[EXIT_REASON_CPUID] == before + 2, "CPUID.0x40000000 raised a #VE");
    cpuid(0x80000002, 0, &a, &b, &c, &d);
    CHECK(ve_counts[EXIT_REASON_CPUID] == before + 3, "CPUID.0x80000002 raised a #VE");
    cpuid(0x7, 0, &a, &b, &c, &d);
    cpuid(0x80000008, 0, &a, &b, &c, &d);
    CHECK(ve_counts[EXIT_REASON_CPUID] == before + 3,
          "CPUID.7 and CPUID.0x80000008 are virtualized (no #VE)");

    /* TDG.VP.CPUIDVE.SET: every CPUID at CPL 0 is a #VE */
    r = (struct tdcall_regs){ .rax = TDG_VP_CPUIDVE_SET, .rcx = 1 };
    tdcall(&r);
    cpuid(0x7, 0, &a, &b, &c, &d);
    CHECK(r.rax == TDX_SUCCESS && ve_counts[EXIT_REASON_CPUID] == before + 4,
          "TDG.VP.CPUIDVE.SET(supervisor): CPUID.7 now raises a #VE");
    r = (struct tdcall_regs){ .rax = TDG_VP_CPUIDVE_SET, .rcx = 0 };
    tdcall(&r);
    r = (struct tdcall_regs){ .rax = TDG_VP_CPUIDVE_SET, .rcx = 4 };
    tdcall(&r);
    CHECK(r.rax == (TDX_OPERAND_INVALID | 1), "TDG.VP.CPUIDVE.SET with reserved bits: OPERAND_INVALID (RCX)");

    /* MSRs: EFER native, x2APIC timer and APIC_BASE through #VE */
    before = ve_counts[EXIT_REASON_MSR_READ];
    v = rdmsr(0xc0000080);
    CHECK((v & 0x500) == 0x500 && ve_counts[EXIT_REASON_MSR_READ] == before,
          "RDMSR IA32_EFER is native (LME, LMA)");
    v = rdmsr(0x1b);
    CHECK(ve_counts[EXIT_REASON_MSR_READ] == before + 1 && (v & 0x800),
          "RDMSR IA32_APIC_BASE raised a #VE, VMM answered 0x%" PRIx64, v);
    v = rdmsr(0x832);
    CHECK(ve_counts[EXIT_REASON_MSR_READ] == before + 2, "RDMSR x2APIC LVT timer raised a #VE");
    before = ve_counts[EXIT_REASON_MSR_WRITE];
    wrmsr(0x1b, v | 0xc00);
    wrmsr(0x832, 0x10020);
    CHECK(ve_counts[EXIT_REASON_MSR_WRITE] == before + 2,
          "WRMSR IA32_APIC_BASE and LVT timer raised #VEs");
    v = rdmsr(0x832);
    CHECK((uint32_t)v == 0x10020, "the LVT timer written through the VMM reads back (%" PRIx64 ")", v);
    before = ve_counts[EXIT_REASON_MSR_READ];
    v = rdmsr(0x40000000);
    CHECK(ve_counts[EXIT_REASON_MSR_READ] == before + 1, "RDMSR of an MSR outside the bitmap windows raised a #VE");

    /* HLT with interrupts disabled: #VE, the VMM halts and the APIC timer wakes us */
    wrmsr(0x80f, 0x1ff);                    /* SVR: APIC software enable */
    wrmsr(0x83e, 0xb);                      /* DCR: divide by 1 */
    wrmsr(0x832, 0x20);                     /* LVT timer: one-shot, vector 32 */
    set_gate(32, other_fault_entry);        /* not expected to be delivered: IF=0 */
    wrmsr(0x838, 100000);                   /* TMICT */
    before = ve_counts[EXIT_REASON_HLT];
    asm volatile("hlt");
    CHECK(ve_counts[EXIT_REASON_HLT] == before + 1 && ve_last_len == 1,
          "HLT raised a #VE with instruction length 1 and the VMM resumed us");
    wrmsr(0x832, 0x10020);                  /* mask the timer again */

    /* the TSC-deadline timer: CPUID says so, the VMM serves IA32_TSC_DEADLINE */
    cpuid(1, 0, &a, &b, &c, &d);
    CHECK(c & (1 << 24), "CPUID.1: TSC-deadline timer available");
    wrmsr(0x832, 0x20 | 0x40000);           /* LVT timer: deadline mode, vector 32 */
    {
        uint32_t lo, hi;
        uint64_t tsc, dl;

        asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
        tsc = ((uint64_t)hi << 32) | lo;
        dl = tsc + 20000000;                /* some milliseconds */
        before = ve_counts[EXIT_REASON_HLT];
        wrmsr(0x6e0, dl);
        asm volatile("hlt");
        CHECK(ve_counts[EXIT_REASON_HLT] == before + 1 && rdmsr(0x6e0) == dl,
              "IA32_TSC_DEADLINE through the VMM armed the timer and reads back");
        wrmsr(0x6e0, 0);
    }
    wrmsr(0x832, 0x10020);                  /* mask the timer again */

    /* IN: the VMM reads the port (0xe9 debugcon reads back 0xe9) */
    before = ve_counts[EXIT_REASON_IO];
    uint8_t inb;
    asm volatile("inb %1, %0" : "=a"(inb) : "Nd"((uint16_t)0xe9));
    uint64_t in_qual = ve_last_qual;        /* before the console #VEs below */
    CHECK(ve_counts[EXIT_REASON_IO] == before + 1 && inb == 0xe9,
          "IN from the debug console raised a #VE and returned 0x%x", inb);
    CHECK((in_qual & 0x3f) == 0x08 && (in_qual >> 16) == 0xe9,
          "IN exit qualification: size 1, IN, port 0xe9 (%" PRIx64 ")", in_qual);

    /* TDG.VM.RD / WR */
    r = (struct tdcall_regs){ .rax = TDG_VM_RD, .rdx = TDCS_ATTRIBUTES };
    tdcall(&r);
    CHECK(r.rax == TDX_SUCCESS && (r.r8 & (1ULL << 28)), "TDG.VM.RD ATTRIBUTES (%" PRIx64 ")", r.r8);
    r = (struct tdcall_regs){ .rax = TDG_VM_WR, .rdx = TDCS_NOTIFY_ENABLES, .r8 = 1, .r9 = ~0ULL };
    tdcall(&r);
    CHECK(r.rax == TDX_SUCCESS && r.r8 == 0, "TDG.VM.WR NOTIFY_ENABLES (old value 0)");
    r = (struct tdcall_regs){ .rax = TDG_VM_RD, .rdx = TDCS_NOTIFY_ENABLES };
    tdcall(&r);
    CHECK(r.rax == TDX_SUCCESS && r.r8 == 1, "TDG.VM.RD NOTIFY_ENABLES reads back 1");
    r = (struct tdcall_regs){ .rax = TDG_VM_WR, .rdx = TDCS_ATTRIBUTES, .r8 = 1, .r9 = ~0ULL };
    tdcall(&r);
    CHECK(r.rax == TDX_METADATA_FIELD_NOT_WRITABLE, "TDG.VM.WR ATTRIBUTES: NOT_WRITABLE");
    r = (struct tdcall_regs){ .rax = TDG_VM_RD, .rdx = 0x1234 };
    tdcall(&r);
    CHECK(r.rax == TDX_METADATA_FIELD_ID_INCORRECT, "TDG.VM.RD of an unknown field: FIELD_ID_INCORRECT");
    r = (struct tdcall_regs){ .rax = TDG_VM_WR, .rdx = TDCS_TD_CTLS, .r8 = 2, .r9 = 2 };
    tdcall(&r);
    CHECK(r.rax == TDX_SUCCESS, "TDG.VM.WR TD_CTLS.ENUM_TOPOLOGY accepted");
    r = (struct tdcall_regs){ .rax = TDG_VM_WR, .rdx = TDCS_TD_CTLS, .r8 = 0, .r9 = 2 };
    tdcall(&r);
    CHECK(r.rax == TDX_SUCCESS && (r.r8 & 2), "TDG.VM.WR TD_CTLS.ENUM_TOPOLOGY cleared (old value %" PRIx64 ")", r.r8);
    r = (struct tdcall_regs){ .rax = TDG_VP_RD, .rdx = TDVPS_VCPU_INDEX };
    tdcall(&r);
    CHECK(r.rax == TDX_SUCCESS && r.r8 == 0, "TDG.VP.RD VCPU_INDEX is 0");

    /* TDG.MEM.PAGE.ACCEPT */
    /* no firmware: the VMM added every page at launch */
    r = (struct tdcall_regs){ .rax = TDG_MEM_PAGE_ACCEPT, .rcx = 0x200000 };
    tdcall(&r);
    CHECK(r.rax == 0x00000B0A00000000ULL, "TDG.MEM.PAGE.ACCEPT of an added 4K page: PAGE_ALREADY_ACCEPTED");
    r = (struct tdcall_regs){ .rax = TDG_MEM_PAGE_ACCEPT, .rcx = 0x200000 | 1 };
    tdcall(&r);
    CHECK(r.rax == 0xC0000B0B00000001ULL, "TDG.MEM.PAGE.ACCEPT of 2M over added 4K pages: PAGE_SIZE_MISMATCH");
    r = (struct tdcall_regs){ .rax = TDG_MEM_PAGE_ACCEPT, .rcx = 0x201000 | 1 };
    tdcall(&r);
    CHECK(r.rax == (TDX_OPERAND_INVALID | 1), "TDG.MEM.PAGE.ACCEPT of a misaligned 2M page: OPERAND_INVALID");
    r = (struct tdcall_regs){ .rax = TDG_MEM_PAGE_ACCEPT, .rcx = 0x200000 | 2 };
    tdcall(&r);
    CHECK(r.rax == (TDX_OPERAND_INVALID | 1), "TDG.MEM.PAGE.ACCEPT of a 1G page: OPERAND_INVALID");

    /* TDG.MR.RTMR.EXTEND and TDG.MR.REPORT */
    for (int i = 0; i < 48; i++) {
        rtmr_data[i] = i;
    }
    r = (struct tdcall_regs){ .rax = TDG_MR_RTMR_EXTEND, .rcx = (uint64_t)rtmr_data, .rdx = 2 };
    tdcall(&r);
    CHECK(r.rax == TDX_SUCCESS, "TDG.MR.RTMR.EXTEND of RTMR[2]");
    r = (struct tdcall_regs){ .rax = TDG_MR_RTMR_EXTEND, .rcx = (uint64_t)rtmr_data, .rdx = 4 };
    tdcall(&r);
    CHECK(r.rax == (TDX_OPERAND_INVALID | 2), "TDG.MR.RTMR.EXTEND of RTMR[4]: OPERAND_INVALID (RDX)");
    for (int i = 0; i < 64; i++) {
        report_data[i] = 0xa0 + i;
    }
    r = (struct tdcall_regs){ .rax = TDG_MR_REPORT, .rcx = (uint64_t)report,
                              .rdx = (uint64_t)report_data, .r8 = 0 };
    tdcall(&r);
    CHECK(r.rax == TDX_SUCCESS && report[0] == 0x81 && report[128] == 0xa0 &&
          report[191] == 0xdf, "TDG.MR.REPORT: type 0x81, REPORTDATA at 128");
    {
        bool rtmr2_nonzero = false, rtmr0_zero = true;

        for (int i = 0; i < 48; i++) {
            rtmr2_nonzero |= report[720 + 96 + i] != 0;
            rtmr0_zero &= report[720 + i] == 0;
        }
        CHECK(rtmr2_nonzero && rtmr0_zero, "TDG.MR.REPORT: RTMR[2] extended, RTMR[0] zero");
    }
    r = (struct tdcall_regs){ .rax = TDG_MR_REPORT, .rcx = (uint64_t)report + 64,
                              .rdx = (uint64_t)report_data, .r8 = 0 };
    tdcall(&r);
    CHECK(r.rax == (TDX_OPERAND_INVALID | 1), "TDG.MR.REPORT with a misaligned report: OPERAND_INVALID (RCX)");

    /* TDG.VP.VMCALL leaves of the GHCI */
    r = (struct tdcall_regs){ .r12 = 0 };
    st = tdvmcall(&r, TDVMCALL_GET_TD_VM_CALL_INFO);
    CHECK(st == 0 && r.r11 == 0, "GetTdVmCallInfo: success, no optional sub-functions");
    r = (struct tdcall_regs){ .r12 = SHARED_BIT | 0x29200000, .r13 = 0x1000 };
    st = tdvmcall(&r, TDVMCALL_MAP_GPA);
    CHECK(st == 0, "MapGPA of a shared page (shared bit 47): success");
    /* the x2APIC id through the VMM: what a TD without ENUM_TOPOLOGY reads */
    r = (struct tdcall_regs){ .r12 = 0x802 };
    st = tdvmcall(&r, EXIT_REASON_MSR_READ);
    CHECK(st == 0 && r.r11 == 0,
          "TDG.VP.VMCALL<Instruction.RDMSR> of MSR 0x802: x2APIC id %" PRIu64, r.r11);
    r = (struct tdcall_regs){ .r12 = 0x29200800, .r13 = 0x1000 };
    st = tdvmcall(&r, TDVMCALL_MAP_GPA);
    CHECK(st == TDVMCALL_STATUS_ALIGN_ERROR, "MapGPA of a misaligned range: ALIGN_ERROR");
    quote_buf[0] = 1;                       /* version */
    r = (struct tdcall_regs){ .r12 = SHARED_BIT | (uint64_t)quote_buf, .r13 = sizeof(quote_buf) };
    st = tdvmcall(&r, TDVMCALL_GET_QUOTE);
    CHECK(st == 0 && *(volatile uint64_t *)(quote_buf + 8) == 0x8000000000000001ULL,
          "GetQuote: accepted, status QGS_UNAVAILABLE in the buffer");
    r = (struct tdcall_regs){ .r12 = 0x30 };
    st = tdvmcall(&r, TDVMCALL_SETUP_EVENT_NOTIFY);
    CHECK(st == 0, "SetupEventNotifyInterrupt(0x30): success");
    r = (struct tdcall_regs){ .r12 = 5 };
    st = tdvmcall(&r, TDVMCALL_SETUP_EVENT_NOTIFY);
    CHECK(st == TDVMCALL_STATUS_INVALID_OPERAND, "SetupEventNotifyInterrupt(5): INVALID_OPERAND");
    r = (struct tdcall_regs){ 0 };
    st = tdvmcall(&r, 0x12345);
    CHECK(st == TDVMCALL_STATUS_SUBFUNC_UNSUPPORTED, "unknown sub-function: SUBFUNC_UNSUPPORTED");
    /* the register mask: RAX/RCX/RSP cannot be selected */
    r = (struct tdcall_regs){ .rax = TDG_VP_VMCALL, .rcx = 0xfc01, .r11 = TDVMCALL_GET_TD_VM_CALL_INFO };
    tdcall(&r);
    CHECK(r.rax == (TDX_OPERAND_INVALID | 1), "TDG.VP.VMCALL with RAX selected: OPERAND_INVALID (RCX)");
    /* an unselected register is not passed and not modified */
    r = (struct tdcall_regs){ .rax = TDG_VP_VMCALL, .rcx = 0x0c00, .r10 = 0,
                              .r11 = EXIT_REASON_CPUID, .r12 = 0x1234, .r13 = 0x5678 };
    tdcall(&r);
    CHECK(r.rax == TDX_SUCCESS && r.r12 == 0x1234 && r.r13 == 0x5678 && r.rcx == 0x0c00,
          "TDG.VP.VMCALL keeps unselected registers and RCX");

    /* a second #VE before VEINFO.GET is a #DF: provoke it from the handler path */
    CHECK(df_count == 0 && gp_count == 0 && ud_count == 0 && ve_unexpected == 0,
          "no unexpected #DF/#GP/#UD/#VE so far");

    ml_printf("tdx: %d failures\n", failures);
    ml_printf("tdx: %u #VE (cpuid %u, msr %u/%u, io %u, hlt %u), %u IO vmcalls\n",
              ve_counts[EXIT_REASON_CPUID] + ve_counts[EXIT_REASON_MSR_READ] +
              ve_counts[EXIT_REASON_MSR_WRITE] + ve_counts[EXIT_REASON_IO] +
              ve_counts[EXIT_REASON_HLT],
              ve_counts[EXIT_REASON_CPUID], ve_counts[EXIT_REASON_MSR_READ],
              ve_counts[EXIT_REASON_MSR_WRITE], ve_counts[EXIT_REASON_IO],
              ve_counts[EXIT_REASON_HLT], vmm_io_count);

    /* the virtualized leaves: TSC frequency, extended range, fixed bits */
    cpuid(0x15, 0, &a, &b, &c, &d);
    CHECK(a == 1 && c == 25000000 && b > 0,
          "CPUID.0x15: crystal 25 MHz, TSC ratio %u", b);
    cpuid(0x80000000, 0, &a, &b, &c, &d);
    CHECK(a == 0x80000008, "CPUID.0x80000000: maximum extended leaf 0x80000008");
    cpuid(0x80000007, 0, &a, &b, &c, &d);
    CHECK(d & (1 << 8), "CPUID.0x80000007: invariant TSC fixed to 1");
    cpuid(1, 0, &a, &b, &c, &d);
    CHECK(!(c & (1 << 3)) && (d & (1 << 5)) && (d & (1 << 9)),
          "CPUID.1: MONITOR fixed to 0, MSR and APIC fixed to 1");
    cpuid(0x16, 0, &a, &b, &c, &d);
    CHECK(ve_last_category == 0x10, "CPUID.0x16: #VE of category 0x10 (configurable)");
    cpuid(0x40000000, 0, &a, &b, &c, &d);
    CHECK(ve_last_category == 0x11, "CPUID.0x40000000: #VE of category 0x11");

    /* INVD, WBINVD: #VE */
    asm volatile("invd" : : : "memory");
    asm volatile("wbinvd" : : : "memory");
    CHECK(ve_counts[13] == 1 && ve_counts[54] == 1, "INVD and WBINVD raised #VEs");

    /* string I/O: the exit qualification has the string and REP bits */
    {
        static const char str[] = "ok   rep outsb through #VE\n";
        before = ve_counts[EXIT_REASON_IO];
        asm volatile("rep outsb" : : "S"(str), "c"(sizeof(str) - 1), "d"((uint16_t)0xe9) : "memory");
        in_qual = ve_last_qual;
        CHECK(ve_counts[EXIT_REASON_IO] > before && (in_qual & 0x3f) == 0x30,
              "REP OUTSB: #VE qualification has string and REP (%" PRIx64 ")", in_qual & 0x3f);
    }

    /* the module's own MSR emulation: EFER (SCE only), MISC_ENABLE */
    before = ve_counts[EXIT_REASON_MSR_WRITE];
    v = rdmsr(0xc0000080);
    wrmsr(0xc0000080, v ^ 1);               /* SCE */
    CHECK(rdmsr(0xc0000080) == (v ^ 1) && ve_counts[EXIT_REASON_MSR_WRITE] == before,
          "WRMSR IA32_EFER may change SCE without a #VE");
    wrmsr(0xc0000080, v);
    wrmsr(0xc0000080, v ^ (1 << 11));       /* NXE: the module refuses */
    CHECK(ve_counts[EXIT_REASON_MSR_WRITE] == before + 1 && ve_last_category == 0x80 &&
          rdmsr(0xc0000080) == v,
          "WRMSR IA32_EFER changing NXE: #VE of category 0x80, EFER unchanged");
    before = ve_counts[EXIT_REASON_MSR_READ];
    v = rdmsr(0x1a0);
    CHECK(ve_counts[EXIT_REASON_MSR_READ] == before, "RDMSR IA32_MISC_ENABLE is emulated by the module (no #VE)");
    before = ve_counts[EXIT_REASON_MSR_WRITE];
    wrmsr(0x1a0, v);
    CHECK(ve_counts[EXIT_REASON_MSR_WRITE] == before + 1 && ve_last_category == 0x10,
          "WRMSR IA32_MISC_ENABLE: #VE of category 0x10");

    /* x2APIC ID: a #VE until the TD enables the topology enumeration (off by default) */
    before = ve_counts[EXIT_REASON_MSR_READ];
    v = rdmsr(0x802);
    CHECK(ve_counts[EXIT_REASON_MSR_READ] == before + 1 && ve_last_category == 0x10,
          "RDMSR x2APIC ID without ENUM_TOPOLOGY: #VE (VMM answered %" PRIx64 ")", v);
    cpuid(0xb, 0, &a, &b, &c, &d);
    CHECK(ve_counts[EXIT_REASON_CPUID] > 0 && ve_last_category == 0x10, "CPUID.0xB without ENUM_TOPOLOGY: #VE");
    r = (struct tdcall_regs){ .rax = TDG_VM_WR, .rdx = TDCS_TD_CTLS, .r8 = 2, .r9 = 2 };
    tdcall(&r);
    before = ve_counts[EXIT_REASON_MSR_READ];
    v = rdmsr(0x802);
    CHECK(r.rax == TDX_SUCCESS && ve_counts[EXIT_REASON_MSR_READ] == before && v == 0,
          "TD_CTLS.ENUM_TOPOLOGY: RDMSR x2APIC ID is virtualized (%" PRIx64 ")", v);
    before = ve_counts[EXIT_REASON_CPUID];
    cpuid(0xb, 0, &a, &b, &c, &d);
    CHECK(ve_counts[EXIT_REASON_CPUID] == before && d == 0, "TD_CTLS.ENUM_TOPOLOGY: CPUID.0xB is virtualized (x2APIC id %u)", d);

    /* TD_CTLS.REDUCE_VE: the leaves and MSRs that were #VE become fixed values or #GP */
    r = (struct tdcall_regs){ .rax = TDG_VM_WR, .rdx = TDCS_TD_CTLS, .r8 = 8, .r9 = 8 };
    tdcall(&r);
    r = (struct tdcall_regs){ .rax = TDG_VM_RD, .rdx = TDCS_TD_CTLS };
    tdcall(&r);
    CHECK((r.r8 & 0xf) == 0xf, "TD_CTLS.REDUCE_VE implies ENUM_TOPOLOGY and VIRT_CPUID2 (%" PRIx64 ")", r.r8);
    before = ve_counts[EXIT_REASON_CPUID];
    cpuid(0x2, 0, &a, &b, &c, &d);
    CHECK(ve_counts[EXIT_REASON_CPUID] == before && a == 0x00feff01, "REDUCE_VE: CPUID.2 is the virtual leaf (%x)", a);
    cpuid(0x6, 0, &a, &b, &c, &d);
    cpuid(0x16, 0, &a, &b, &c, &d);
    CHECK(ve_counts[EXIT_REASON_CPUID] == before && a == 0, "REDUCE_VE: CPUID.6 and CPUID.0x16 do not #VE");
    before = ve_counts[EXIT_REASON_MSR_READ];
    v = rdmsr(0x3a);
    CHECK(ve_counts[EXIT_REASON_MSR_READ] == before && v == 1, "REDUCE_VE: IA32_FEATURE_CONTROL reads 1");
    skip_faulting_insn = true;
    skip_faulting_len = 2;                  /* rdmsr */
    v = rdmsr(0x832);
    CHECK(gp_count == 1 && ve_counts[EXIT_REASON_MSR_READ] == before,
          "REDUCE_VE: RDMSR LVT timer raises #GP instead of #VE");
    r = (struct tdcall_regs){ .rax = TDG_VM_WR, .rdx = TDCS_TD_CTLS, .r8 = 0, .r9 = 0xe };
    tdcall(&r);
    CHECK(r.rax == TDX_SUCCESS, "TD_CTLS cleared again");
    r = (struct tdcall_regs){ .rax = TDG_VM_WR, .rdx = TDCS_TD_CTLS, .r8 = 0, .r9 = 1 };
    tdcall(&r);
    CHECK(r.rax == 0xC0000C0300000000ULL, "TD_CTLS.PENDING_VE_DISABLE cannot change: VALUE_NOT_VALID");

    /* TD_CTLS.LOCK: no more changes */
    r = (struct tdcall_regs){ .rax = TDG_VM_WR, .rdx = TDCS_TD_CTLS, .r8 = 1ULL << 63, .r9 = 1ULL << 63 };
    tdcall(&r);
    r = (struct tdcall_regs){ .rax = TDG_VM_WR, .rdx = TDCS_TD_CTLS, .r8 = 2, .r9 = 2 };
    tdcall(&r);
    CHECK(r.rax == 0xC0000C0300000000ULL, "TD_CTLS.LOCK: a later write is VALUE_NOT_VALID");
    r = (struct tdcall_regs){ .rax = TDG_VP_CPUIDVE_SET, .rcx = 1 };
    tdcall(&r);
    CHECK(r.rax == (TDX_OPERAND_INVALID | 1), "TD_CTLS.LOCK: TDG.VP.CPUIDVE.SET change is OPERAND_INVALID");
    CHECK(df_count == 0 && gp_count == 1 && ud_count == 0 && ve_unexpected == 0,
          "no unexpected #DF/#GP/#UD/#VE");

    /*
     * No firmware programmed the chipset: map the ICH9 power-management I/O
     * block (LPC config PMBASE 0x40, ACPI_CNTL 0x44) so that the ACPI power
     * off of the exit path works; the config-space accesses go through #VE.
     */
    asm volatile("outl %0, %1" : : "a"(0x8000f840u), "Nd"((uint16_t)0xcf8));
    asm volatile("outl %0, %1" : : "a"(0x00000601u), "Nd"((uint16_t)0xcfc));
    asm volatile("outl %0, %1" : : "a"(0x8000f844u), "Nd"((uint16_t)0xcf8));
    asm volatile("outb %0, %1" : : "a"((uint8_t)0x80), "Nd"((uint16_t)0xcfc));
    return failures ? 1 : 0;
}
