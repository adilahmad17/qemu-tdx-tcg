/*
 * A payload for td-shim: the emulated TDX guest boots td-shim from its
 * firmware image, td-shim accepts the memory, builds the payload HOB and
 * calls this entry in 64-bit mode (RDI = payload HOB, RSI = load address),
 * as it calls Saguaro's TDX PAL. Like the PAL, the payload installs its own
 * IDT first (td-shim hands over with empty exception handlers), with a #VE
 * handler that forwards port I/O to the VMM through TDG.VP.VMCALL. It checks
 * the HOB (the CPU HOB with the address width, the E820 and ACPI GUID HOBs,
 * the MADT with the wakeup mailbox), prints on the serial port and exits
 * through the debug-exit port.
 *
 * Built as a position-independent ELF (td-shim relocates it) without boot.S
 * or minilib: everything it needs is here.
 *
 * Copyright (C) 2026 The ASTERISC Research Lab
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdint.h>
#include <stddef.h>

#define EFI_HOB_TYPE_HANDOFF            0x0001
#define EFI_HOB_TYPE_RESOURCE_DESCRIPTOR 0x0003
#define EFI_HOB_TYPE_GUID_EXTENSION     0x0004
#define EFI_HOB_TYPE_FV                 0x0005
#define EFI_HOB_TYPE_CPU                0x0006
#define EFI_HOB_TYPE_END_OF_HOB_LIST    0xffff

#define TDG_VP_VMCALL           0
#define TDG_VP_VEINFO_GET       3
#define EXIT_REASON_IO          30

struct hob_header {
    uint16_t type;
    uint16_t length;
    uint32_t reserved;
};

struct hob_cpu {
    struct hob_header hdr;
    uint8_t memory_space;
    uint8_t io_space;
    uint8_t reserved[6];
};

struct hob_guid {
    struct hob_header hdr;
    uint8_t guid[16];
    /* data follows */
};

/* td-shim's GUIDs (td-shim/src/lib.rs), in the binary EFI_GUID layout */
static const uint8_t acpi_table_guid[16] = {
    0x70, 0x58, 0x0c, 0x6a, 0xed, 0xd4, 0xf4, 0x44,
    0xa1, 0x35, 0xdd, 0x23, 0x8b, 0x6f, 0x0c, 0x8d
};
static const uint8_t e820_table_guid[16] = {
    0xea, 0x72, 0x80, 0x8f, 0x86, 0x34, 0x47, 0x4b,
    0x86, 0xa7, 0x23, 0x53, 0xb8, 0x8a, 0x87, 0x73
};

/* ---- TDCALL and the #VE handler ---- */

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

struct ve_regs {
    uint64_t r11, r10, r9, r8, rdi, rsi, rbp, rbx, rdx, rcx, rax;
    uint64_t rip, cs, rflags, rsp, ss;
};

void ve_handler_c(struct ve_regs *regs);

/* #VE: port I/O goes to the VMM; anything else stops here */
void ve_handler_c(struct ve_regs *regs)
{
    struct tdcall_regs r = { .rax = TDG_VP_VEINFO_GET };

    tdcall(&r);
    if (r.rax != 0 || (uint32_t)r.rcx != EXIT_REASON_IO) {
        for (;;) {
            asm volatile("pause");
        }
    }
    {
        uint64_t qual = r.rdx;
        unsigned size = (qual & 7) + 1;
        int in = qual & (1 << 3);
        struct tdcall_regs io = { .rax = TDG_VP_VMCALL, .rcx = 0xfc00,
                                  .r10 = 0, .r11 = EXIT_REASON_IO,
                                  .r12 = size, .r13 = in ? 0 : 1,
                                  .r14 = qual >> 16, .r15 = regs->rax };

        tdcall(&io);
        if (in) {
            regs->rax = (regs->rax & ~0xffULL) | (io.r11 & 0xff);
        }
    }
    regs->rip += (uint32_t)r.r10;
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
    asm volatile("1: pause\n jmp 1b\n");
}

struct idt_entry {
    uint16_t off0, sel;
    uint8_t ist, type;
    uint16_t off1;
    uint32_t off2, rsvd;
} __attribute__((packed));

static struct idt_entry idt[32] __attribute__((aligned(16)));

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
    idt[vec].rsvd = 0;
}

static void idt_init(void)
{
    struct { uint16_t limit; uint64_t base; } __attribute__((packed)) idtr = {
        sizeof(idt) - 1, (uint64_t)idt };

    for (int v = 0; v < 32; v++) {
        set_gate(v, fault_entry);
    }
    set_gate(20, ve_entry);
    asm volatile("lidt %0" : : "m"(idtr));
}

/* ---- console and checks ---- */

static void outb(uint16_t port, uint8_t val)
{
    asm volatile("outb %0, %1" : : "a"(val), "Nd"(port));
}

static void puts(const char *s)
{
    while (*s) {
        outb(0x3f8, *s++);
    }
}

static void puthex(uint64_t v)
{
    static const char digits[] = "0123456789abcdef";
    char buf[17];
    int i = 16;

    buf[i] = 0;
    do {
        buf[--i] = digits[v & 15];
        v >>= 4;
    } while (v && i > 0);
    puts(buf + i);
}

static int failures;

static void check(int cond, const char *what)
{
    puts(cond ? "ok   " : "FAIL ");
    puts(what);
    puts("\n");
    if (!cond) {
        failures++;
    }
}

static int guid_equal(const uint8_t *a, const uint8_t *b)
{
    for (int i = 0; i < 16; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

static uint64_t rdmsr(uint32_t msr)
{
    uint32_t lo, hi;

    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

void _start(void *hob_list, void *load_base);

void _start(void *hob_list, void *load_base)
{
    const struct hob_header *hob = hob_list;
    unsigned cpu_bits = 0, e820_entries = 0, resources = 0;
    int have_madt = 0, have_wakeup = 0, have_fv = 0;
    uint64_t mailbox = 0;
    uint64_t efer, cr0, cr4;

    idt_init();
    puts("tdx-payload: td-shim handed over to the payload\n");
    puts("tdx-payload: hob "); puthex((uint64_t)hob_list);
    puts(" base "); puthex((uint64_t)load_base); puts("\n");

    asm volatile("mov %%cr0, %0" : "=r"(cr0));
    asm volatile("mov %%cr4, %0" : "=r"(cr4));
    efer = rdmsr(0xc0000080);
    check((cr0 & 0x80000001) == 0x80000001 && (efer & 0x500) == 0x500,
          "64-bit mode with paging (CR0.PG, EFER.LME and LMA)");

    check(hob->type == EFI_HOB_TYPE_HANDOFF,
          "the payload HOB starts with the handoff table");
    for (; hob->type != EFI_HOB_TYPE_END_OF_HOB_LIST && hob->length >= 8;
         hob = (const void *)((const uint8_t *)hob + hob->length)) {
        if (hob->type == EFI_HOB_TYPE_CPU) {
            cpu_bits = ((const struct hob_cpu *)hob)->memory_space;
        } else if (hob->type == EFI_HOB_TYPE_FV) {
            have_fv = 1;
        } else if (hob->type == EFI_HOB_TYPE_RESOURCE_DESCRIPTOR) {
            resources++;
        } else if (hob->type == EFI_HOB_TYPE_GUID_EXTENSION) {
            const struct hob_guid *g = (const void *)hob;
            const uint8_t *data = (const uint8_t *)(g + 1);
            unsigned len = hob->length - sizeof(*g);

            if (guid_equal(g->guid, e820_table_guid)) {
                e820_entries = len / 20;
            } else if (guid_equal(g->guid, acpi_table_guid) && len >= 44 &&
                       data[0] == 'A' && data[1] == 'P' && data[2] == 'I' &&
                       data[3] == 'C') {
                uint32_t tlen = *(const uint32_t *)(data + 4);
                unsigned off = 44;

                have_madt = 1;
                while (off + 2 <= tlen && off + 2 <= len) {
                    uint8_t etype = data[off], elen = data[off + 1];

                    if (etype == 0x10 && elen == 16) {   /* MP wakeup */
                        have_wakeup = 1;
                        mailbox = *(const uint64_t *)(data + off + 8);
                    }
                    if (elen < 2) {
                        break;
                    }
                    off += elen;
                }
            }
        }
    }
    check(hob->type == EFI_HOB_TYPE_END_OF_HOB_LIST,
          "the HOB list ends with END_OF_HOB_LIST");
    puts("tdx-payload: CPU HOB address width "); puthex(cpu_bits); puts("\n");
    check(cpu_bits == 48 || cpu_bits == 52, "CPU HOB: memory space 48 or 52 bits");
    check(have_fv, "FV HOB of the payload volume");
    puts("tdx-payload: E820 entries "); puthex(e820_entries); puts("\n");
    check(e820_entries >= 2, "E820 GUID HOB with entries");
    check(have_madt, "ACPI GUID HOB with the MADT");
    puts("tdx-payload: MP wakeup mailbox "); puthex(mailbox); puts("\n");
    check(have_wakeup && mailbox != 0 && (mailbox & 0xfff) == 0,
          "MADT multiprocessor wakeup structure with a page-aligned mailbox");

    /* the mailbox: td-shim's AP loop left the command word idle */
    if (mailbox) {
        volatile uint16_t *command = (volatile uint16_t *)mailbox;

        check(*command == 0, "mailbox command is NOOP");
    }

    puts(failures ? "tdx-payload: FAILED\n" : "tdx-payload: all checks passed\n");
    if (failures) {
        outb(0xf4, 1);                  /* debug-exit: status 3 */
    }
    /*
     * Success: power off through the chipset, as the test harness expects.
     * No firmware programmed it: map the ICH9 power-management I/O block
     * (LPC config PMBASE 0x40, ACPI_CNTL 0x44) and set SLP_TYP/SLP_EN.
     */
    asm volatile("outl %0, %1" : : "a"(0x8000f840u), "Nd"((uint16_t)0xcf8));
    asm volatile("outl %0, %1" : : "a"(0x00000601u), "Nd"((uint16_t)0xcfc));
    asm volatile("outl %0, %1" : : "a"(0x8000f844u), "Nd"((uint16_t)0xcf8));
    outb(0xcfc, 0x80);
    asm volatile("outw %0, %1" : : "a"((uint16_t)0x2000), "Nd"((uint16_t)0x604));
    for (;;) {
        asm volatile("pause");
    }
}
