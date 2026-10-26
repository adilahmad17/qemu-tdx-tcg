/*
 * QEMU Intel TDX guest emulation for TCG (tdx-emu): the object, the CPUID
 * virtualization, the initial vCPU state, the page states and the launch
 * from the TD firmware
 *
 * Copyright (C) 2026 The ASTERISC Research Lab
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "qemu/error-report.h"
#include "qemu/timer.h"
#include "qemu/units.h"
#include "exec/target_page.h"
#include "qom/object_interfaces.h"
#include "system/tcg.h"
#include "system/system.h"
#include "system/address-spaces.h"
#include "system/memory.h"
#include "standard-headers/uefi/uefi.h"
#include "hw/i386/tdvf.h"
#include "hw/i386/pc.h"
#include "hw/i386/e820_memory_layout.h"
#include "cpu.h"
#include "hw/i386/apic.h"
#include "confidential-guest.h"
#include "tdx-emu.h"

TdxEmuState *tdx_emu_state;

/* the GUID of the TDVF metadata offset in the firmware's GUID table */
#define TDX_METADATA_OFFSET_GUID "e47a6535-984a-4798-865e-4685a7bf8ec2"

/*
 * The CPUID bits the TDX module fixes to 1 in every TD (the same list as the
 * KVM tdx-guest's tdx_fixed1_bits). Only the bits the CPU model and TCG
 * support are forced: a bit TCG cannot honour (XSAVEC, SHA-NI, ...) would
 * promise an instruction that raises #UD; the real platform forces them all.
 */
static const struct {
    FeatureWord w;
    uint32_t bits;
} tdx_emu_fixed1[] = {
    { FEAT_1_ECX, CPUID_EXT_SSE3 | CPUID_EXT_PCLMULQDQ | CPUID_EXT_DTES64 |
                  CPUID_EXT_DSCPL | CPUID_EXT_SSSE3 | CPUID_EXT_CX16 |
                  CPUID_EXT_PDCM | CPUID_EXT_PCID | CPUID_EXT_SSE41 |
                  CPUID_EXT_SSE42 | CPUID_EXT_X2APIC | CPUID_EXT_MOVBE |
                  CPUID_EXT_POPCNT | CPUID_EXT_AES | CPUID_EXT_XSAVE |
                  CPUID_EXT_RDRAND | CPUID_EXT_HYPERVISOR },
    { FEAT_1_EDX, CPUID_FP87 | CPUID_VME | CPUID_DE | CPUID_PSE | CPUID_TSC |
                  CPUID_MSR | CPUID_PAE | CPUID_MCE | CPUID_CX8 | CPUID_APIC |
                  CPUID_SEP | CPUID_MTRR | CPUID_PGE | CPUID_MCA | CPUID_CMOV |
                  CPUID_PAT | CPUID_CLFLUSH | CPUID_DTS | CPUID_MMX |
                  CPUID_FXSR | CPUID_SSE | CPUID_SSE2 },
    { FEAT_6_EAX, CPUID_6_EAX_ARAT },
    { FEAT_7_0_EBX, CPUID_7_0_EBX_FSGSBASE | CPUID_7_0_EBX_FDP_EXCPTN_ONLY |
                    CPUID_7_0_EBX_SMEP | CPUID_7_0_EBX_INVPCID |
                    CPUID_7_0_EBX_ZERO_FCS_FDS | CPUID_7_0_EBX_RDSEED |
                    CPUID_7_0_EBX_SMAP | CPUID_7_0_EBX_CLFLUSHOPT |
                    CPUID_7_0_EBX_CLWB | CPUID_7_0_EBX_SHA_NI },
    { FEAT_7_0_ECX, CPUID_7_0_ECX_BUS_LOCK_DETECT | CPUID_7_0_ECX_MOVDIRI |
                    CPUID_7_0_ECX_MOVDIR64B },
    { FEAT_7_0_EDX, CPUID_7_0_EDX_MD_CLEAR | CPUID_7_0_EDX_SPEC_CTRL |
                    CPUID_7_0_EDX_STIBP | CPUID_7_0_EDX_FLUSH_L1D |
                    CPUID_7_0_EDX_ARCH_CAPABILITIES |
                    CPUID_7_0_EDX_CORE_CAPABILITY |
                    CPUID_7_0_EDX_SPEC_CTRL_SSBD },
    { FEAT_7_2_EDX, CPUID_7_2_EDX_PSFD | CPUID_7_2_EDX_IPRED_CTRL |
                    CPUID_7_2_EDX_RRSBA_CTRL | CPUID_7_2_EDX_BHI_CTRL },
    { FEAT_XSAVE_XCR0_LO, XSTATE_FP_MASK | XSTATE_SSE_MASK },
    { FEAT_XSAVE, CPUID_XSAVE_XSAVEOPT | CPUID_XSAVE_XSAVEC |
                  CPUID_XSAVE_XGETBV1 | CPUID_XSAVE_XSAVES },
    { FEAT_8000_0001_ECX, CPUID_EXT3_LAHF_LM | CPUID_EXT3_ABM |
                          CPUID_EXT3_3DNOWPREFETCH },
    { FEAT_8000_0001_EDX, CPUID_EXT2_SYSCALL | CPUID_EXT2_NX |
                          CPUID_EXT2_PDPE1GB | CPUID_EXT2_RDTSCP |
                          CPUID_EXT2_LM },
    { FEAT_8000_0007_EDX, CPUID_APM_INVTSC },
};

static uint32_t tdx_emu_fixed1_bits(X86CPU *cpu, FeatureWord w)
{
    for (int i = 0; i < ARRAY_SIZE(tdx_emu_fixed1); i++) {
        if (tdx_emu_fixed1[i].w == w) {
            uint32_t supported = x86_cpu_get_supported_feature_word(cpu, w);

            if (w == FEAT_8000_0007_EDX) {
                /* a flag, not an instruction: TCG's TSC is invariant too */
                supported |= CPUID_APM_INVTSC;
            }
            return tdx_emu_fixed1[i].bits & supported;
        }
    }
    return 0;
}

/* CPUID leaves the module fixes to zero (the fixed-0 bitmap of the tables) */
static bool tdx_emu_cpuid_fixed0(uint32_t index)
{
    switch (index) {
    case 0x3: case 0x8: case 0x9: case 0xc: case 0xe: case 0xf: case 0x10:
    case 0x11: case 0x12: case 0x13: case 0x16: case 0x17: case 0x1b:
    case 0x20: case 0x22:
    case 0x80000003: case 0x80000004: case 0x80000005:
        return true;
    default:
        return false;
    }
}

/*
 * The TDX module's CPUID virtualization (TDX Module ABI, "CPUID
 * virtualization"; the values of the module's tables): the maximum basic leaf
 * is 0x23, leaf 0x21 enumerates TDX, the fixed bits, leaf 0x15 carries the
 * TSC frequency, and TD_CTLS selects what the leaves that otherwise raise #VE
 * return. Runs on the leaf the guest asked for, after the CPU model's values.
 */
void tdx_emu_cpuid(CPUX86State *env, uint32_t index, uint32_t count,
                   uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
    X86CPU *cpu = env_archcpu(env);
    uint64_t td_ctls = tdx_emu_td_ctls();
    uint32_t level = env->cpuid_level;

    if (index > level && index > 0x23 && index < 0x40000000) {
        /* an invalid basic leaf returns the highest basic leaf, 0x23 */
        index = 0x23;
    }
    if (tdx_emu_cpuid_fixed0(index)) {
        *eax = *ebx = *ecx = *edx = 0;
        return;
    }
    switch (index) {
    case 0:
        if (*eax < 0x23) {
            *eax = 0x23;
        }
        break;
    case 1:
        *ecx |= tdx_emu_fixed1_bits(cpu, FEAT_1_ECX);
        *edx |= tdx_emu_fixed1_bits(cpu, FEAT_1_EDX);
        *ecx &= ~CPUID_EXT_MONITOR;         /* fixed 0: MONITOR/MWAIT #UD */
        break;
    case 2:
        if (td_ctls & TDX_TD_CTLS_VIRT_CPUID2) {
            *eax = 0x00feff01;              /* the module's virtual leaf 2 */
            *ebx = *ecx = *edx = 0;
        }
        break;
    case 6:
        *eax = (td_ctls & TDX_TD_CTLS_REDUCE_VE) ? CPUID_6_EAX_ARAT : 0;
        *ebx = *ecx = *edx = 0;
        break;
    case 7:
        if (count == 0) {
            *ebx |= tdx_emu_fixed1_bits(cpu, FEAT_7_0_EBX);
            *ecx |= tdx_emu_fixed1_bits(cpu, FEAT_7_0_ECX);
            *edx |= tdx_emu_fixed1_bits(cpu, FEAT_7_0_EDX);
        } else if (count == 2) {
            *edx |= tdx_emu_fixed1_bits(cpu, FEAT_7_2_EDX);
        } else if (count >= 3) {
            *eax = *ebx = *ecx = *edx = 0;
        }
        break;
    case 0xd:
        if (count == 0) {
            *eax |= tdx_emu_fixed1_bits(cpu, FEAT_XSAVE_XCR0_LO);
        } else if (count == 1) {
            *eax |= tdx_emu_fixed1_bits(cpu, FEAT_XSAVE);
        }
        break;
    case 0x15:
        /*
         * Time stamp counter and core crystal clock: the module reports a
         * 25 MHz crystal and the TD's TSC frequency as the ratio.
         */
        *eax = 1;
        *ebx = tdx_emu_state->tsc_khz / 25000;
        *ecx = 25000000;
        *edx = 0;
        break;
    case 0x4:
        if (count >= 5) {
            *eax = *ebx = *ecx = *edx = 0;
        }
        break;
    case 0x23:
        if (index > level) {
            *eax = *ebx = *ecx = *edx = 0;
        }
        break;
    case 0x21:
        /* "IntelTDX    " in EBX, EDX, ECX; EAX = maximum subleaf (0) */
        *eax = 0;
        if (count == 0) {
            *ebx = 0x65746e49;  /* "Inte" */
            *edx = 0x5844546c;  /* "lTDX" */
            *ecx = 0x20202020;  /* "    " */
        } else {
            *ebx = *ecx = *edx = 0;
        }
        break;
    case 0x80000000:
        *eax = 0x80000008;
        *ebx = *ecx = *edx = 0;
        break;
    case 0x80000001:
        *ecx |= tdx_emu_fixed1_bits(cpu, FEAT_8000_0001_ECX);
        *edx |= tdx_emu_fixed1_bits(cpu, FEAT_8000_0001_EDX);
        if (!(env->hflags & HF_CS64_MASK)) {
            *edx &= ~CPUID_EXT2_SYSCALL;    /* reported only in 64-bit mode */
        }
        break;
    case 0x80000002:
        /* with REDUCE_VE the brand string is "Intel TDX" (else a #VE) */
        *eax = 0x65746e49;
        *ebx = 0x4454206c;
        *ecx = 0x20202058;
        *edx = 0;
        break;
    case 0x80000006:
        *eax = *ebx = *edx = 0;
        *ecx = 0x7040;                  /* 64-byte lines, L2 size per leaf 4 */
        break;
    case 0x80000007:
        *edx |= tdx_emu_fixed1_bits(cpu, FEAT_8000_0007_EDX);
        break;
    default:
        break;
    }
    if (index > 0x80000008 && index >= 0x80000000) {
        *eax = *ebx = *ecx = *edx = 0;
    }
}

/*
 * The state TDH.VP.INIT gives every vCPU (TDX Module ABI, "Initial state of a
 * VCPU"): 32-bit flat protected mode at the reset vector 0xFFFFFFF0 with
 * paging off, EFER.LME already set, RBX = GPAW, RSI = vCPU index, RDX =
 * CPUID(1).EAX, RCX = R8 = the VMM's TDH.VP.INIT value (0 here).
 */
void tdx_emu_cpu_reset(X86CPU *cpu)
{
    CPUX86State *env = &cpu->env;
    uint32_t eax, ebx, ecx, edx;

    cpu_x86_update_cr0(env, CR0_PE_MASK | CR0_NE_MASK);
    cpu_x86_update_cr4(env, CR4_MCE_MASK);
    cpu_load_efer(env, MSR_EFER_SCE | MSR_EFER_LME | MSR_EFER_NXE);
    cpu_x86_load_seg_cache(env, R_CS, 0, 0, 0xffffffff,
                           DESC_G_MASK | DESC_B_MASK | DESC_P_MASK |
                           DESC_S_MASK | DESC_CS_MASK | DESC_R_MASK |
                           DESC_A_MASK);
    for (int seg = 0; seg < 6; seg++) {
        if (seg != R_CS) {
            cpu_x86_load_seg_cache(env, seg, 0, 0, 0xffffffff,
                                   DESC_G_MASK | DESC_B_MASK | DESC_P_MASK |
                                   DESC_S_MASK | DESC_W_MASK | DESC_A_MASK);
        }
    }
    env->eip = 0xfffffff0;
    env->eflags = 0x2;
    env->pat = 0x0007040600070406ULL;
    env->tdx_ve.valid = false;
    cpu_x86_cpuid(env, 1, 0, &eax, &ebx, &ecx, &edx);
    env->regs[R_EBX] = tdx_emu_state->gpaw;
    env->regs[R_ECX] = 0;
    env->regs[R_EDX] = eax;
    env->regs[R_ESI] = CPU(cpu)->cpu_index;
    env->regs[R_R8] = 0;
}

void tdx_emu_apic_reset(X86CPU *cpu)
{
    uint64_t base = cpu_get_apic_base(cpu->apic_state);

    cpu_set_apic_base(cpu->apic_state, base | MSR_IA32_APICBASE_ENABLE |
                      MSR_IA32_APICBASE_EXTD);
}

/* ---- page states, firmware and launch ---- */

uint8_t tdx_emu_page_state(hwaddr gpa)
{
    TdxEmuState *tdx = tdx_emu_state;

    if (!tdx->pages || gpa >= tdx->pages_end) {
        /* nothing describes it: as memory the VMM added at launch */
        return TDX_PAGE_ACCEPTED;
    }
    return tdx->pages[gpa >> TARGET_PAGE_BITS];
}

void tdx_emu_set_page_state(hwaddr gpa, uint64_t len, uint8_t state)
{
    TdxEmuState *tdx = tdx_emu_state;
    uint64_t end = gpa + len;

    if (!tdx->pages) {
        return;
    }
    end = MIN(end, tdx->pages_end);
    for (hwaddr p = gpa; p < end; p += TARGET_PAGE_SIZE) {
        tdx->pages[p >> TARGET_PAGE_BITS] = state;
    }
}

/*
 * Guest RAM as the TD sees it: what the memory map (and so the TD HOB) calls
 * RAM, plus the firmware image. The address space may show something else at
 * a RAM address (the VGA window of the chipset over low RAM): on the real
 * platform the private memory behind it still exists, so it counts as RAM.
 */
bool tdx_emu_gpa_is_ram(hwaddr gpa)
{
    TdxEmuState *tdx = tdx_emu_state;
    MemoryRegion *mr;
    hwaddr xlat, len = TARGET_PAGE_SIZE;
    struct e820_entry *table;
    int n = e820_get_table(&table);

    if (tdx->fw_size && gpa >= tdx->fw_base &&
        gpa < tdx->fw_base + tdx->fw_size) {
        return true;
    }
    for (int i = 0; i < n; i++) {
        uint64_t start = le64_to_cpu(table[i].address);

        if (le32_to_cpu(table[i].type) == E820_RAM && gpa >= start &&
            gpa < start + le64_to_cpu(table[i].length)) {
            return true;
        }
    }
    RCU_READ_LOCK_GUARD();
    mr = address_space_translate(&address_space_memory, gpa, &xlat, &len,
                                 false, MEMTXATTRS_UNSPECIFIED);
    return memory_region_is_ram(mr);
}

G_NORETURN void tdx_emu_stop(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    error_vreport(fmt, ap);
    va_end(ap);
    error_report("tdx-emu: the TD did what a real TDX module or VMM would "
                 "not survive; stopping (strict=off continues)");
    exit(1);
}

/*
 * The TD firmware was loaded with -bios into RAM below 4 GiB: keep its TDVF
 * metadata (td-shim and TDVF carry one) for the launch.
 */
void tdx_emu_set_firmware(hwaddr base, void *ptr, int size)
{
    TdxEmuState *tdx = tdx_emu_state;
    TdxFirmware *fw = g_new0(TdxFirmware, 1);

    tdx->fw_base = base;
    tdx->fw_size = size;
    if (!pc_system_ovmf_table_find(TDX_METADATA_OFFSET_GUID, NULL, NULL) ||
        tdvf_parse_metadata(fw, ptr, size) < 0) {
        warn_report("tdx-emu: the firmware has no TDVF metadata: all memory "
                    "is treated as added at launch");
        g_free(fw);
        return;
    }
    fw->mem_ptr = ptr;
    tdx->fw = fw;
}

/*
 * The TD HOB the VMM hands to the firmware: the handoff table, one resource
 * descriptor per range of guest RAM (unaccepted, except the ranges the launch
 * adds: the HOB itself and the temporary memory) and the end marker; what
 * td-shim and TDVF expect from KVM's QEMU.
 */
static void tdx_emu_hob_add(GByteArray *hob, const void *data, size_t len)
{
    g_byte_array_append(hob, data, len);
    while (hob->len & 7) {
        g_byte_array_append(hob, (const guint8 *)"", 1);
    }
}

static void tdx_emu_hob_resource(GByteArray *hob, uint64_t start, uint64_t len,
                                 uint32_t type)
{
    EFI_HOB_RESOURCE_DESCRIPTOR r = {
        .Header = { .HobType = EFI_HOB_TYPE_RESOURCE_DESCRIPTOR,
                    .HobLength = cpu_to_le16(sizeof(r)) },
        .Owner = EFI_HOB_OWNER_ZERO,
        .ResourceType = cpu_to_le32(type),
        .ResourceAttribute = cpu_to_le32(EFI_RESOURCE_ATTRIBUTE_PRESENT |
                                         EFI_RESOURCE_ATTRIBUTE_INITIALIZED |
                                         EFI_RESOURCE_ATTRIBUTE_TESTED),
        .PhysicalStart = cpu_to_le64(start),
        .ResourceLength = cpu_to_le64(len),
    };

    if (len) {
        tdx_emu_hob_add(hob, &r, sizeof(r));
    }
}

/* a RAM range of the e820 map, cut around the ranges added at launch */
static void tdx_emu_hob_ram(GByteArray *hob, TdxFirmware *fw, uint64_t start,
                            uint64_t end)
{
    TdxFirmwareEntry *e;
    uint64_t cut = end;
    TdxFirmwareEntry *first = NULL;

    /* the lowest added range inside [start, end) */
    for_each_tdx_fw_entry(fw, e) {
        if ((e->type == TDVF_SECTION_TYPE_TD_HOB ||
             e->type == TDVF_SECTION_TYPE_TEMP_MEM) &&
            e->address >= start && e->address < cut) {
            cut = e->address;
            first = e;
        }
    }
    if (!first) {
        tdx_emu_hob_resource(hob, start, end - start,
                             EFI_RESOURCE_MEMORY_UNACCEPTED);
        return;
    }
    tdx_emu_hob_resource(hob, start, cut - start,
                         EFI_RESOURCE_MEMORY_UNACCEPTED);
    tdx_emu_hob_resource(hob, first->address, MIN(first->size, end - cut),
                         EFI_RESOURCE_SYSTEM_MEMORY);
    if (first->address + first->size < end) {
        tdx_emu_hob_ram(hob, fw, first->address + first->size, end);
    }
}

static void tdx_emu_hob_create(TdxEmuState *tdx, TdxFirmwareEntry *td_hob)
{
    TdxFirmware *fw = tdx->fw;
    g_autoptr(GByteArray) hob = g_byte_array_new();
    EFI_HOB_HANDOFF_INFO_TABLE hit = {
        .Header = { .HobType = EFI_HOB_TYPE_HANDOFF,
                    .HobLength = cpu_to_le16(sizeof(hit)) },
        .Version = cpu_to_le32(EFI_HOB_HANDOFF_TABLE_VERSION),
    };
    EFI_HOB_GENERIC_HEADER end = {
        .HobType = EFI_HOB_TYPE_END_OF_HOB_LIST,
        .HobLength = cpu_to_le16(sizeof(end)),
    };
    struct e820_entry *table;
    int n = e820_get_table(&table);

    tdx_emu_hob_add(hob, &hit, sizeof(hit));
    for (int i = 0; i < n; i++) {
        uint64_t start = le64_to_cpu(table[i].address);
        uint64_t len = le64_to_cpu(table[i].length);

        if (le32_to_cpu(table[i].type) != E820_RAM) {
            continue;
        }
        tdx_emu_hob_ram(hob, fw, start, start + len);
    }
    tdx_emu_hob_add(hob, &end, sizeof(end));
    hit.EfiEndOfHobList = cpu_to_le64(td_hob->address + hob->len);
    memcpy(hob->data, &hit, sizeof(hit));
    if (hob->len > td_hob->size) {
        error_report("tdx-emu: the TD HOB (%u bytes) does not fit its section"
                     " (%" PRIu64 " bytes)", hob->len, td_hob->size);
        exit(1);
    }
    address_space_write(&address_space_memory, td_hob->address,
                        MEMTXATTRS_UNSPECIFIED, hob->data, hob->len);
}

/*
 * The launch (TDH.MEM.PAGE.ADD of the firmware sections, TDH.MR.FINALIZE):
 * every page of RAM is private and pending until the TD accepts it, except
 * the firmware image, the TD HOB and the temporary memory, which the VMM adds;
 * the temporary memory is zeroed, the HOB written. Without TDVF metadata
 * every page is treated as added.
 */
static void tdx_emu_init_done(Notifier *notifier, void *unused)
{
    TdxEmuState *tdx = container_of(notifier, TdxEmuState, init_done);
    TdxFirmware *fw = tdx->fw;
    TdxFirmwareEntry *e;
    struct e820_entry *table;
    int n = e820_get_table(&table);
    uint64_t end = 4 * GiB;
    g_autofree uint8_t *zero = NULL;

    for (int i = 0; i < n; i++) {
        uint64_t top = le64_to_cpu(table[i].address) +
                       le64_to_cpu(table[i].length);

        end = MAX(end, QEMU_ALIGN_UP(top, TARGET_PAGE_SIZE));
    }
    tdx->pages_end = end;
    tdx->pages = g_malloc(end >> TARGET_PAGE_BITS);
    memset(tdx->pages, fw ? TDX_PAGE_PENDING : TDX_PAGE_ACCEPTED,
           end >> TARGET_PAGE_BITS);
    if (!fw) {
        return;
    }
    tdx_emu_set_page_state(tdx->fw_base, tdx->fw_size, TDX_PAGE_ACCEPTED);
    zero = g_malloc0(TARGET_PAGE_SIZE);
    for_each_tdx_fw_entry(fw, e) {
        tdx_emu_set_page_state(e->address, e->size, TDX_PAGE_ACCEPTED);
        if (e->type == TDVF_SECTION_TYPE_TEMP_MEM) {
            for (uint64_t off = 0; off < e->size; off += TARGET_PAGE_SIZE) {
                address_space_write(&address_space_memory, e->address + off,
                                    MEMTXATTRS_UNSPECIFIED, zero,
                                    MIN(TARGET_PAGE_SIZE, e->size - off));
            }
        } else if (e->type == TDVF_SECTION_TYPE_TD_HOB) {
            tdx_emu_hob_create(tdx, e);
        }
    }
}

/*
 * The TSC frequency the TD sees: the CPU's tsc-frequency property, else the
 * rate of the host counter that TCG's guest TSC follows, measured once.
 */
static uint64_t tdx_emu_measure_tsc_khz(void)
{
    int64_t t0 = cpu_get_host_ticks();
    int64_t n0 = qemu_clock_get_ns(QEMU_CLOCK_HOST);
    int64_t t1, n1;

    g_usleep(20000);
    t1 = cpu_get_host_ticks();
    n1 = qemu_clock_get_ns(QEMU_CLOCK_HOST);
    if (n1 <= n0 || t1 <= t0) {
        return 0;
    }
    return (uint64_t)(t1 - t0) * 1000000 / (uint64_t)(n1 - n0);
}

/* the TD's CPUs: no PMU (ATTRIBUTES.PERFMON is off), no MONITOR/MWAIT */
static void tdx_emu_cpu_instance_init(X86ConfidentialGuest *cg, CPUState *cpu)
{
    object_property_set_bool(OBJECT(cpu), "pmu", false, &error_abort);
    object_property_set_bool(OBJECT(cpu), "monitor", false, &error_abort);
    if (X86_CPU(cpu)->env.tsc_khz) {
        tdx_emu_state->tsc_khz = X86_CPU(cpu)->env.tsc_khz;
    }
}

static int tdx_emu_kvm_init(ConfidentialGuestSupport *cgs, Error **errp)
{
    TdxEmuState *tdx = TDX_EMU(cgs);

    if (!tcg_enabled()) {
        error_setg(errp, "tdx-emu is an emulation and needs -accel tcg");
        return -1;
    }
    if (tdx->gpaw != 48 && tdx->gpaw != 52) {
        error_setg(errp, "tdx-emu: gpaw must be 48 or 52 (got %u)", tdx->gpaw);
        return -1;
    }
    tdx_emu_state = tdx;
    tdx->init_done.notify = tdx_emu_init_done;
    qemu_add_machine_init_done_notifier(&tdx->init_done);
    cgs->ready = true;
    return 0;
}

static void tdx_emu_get_gpaw(Object *obj, Visitor *v, const char *name,
                             void *opaque, Error **errp)
{
    TdxEmuState *tdx = TDX_EMU(obj);
    uint32_t value = tdx->gpaw;

    visit_type_uint32(v, name, &value, errp);
}

static void tdx_emu_set_gpaw(Object *obj, Visitor *v, const char *name,
                             void *opaque, Error **errp)
{
    TdxEmuState *tdx = TDX_EMU(obj);
    uint32_t value;

    if (!visit_type_uint32(v, name, &value, errp)) {
        return;
    }
    if (value != 48 && value != 52) {
        error_setg(errp, "tdx-emu: gpaw must be 48 or 52");
        return;
    }
    tdx->gpaw = value;
}

static bool tdx_emu_get_sept_ve_disable(Object *obj, Error **errp)
{
    return !!(TDX_EMU(obj)->attributes & TDX_EMU_ATTR_SEPT_VE_DISABLE);
}

static void tdx_emu_set_sept_ve_disable(Object *obj, bool value, Error **errp)
{
    TdxEmuState *tdx = TDX_EMU(obj);

    if (value) {
        tdx->attributes |= TDX_EMU_ATTR_SEPT_VE_DISABLE;
        tdx->td_ctls |= TDX_TD_CTLS_PENDING_VE_DISABLE;
    } else {
        tdx->attributes &= ~TDX_EMU_ATTR_SEPT_VE_DISABLE;
        tdx->td_ctls &= ~TDX_TD_CTLS_PENDING_VE_DISABLE;
    }
}

static bool tdx_emu_get_debug(Object *obj, Error **errp)
{
    return !!(TDX_EMU(obj)->attributes & TDX_EMU_ATTR_DEBUG);
}

static void tdx_emu_set_debug(Object *obj, bool value, Error **errp)
{
    TdxEmuState *tdx = TDX_EMU(obj);

    if (value) {
        tdx->attributes |= TDX_EMU_ATTR_DEBUG;
    } else {
        tdx->attributes &= ~TDX_EMU_ATTR_DEBUG;
    }
}

static bool tdx_emu_get_strict(Object *obj, Error **errp)
{
    return TDX_EMU(obj)->strict;
}

static void tdx_emu_set_strict(Object *obj, bool value, Error **errp)
{
    TDX_EMU(obj)->strict = value;
}

static void tdx_emu_init(Object *obj)
{
    TdxEmuState *tdx = TDX_EMU(obj);

    tdx->gpaw = 52;
    tdx->attributes = TDX_EMU_ATTR_SEPT_VE_DISABLE;
    tdx->td_ctls = TDX_TD_CTLS_PENDING_VE_DISABLE;
    tdx->strict = true;
    tdx->event_notify_vector = -1;
    tdx->event_notify_apicid = -1;
    tdx->tsc_khz = tdx_emu_measure_tsc_khz();
}

static void tdx_emu_class_init(ObjectClass *oc, const void *data)
{
    ConfidentialGuestSupportClass *klass = CONFIDENTIAL_GUEST_SUPPORT_CLASS(oc);
    X86ConfidentialGuestClass *x86_klass = X86_CONFIDENTIAL_GUEST_CLASS(oc);

    klass->kvm_init = tdx_emu_kvm_init;
    x86_klass->cpu_instance_init = tdx_emu_cpu_instance_init;

    object_class_property_add(oc, "gpaw", "uint32", tdx_emu_get_gpaw,
                              tdx_emu_set_gpaw, NULL, NULL);
    object_class_property_set_description(oc, "gpaw",
        "guest physical address width, 48 or 52 (the shared bit is gpaw-1)");
    object_class_property_add_bool(oc, "sept-ve-disable",
                                   tdx_emu_get_sept_ve_disable,
                                   tdx_emu_set_sept_ve_disable);
    object_class_property_add_bool(oc, "debug", tdx_emu_get_debug,
                                   tdx_emu_set_debug);
    object_class_property_add_bool(oc, "strict", tdx_emu_get_strict,
                                   tdx_emu_set_strict);
    object_class_property_set_description(oc, "strict",
        "stop the VM on what would kill a real TD (default on)");
}

static const TypeInfo tdx_emu_info = {
    .parent = TYPE_X86_CONFIDENTIAL_GUEST,
    .name = TYPE_TDX_EMU,
    .instance_size = sizeof(TdxEmuState),
    .instance_init = tdx_emu_init,
    .class_init = tdx_emu_class_init,
    .interfaces = (const InterfaceInfo[]) {
        { TYPE_USER_CREATABLE },
        { }
    }
};

static void tdx_emu_register_types(void)
{
    type_register_static(&tdx_emu_info);
}

type_init(tdx_emu_register_types);
