/*
 * QEMU Intel TDX guest emulation for TCG (tdx-emu): TDCALL, #VE and the
 * emulated TDX module and host VMM.
 *
 * What the guest sees follows the TDX Module 1.5 ABI (the public module
 * source, MIT, was read for the register conventions, status codes and the
 * CPUID/MSR classification; no code was copied) and the GHCI for the
 * TDG.VP.VMCALL interface, answered the way KVM and QEMU answer it.
 * Functional only: no attestation, no memory protection.
 *
 * Copyright (C) 2026 The ASTERISC Research Lab
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/error-report.h"
#include "qemu/units.h"
#include "exec/target_page.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "accel/tcg/cpu-loop.h"
#include "system/address-spaces.h"
#include "system/memory.h"
#include "system/runstate.h"
#include "hw/core/boards.h"
#include "hw/i386/apic.h"
#include "crypto/hash.h"
#include "exec/cputlb.h"
#include "tcg/helper-tcg.h"
#include "tdx-emu.h"
#include "trace.h"

/* TDCALL leaves (TDX Module ABI, "TDCALL Instruction Leaf Numbers") */
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
#define TDG_VP_WR               10
#define TDG_SYS_RD              11
#define TDG_SYS_RDALL           12

/* TDCALL status codes (RAX): class in bits 47:40, operand id in bits 31:0 */
#define TDX_SUCCESS                         0x0000000000000000ULL
#define TDX_OPERAND_INVALID                 0xC000010000000000ULL
#define TDX_OPERAND_BUSY                    0x8000020000000000ULL
#define TDX_PAGE_ALREADY_ACCEPTED           0x00000B0A00000000ULL
#define TDX_PAGE_SIZE_MISMATCH              0xC0000B0B00000000ULL
#define TDX_NO_VALID_VE_INFO                0xC000070400000000ULL
#define TDX_METADATA_FIELD_ID_INCORRECT     0xC0000C0000000000ULL
#define TDX_METADATA_FIELD_NOT_WRITABLE     0xC0000C0100000000ULL
#define TDX_METADATA_FIELD_NOT_READABLE     0xC0000C0200000000ULL
#define TDX_METADATA_FIELD_VALUE_NOT_VALID  0xC0000C0300000000ULL
#define TDX_OPERAND_ID_RAX  0
#define TDX_OPERAND_ID_RCX  1
#define TDX_OPERAND_ID_RDX  2
#define TDX_OPERAND_ID_R8   8
#define TDX_OPERAND_ID_R9   9

/* TDG.VP.VMCALL sub-functions (GHCI) */
#define TDVMCALL_GET_TD_VM_CALL_INFO    0x10000
#define TDVMCALL_MAP_GPA                0x10001
#define TDVMCALL_GET_QUOTE              0x10002
#define TDVMCALL_REPORT_FATAL_ERROR     0x10003
#define TDVMCALL_SETUP_EVENT_NOTIFY     0x10004

/* TDG.VP.VMCALL completion status (R10) */
#define TDVMCALL_STATUS_SUCCESS             0x0000000000000000ULL
#define TDVMCALL_STATUS_RETRY               0x0000000000000001ULL
#define TDVMCALL_STATUS_INVALID_OPERAND     0x8000000000000000ULL
#define TDVMCALL_STATUS_GPA_INUSE           0x8000000000000001ULL
#define TDVMCALL_STATUS_ALIGN_ERROR         0x8000000000000002ULL
#define TDVMCALL_STATUS_SUBFUNC_UNSUPPORTED 0x8000000000000003ULL

/* GetQuote shared-buffer header status */
#define TDX_GET_QUOTE_STATUS_QGS_UNAVAILABLE 0x8000000000000001ULL

/*
 * TD-scope and vCPU-scope metadata fields: matched on the field code and the
 * class code (bits 61:56); bit 63, the element size and the context code are
 * ignored, as the module does (Linux spells TD_CTLS 0x1110000300000017).
 */
#define MD_FIELD_KEY(id)    ((id) & 0x3F00000000FFFFFFULL)
#define TDCS_ATTRIBUTES             0x1110000300000000ULL
#define TDCS_GPAW                   0x1110000300000003ULL
#define TDCS_NOTIFY_ENABLES         0x9110000300000010ULL
#define TDCS_CONFIG_FLAGS           0x9110000300000016ULL
#define TDCS_TD_CTLS                0x9110000300000017ULL
#define TDCS_TOPOLOGY_ENUM_CONFIGURED 0x9110000300000019ULL
#define TDVPS_VCPU_INDEX            0xA020000200000002ULL
#define TDVPS_CPUID_SUPERVISOR_VE   0xA020000000000007ULL
#define TDVPS_CPUID_USER_VE         0xA020000000000008ULL
#define TD_CTLS_WRITABLE            0x800000000000001FULL

#define TDX_REPORT_TYPE_TDX 0x81

/* x2APIC ICR delivery modes a TD cannot send: INIT and start-up IPI */
#define APIC_ICR_DM_INIT    5
#define APIC_ICR_DM_SIPI    6

/*
 * The MSRs the host VMM serves through TDG.VP.VMCALL<Instruction.RDMSR/WRMSR>
 * (KVM's tdx_has_emulated_msr): the x2APIC registers it has a model of, the
 * timer deadline, MTRRs, machine-check, a few platform MSRs. Anything else is
 * refused with INVALID_OPERAND, as KVM does. APIC_BASE, EFER and
 * FEATURE_CONTROL are read-only through this path.
 */
static bool tdx_emu_vmm_msr_allowed(uint32_t index, bool write)
{
    switch (index) {
    case 0x8b:                          /* IA32_UCODE_REV */
    case 0x10a:                         /* IA32_ARCH_CAPABILITIES */
    case 0x1fc:                         /* IA32_POWER_CTL */
    case 0x277:                         /* IA32_PAT */
    case 0xfe:                          /* IA32_MTRRCAP */
    case 0x200 ... 0x26f:               /* MTRRs */
    case 0x2ff:                         /* IA32_MTRR_DEF_TYPE */
    case 0x6e0:                         /* IA32_TSC_DEADLINE */
    case 0x1a0:                         /* IA32_MISC_ENABLE */
    case 0xce:                          /* MSR_PLATFORM_INFO */
    case 0x140:                         /* MSR_MISC_FEATURES_ENABLES */
    case 0x179 ... 0x17b:               /* IA32_MCG_CAP, STATUS, CTL */
    case 0x4d0:                         /* IA32_MCG_EXT_CTL */
    case 0x400 ... 0x47f:               /* IA32_MCx_CTL, STATUS, ADDR, MISC */
    case 0x280 ... 0x29f:               /* IA32_MCx_CTL2 */
    case 0x4b564d05:                    /* MSR_KVM_POLL_CONTROL */
        return true;
    case MSR_IA32_APICBASE:
    case MSR_EFER:
    case 0x3a:                          /* IA32_FEATURE_CONTROL */
        return !write;
    case 0x800 ... 0x8ff:
        switch (index) {
        case 0x808:                     /* TPR */
        case 0x80a:                     /* PPR */
        case 0x80b:                     /* EOI */
        case 0x810 ... 0x827:           /* ISR, TMR, IRR */
            /* virtualized by the CPU: KVM has no model of them */
            return false;
        default:
            return true;
        }
    default:
        return false;
    }
}

/* ---- #VE ---- */

/*
 * Record the information of a virtualization exception and raise it: vector
 * 20, no error code, RIP at the instruction (a fault).  A #VE while the
 * previous one is still pending (TDG.VP.VEINFO.GET not yet called) is a #DF,
 * as the TDX module does.
 */
static G_NORETURN void tdx_emu_raise_ve(CPUX86State *env, uint32_t exit_reason,
                                        uint64_t exit_qual, uint64_t gla,
                                        uint64_t gpa, uint32_t instr_len,
                                        uint8_t category, uintptr_t retaddr)
{
    trace_tdx_emu_ve(exit_reason, exit_qual, instr_len, category);
    if (env->tdx_ve.valid) {
        raise_exception_err_ra(env, EXCP08_DBLE, 0, retaddr);
    }
    env->tdx_ve.valid = true;
    env->tdx_ve.exit_reason = exit_reason;
    env->tdx_ve.exit_qual = exit_qual;
    env->tdx_ve.gla = gla;
    env->tdx_ve.gpa = gpa;
    env->tdx_ve.instr_len = instr_len;
    env->tdx_ve.instr_info = 0;
    env->tdx_ve.category = category;
    raise_exception_ra(env, EXCP14_VE, retaddr);
}

G_NORETURN void helper_tdx_ve(CPUX86State *env, uint32_t exit_reason,
                              uint64_t exit_qual, int insn_len)
{
    tdx_emu_raise_ve(env, exit_reason, exit_qual, 0, 0, insn_len,
                     TDX_VE_CATEGORY_PARAVIRT, GETPC());
}

G_NORETURN void helper_tdx_ve_io(CPUX86State *env, uint32_t qual,
                                 uint32_t port, uint32_t unused, int insn_len)
{
    uint64_t exit_qual = qual | ((uint64_t)(port & 0xffff) << 16);

    tdx_emu_raise_ve(env, TDX_EXIT_REASON_IO_INSTRUCTION, exit_qual, 0, 0,
                     insn_len, TDX_VE_CATEGORY_PARAVIRT, GETPC());
}

/*
 * The module's CPUID classification. Leaves in the paravirtualization range
 * are always a #VE; the leaves the module's table does not cover are a #VE
 * unless TD_CTLS.REDUCE_VE makes them return zeros; leaf 2 is a #VE unless
 * VIRT_CPUID2, leaves 0xB and 0x1F unless ENUM_TOPOLOGY. The rest is
 * virtualized from the CPU model (tdx_emu_cpuid()).
 */
static bool tdx_emu_cpuid_is_ve(uint32_t leaf, uint32_t subleaf,
                                uint8_t *category)
{
    uint64_t td_ctls = tdx_emu_td_ctls();

    *category = TDX_VE_CATEGORY_CONFIG_PARAVIRT;
    if (leaf >= 0x40000000 && leaf <= 0x4fffffff) {
        *category = TDX_VE_CATEGORY_PARAVIRT;
        return true;
    }
    switch (leaf) {
    case 0x2:
        return !(td_ctls & TDX_TD_CTLS_VIRT_CPUID2);
    case 0xb:
    case 0x1f:
        return !(td_ctls & TDX_TD_CTLS_ENUM_TOPOLOGY);
    case 0x6:
    case 0x9:
    case 0xc:
    case 0xf:
    case 0x10:
    case 0x16:
    case 0x17:
    case 0x1b:
    case 0x80000002:
    case 0x80000003:
    case 0x80000004:
    case 0x80000005:
        return !(td_ctls & TDX_TD_CTLS_REDUCE_VE);
    case 0x4:
        return subleaf >= 5 && !(td_ctls & TDX_TD_CTLS_REDUCE_VE);
    case 0x7:
        return subleaf >= 3 && !(td_ctls & TDX_TD_CTLS_REDUCE_VE);
    case 0x21:
        return subleaf != 0 && !(td_ctls & TDX_TD_CTLS_REDUCE_VE);
    default:
        return false;
    }
}

/* CPUID in an emulated TD: #VE for the leaves above, else the virtual value */
void helper_tdx_cpuid(CPUX86State *env, int insn_len)
{
    uint32_t leaf = env->regs[R_EAX];
    uint32_t subleaf = env->regs[R_ECX];
    int cpl = env->hflags & HF_CPL_MASK;
    uint8_t category = TDX_VE_CATEGORY_CONFIG_PARAVIRT;

    if ((cpl == 0 && (env->tdx_cpuid_ve & 1)) ||
        (cpl != 0 && (env->tdx_cpuid_ve & 2)) ||
        tdx_emu_cpuid_is_ve(leaf, subleaf, &category)) {
        tdx_emu_raise_ve(env, TDX_EXIT_REASON_CPUID, 0, 0, 0, insn_len,
                         category, GETPC());
    }
}

/*
 * The module's MSR classification with TD_CTLS.REDUCE_VE clear. Everything
 * not listed is native (the MSR is accessed directly, QEMU's own #GP rules
 * apply) except the few the module emulates itself (tdx_emu_msr_emulated).
 */
enum {
    TDX_MSR_NATIVE,
    TDX_MSR_VE,                 /* #VE, category 0x11 (non-configurable) */
    TDX_MSR_VE_CONFIG,          /* #VE, category 0x10; #GP with REDUCE_VE */
    TDX_MSR_GP,                 /* #GP(0) */
};

static int tdx_emu_msr_class(uint32_t index, bool write)
{
    uint64_t td_ctls = tdx_emu_td_ctls();

    /* outside the MSR bitmap windows, every access is a #VE */
    if (index > 0x1fff && (index < 0xc0000000 || index > 0xc0001fff)) {
        return TDX_MSR_VE;
    }
    switch (index) {
    case MSR_IA32_APICBASE:
    case 0xc0000083:                    /* IA32_CSTAR */
        return TDX_MSR_VE;
    case 0x17:                          /* IA32_PLATFORM_ID */
        return write ? TDX_MSR_VE_CONFIG : TDX_MSR_VE;
    case 0x3a:                          /* FEATURE_CONTROL: read emulated */
        return write ? TDX_MSR_VE_CONFIG : TDX_MSR_NATIVE;
    case 0xfe:                          /* IA32_MTRRCAP */
        return write ? TDX_MSR_GP : TDX_MSR_VE_CONFIG;
    case 0x2ff:                         /* IA32_MTRR_DEF_TYPE */
    case 0x6e0:                         /* IA32_TSC_DEADLINE */
    case 0x80f:                         /* x2APIC: SIVR */
    case 0x828:                         /* ESR */
    case 0x82f:                         /* LVT CMCI */
    case 0x830:                         /* ICR */
    case 0x832 ... 0x838:               /* LVT timer..error, TMICT */
    case 0x83a:                         /* LVT HWP */
    case 0x83e:                         /* DCR */
        return TDX_MSR_VE_CONFIG;
    case 0x802:                         /* x2APIC ID: see ENUM_TOPOLOGY */
        if (write) {
            return TDX_MSR_GP;
        }
        return (td_ctls & TDX_TD_CTLS_ENUM_TOPOLOGY) ? TDX_MSR_NATIVE
                                                     : TDX_MSR_VE_CONFIG;
    case 0x803:                         /* version */
    case 0x80d:                         /* LDR */
    case 0x839:                         /* TMCCT */
        return write ? TDX_MSR_GP : TDX_MSR_VE_CONFIG;
    case 0x10:                          /* IA32_TSC: write #VE */
        return write ? TDX_MSR_VE : TDX_MSR_NATIVE;
    case 0x1a0:                         /* IA32_MISC_ENABLE: read emulated */
        return write ? TDX_MSR_VE_CONFIG : TDX_MSR_NATIVE;
    default:
        break;
    }
    if (index >= 0x200 && index <= 0x26f) {
        return TDX_MSR_VE_CONFIG;       /* MTRRs */
    }
    return TDX_MSR_NATIVE;
}

/*
 * The MSRs the module emulates itself; true when handled (the value is in
 * *val for a read). The native helpers run for everything else.
 */
static bool tdx_emu_msr_emulated(CPUX86State *env, uint32_t index, bool write,
                                 uint64_t *val, int insn_len, uintptr_t ra)
{
    uint64_t td_ctls = tdx_emu_td_ctls();

    switch (index) {
    case 0x802:                         /* x2APIC ID with ENUM_TOPOLOGY */
        if (!write && (td_ctls & TDX_TD_CTLS_ENUM_TOPOLOGY)) {
            *val = env_archcpu(env)->apic_id;
            return true;
        }
        return false;
    case 0x3a:                          /* IA32_FEATURE_CONTROL */
        if (!write) {
            if (td_ctls & TDX_TD_CTLS_REDUCE_VE) {
                *val = 1;               /* locked, nothing enabled */
                return true;
            }
            tdx_emu_raise_ve(env, TDX_EXIT_REASON_MSR_READ, 0, 0, 0, insn_len,
                             TDX_VE_CATEGORY_CONFIG_PARAVIRT, ra);
        }
        return false;
    case 0x1a0:                         /* MISC_ENABLE: read emulated */
        if (!write) {
            *val = env->msr_ia32_misc_enable;
            return true;
        }
        if (td_ctls & TDX_TD_CTLS_REDUCE_VE) {
            if (*val & 0xFFFFFFFFFF3AE776ULL) {
                raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
            }
            if ((*val ^ env->msr_ia32_misc_enable) & ((1 << 18) | (1 << 22))) {
                /* MONITOR FSM and LIMIT_CPUID_MAXVAL cannot change */
                tdx_emu_raise_ve(env, TDX_EXIT_REASON_MSR_WRITE, 0, 0, 0,
                                 insn_len, TDX_VE_CATEGORY_UNSUPPORTED, ra);
            }
            env->msr_ia32_misc_enable = *val;
            return true;
        }
        return false;
    case MSR_EFER:
        if (write) {
            /* only SCE may change; LMA is ignored; the rest is a #VE */
            uint64_t cur = env->efer;

            if ((*val ^ cur) & ~(uint64_t)(MSR_EFER_SCE | MSR_EFER_LMA)) {
                tdx_emu_raise_ve(env, TDX_EXIT_REASON_MSR_WRITE, 0, 0, 0,
                                 insn_len, TDX_VE_CATEGORY_UNSUPPORTED, ra);
            }
            cpu_load_efer(env, (cur & ~(uint64_t)MSR_EFER_SCE) |
                               (*val & MSR_EFER_SCE));
            return true;
        }
        return false;
    default:
        return false;
    }
}

/*
 * RDMSR/WRMSR in an emulated TD: #VE or #GP for the MSRs the module does not
 * pass through, the module's own emulation for a few; returns 1 when the
 * access is complete, 0 when the native helper must run.
 */
static uint32_t tdx_emu_msr_access(CPUX86State *env, bool write, int insn_len,
                                   uintptr_t ra)
{
    uint32_t index = env->regs[R_ECX];
    uint32_t reason = write ? TDX_EXIT_REASON_MSR_WRITE
                            : TDX_EXIT_REASON_MSR_READ;
    uint64_t val = 0;

    switch (tdx_emu_msr_class(index, write)) {
    case TDX_MSR_VE:
        tdx_emu_raise_ve(env, reason, 0, 0, 0, insn_len,
                         TDX_VE_CATEGORY_PARAVIRT, ra);
    case TDX_MSR_VE_CONFIG:
        if (tdx_emu_td_ctls() & TDX_TD_CTLS_REDUCE_VE) {
            raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
        }
        tdx_emu_raise_ve(env, reason, 0, 0, 0, insn_len,
                         TDX_VE_CATEGORY_CONFIG_PARAVIRT, ra);
    case TDX_MSR_GP:
        raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
    default:
        break;
    }
    if (write) {
        val = (uint32_t)env->regs[R_EAX] |
              ((uint64_t)(uint32_t)env->regs[R_EDX] << 32);
    }
    if (tdx_emu_msr_emulated(env, index, write, &val, insn_len, ra)) {
        if (!write) {
            env->regs[R_EAX] = (uint32_t)val;
            env->regs[R_EDX] = (uint32_t)(val >> 32);
        }
        return 1;
    }
    return 0;
}

uint32_t helper_tdx_rdmsr(CPUX86State *env, int insn_len)
{
    return tdx_emu_msr_access(env, false, insn_len, GETPC());
}

uint32_t helper_tdx_wrmsr(CPUX86State *env, int insn_len)
{
    return tdx_emu_msr_access(env, true, insn_len, GETPC());
}

/* ---- the emulated host VMM: TDG.VP.VMCALL ---- */

static uint64_t tdx_emu_gpa_mask(void)
{
    return ~(1ULL << (tdx_emu_state->gpaw - 1));
}

/*
 * r[] is the VMM's view of the guest GPRs (unselected ones read as zero);
 * the handler writes its outputs into it and returns the R10 status.
 */
static uint64_t tdx_emu_vmcall(CPUX86State *env, uint64_t *r, int insn_len)
{
    TdxEmuState *tdx = tdx_emu_state;
    uint64_t leaf = r[R_R11];

    if (r[R_R10] != 0) {
        /* vendor-specific (KVM hypercall) class: not provided */
        return TDVMCALL_STATUS_INVALID_OPERAND;
    }

    switch (leaf) {
    case TDX_EXIT_REASON_CPUID: {
        uint32_t eax, ebx, ecx, edx;

        cpu_x86_cpuid(env, (uint32_t)r[R_R12], (uint32_t)r[R_R13],
                      &eax, &ebx, &ecx, &edx);
        r[R_R12] = eax;
        r[R_R13] = ebx;
        r[R_R14] = ecx;
        r[R_R15] = edx;
        return TDVMCALL_STATUS_SUCCESS;
    }
    case TDX_EXIT_REASON_HLT: {
        CPUState *cs = env_cpu(env);

        /*
         * r12: interrupts blocked in the TD. The vCPU sleeps until an
         * interrupt is pending, whatever RFLAGS.IF says (x86_cpu_has_work).
         */
        env->eip += insn_len;
        do_end_instruction(env);
        env->tdx_hlt_wait = true;
        cs->halted = 1;
        cs->exception_index = EXCP_HLT;
        cpu_loop_exit(cs);
    }
    case TDX_EXIT_REASON_IO_INSTRUCTION: {
        uint64_t size = r[R_R12], dir = r[R_R13], port = r[R_R14];
        MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;

        if ((size != 1 && size != 2 && size != 4) || dir > 1 || port > 0xffff) {
            return TDVMCALL_STATUS_INVALID_OPERAND;
        }
        if (dir == 0) {
            switch (size) {
            case 1:
                r[R_R11] = address_space_ldub(&address_space_io, port,
                                              attrs, NULL);
                break;
            case 2:
                r[R_R11] = address_space_lduw_le(&address_space_io, port,
                                                 attrs, NULL);
                break;
            default:
                r[R_R11] = address_space_ldl_le(&address_space_io, port,
                                                attrs, NULL);
                break;
            }
        } else {
            switch (size) {
            case 1:
                address_space_stb(&address_space_io, port, r[R_R15],
                                  attrs, NULL);
                break;
            case 2:
                address_space_stw_le(&address_space_io, port, r[R_R15],
                                     attrs, NULL);
                break;
            default:
                address_space_stl_le(&address_space_io, port, r[R_R15],
                                     attrs, NULL);
                break;
            }
        }
        return TDVMCALL_STATUS_SUCCESS;
    }
    case TDX_EXIT_REASON_MSR_READ: {
        uint64_t val;

        /* the VMM emulates the MSR in the host: QEMU's MSR core, no #GP */
        if (r[R_R12] > 0xffffffffULL ||
            !tdx_emu_vmm_msr_allowed(r[R_R12], false) ||
            !x86_rdmsr_core(env, r[R_R12], &val)) {
            return TDVMCALL_STATUS_INVALID_OPERAND;
        }
        r[R_R11] = val;
        return TDVMCALL_STATUS_SUCCESS;
    }
    case TDX_EXIT_REASON_MSR_WRITE: {
        uint32_t index = r[R_R12];

        if (r[R_R12] > 0xffffffffULL ||
            !tdx_emu_vmm_msr_allowed(index, true)) {
            return TDVMCALL_STATUS_INVALID_OPERAND;
        }
        if (index == 0x830) {
            unsigned dm = (r[R_R13] >> 8) & 7;

            if (dm == APIC_ICR_DM_INIT || dm == APIC_ICR_DM_SIPI) {
                /* a TD has no INIT or SIPI: the VMM drops them */
                qemu_log_mask(LOG_GUEST_ERROR, "tdx-emu: INIT/SIPI through the "
                              "ICR dropped (0x%" PRIx64 ")\n", r[R_R13]);
                return TDVMCALL_STATUS_SUCCESS;
            }
        }
        if (!x86_wrmsr_core(env, index, r[R_R13])) {
            return TDVMCALL_STATUS_INVALID_OPERAND;
        }
        return TDVMCALL_STATUS_SUCCESS;
    }
    case TDX_EXIT_REASON_EPT_VIOLATION: {
        /* #VE.RequestMMIO: r12 size, r13 direction, r14 GPA, r15 data */
        uint64_t size = r[R_R12], dir = r[R_R13];
        hwaddr gpa = r[R_R14] & tdx_emu_gpa_mask();
        uint64_t data = r[R_R15];
        MemTxResult res;

        if ((size != 1 && size != 2 && size != 4 && size != 8) || dir > 1) {
            return TDVMCALL_STATUS_INVALID_OPERAND;
        }
        if (dir == 0) {
            data = 0;
            res = address_space_read(&address_space_memory, gpa,
                                     MEMTXATTRS_UNSPECIFIED, &data, size);
            r[R_R11] = le64_to_cpu(data);
        } else {
            data = cpu_to_le64(data);
            res = address_space_write(&address_space_memory, gpa,
                                      MEMTXATTRS_UNSPECIFIED, &data, size);
        }
        return res == MEMTX_OK ? TDVMCALL_STATUS_SUCCESS
                               : TDVMCALL_STATUS_INVALID_OPERAND;
    }
    case TDVMCALL_GET_TD_VM_CALL_INFO:
        /* leaf r12 = 0: the sub-function bitmap (none of the optional ones) */
        r[R_R11] = r[R_R12] = r[R_R13] = r[R_R14] = 0;
        return TDVMCALL_STATUS_SUCCESS;
    case TDVMCALL_MAP_GPA: {
        uint64_t gpa = r[R_R12], size = r[R_R13];
        bool shared = gpa & tdx_emu_shared_bit();

        if ((gpa & 0xfff) || (size & 0xfff)) {
            return TDVMCALL_STATUS_ALIGN_ERROR;
        }
        gpa &= tdx_emu_gpa_mask();
        if (gpa + size < gpa || gpa + size > tdx->pages_end) {
            return TDVMCALL_STATUS_INVALID_OPERAND;
        }
        if (tdx->fw_size && gpa < tdx->fw_base + tdx->fw_size &&
            gpa + size > tdx->fw_base) {
            return TDVMCALL_STATUS_GPA_INUSE;     /* the firmware image */
        }
        /*
         * To shared: the host maps the pages (nothing to do without memory
         * protection). To private: the pages are pending until accepted.
         * Either way the TD's mappings of the range must be re-checked.
         */
        tdx_emu_set_page_state(gpa, size,
                               shared ? TDX_PAGE_SHARED : TDX_PAGE_PENDING);
        tlb_flush_all_cpus_synced(env_cpu(env));
        return TDVMCALL_STATUS_SUCCESS;
    }
    case TDVMCALL_GET_QUOTE: {
        hwaddr gpa = r[R_R12] & tdx_emu_gpa_mask();
        uint64_t size = r[R_R13], status;

        if ((r[R_R12] & 0xfff) || (size & 0xfff)) {
            return TDVMCALL_STATUS_ALIGN_ERROR;
        }
        if (size == 0) {
            return TDVMCALL_STATUS_INVALID_OPERAND;
        }
        /* no quote generation service: say so in the buffer, as QEMU does */
        status = cpu_to_le64(TDX_GET_QUOTE_STATUS_QGS_UNAVAILABLE);
        address_space_write(&address_space_memory, gpa + 8,
                            MEMTXATTRS_UNSPECIFIED, &status, 8);
        return TDVMCALL_STATUS_SUCCESS;
    }
    case TDVMCALL_REPORT_FATAL_ERROR: {
        /* the message is in r14, r15, rbx, rdi, rsi, r8, r9, rdx */
        uint64_t words[8] = { r[R_R14], r[R_R15], r[R_EBX], r[R_EDI],
                              r[R_ESI], r[R_R8], r[R_R9], r[R_EDX] };
        char msg[65] = { 0 };

        memcpy(msg, words, 64);
        for (int i = 0; i < 64; i++) {
            if (msg[i] && (msg[i] < 0x20 || msg[i] > 0x7e)) {
                msg[i] = '.';
            }
        }
        error_report("tdx-emu: TD reported a fatal error: code 0x%" PRIx64
                     " gpa 0x%" PRIx64 " \"%s\"", r[R_R12], r[R_R13], msg);
        qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_PANIC);
        return TDVMCALL_STATUS_SUCCESS;
    }
    case TDVMCALL_SETUP_EVENT_NOTIFY: {
        uint64_t vector = r[R_R12];

        if (vector < 32 || vector > 255) {
            return TDVMCALL_STATUS_INVALID_OPERAND;
        }
        tdx->event_notify_vector = vector;
        tdx->event_notify_apicid = env_archcpu(env)->apic_id;
        return TDVMCALL_STATUS_SUCCESS;
    }
    default:
        qemu_log_mask(LOG_GUEST_ERROR, "tdx-emu: unsupported TDG.VP.VMCALL "
                      "leaf 0x%" PRIx64 "\n", leaf);
        return TDVMCALL_STATUS_SUBFUNC_UNSUPPORTED;
    }
}

/* TDG.VP.VMCALL: pass the selected GPRs to the VMM, bring the results back */
static uint64_t tdg_vp_vmcall(CPUX86State *env, int insn_len)
{
    uint64_t control = env->regs[R_ECX];
    uint32_t select = control & 0xffff;
    uint64_t r[CPU_NB_REGS];
    uint64_t status;

    /* bits 63:32 reserved; RAX, RCX and RSP cannot be selected */
    if ((control >> 32) || (select & 0x13)) {
        return TDX_OPERAND_INVALID | TDX_OPERAND_ID_RCX;
    }
    for (int i = 0; i < CPU_NB_REGS; i++) {
        r[i] = (select & (1u << i)) ? env->regs[i] : 0;
    }
    trace_tdx_emu_vmcall(r[R_R11], r[R_R10]);
    status = tdx_emu_vmcall(env, r, insn_len);
    r[R_R10] = status;
    for (int i = 0; i < CPU_NB_REGS; i++) {
        if (select & (1u << i)) {
            env->regs[i] = r[i];
        }
    }
    return TDX_SUCCESS;
}

/* ---- the emulated TDX module: the other TDCALL leaves ---- */

static uint64_t tdg_vp_info(CPUX86State *env)
{
    TdxEmuState *tdx = tdx_emu_state;
    CPUState *cs = env_cpu(env);
    MachineState *ms = MACHINE(qdev_get_machine());

    env->regs[R_ECX] = tdx->gpaw;
    env->regs[R_EDX] = tdx->attributes;
    env->regs[R_R8] = (uint64_t)ms->smp.cpus |
                      ((uint64_t)ms->smp.max_cpus << 32);
    env->regs[R_R9] = cs->cpu_index;
    env->regs[R_R10] = 1;                   /* TDG.SYS.RD is available */
    env->regs[R_R11] = 0;
    return TDX_SUCCESS;
}

static uint64_t tdg_vp_veinfo_get(CPUX86State *env, unsigned version)
{
    env->regs[R_ECX] = env->regs[R_EDX] = 0;
    env->regs[R_R8] = env->regs[R_R9] = env->regs[R_R10] = 0;
    if (!env->tdx_ve.valid) {
        return TDX_NO_VALID_VE_INFO;
    }
    env->regs[R_ECX] = env->tdx_ve.exit_reason;
    if (version >= 1) {
        env->regs[R_ECX] |= (uint64_t)env->tdx_ve.category << 32;
    }
    env->regs[R_EDX] = env->tdx_ve.exit_qual;
    env->regs[R_R8] = env->tdx_ve.gla;
    env->regs[R_R9] = env->tdx_ve.gpa;
    env->regs[R_R10] = env->tdx_ve.instr_len |
                       ((uint64_t)env->tdx_ve.instr_info << 32);
    env->tdx_ve.valid = false;
    return TDX_SUCCESS;
}

static uint64_t tdg_vp_cpuidve_set(CPUX86State *env)
{
    uint64_t rcx = env->regs[R_ECX];

    if (rcx & ~3ULL) {
        return TDX_OPERAND_INVALID | TDX_OPERAND_ID_RCX;
    }
    if ((tdx_emu_td_ctls() & TDX_TD_CTLS_LOCK) && rcx != env->tdx_cpuid_ve) {
        return TDX_OPERAND_INVALID | TDX_OPERAND_ID_RCX;
    }
    env->tdx_cpuid_ve = rcx;
    return TDX_SUCCESS;
}

/*
 * TDG.MEM.PAGE.ACCEPT: a pending private page (4 KiB, or 2 MiB of them)
 * becomes accepted and is zero-filled, as the module does; an accepted one
 * reports PAGE_ALREADY_ACCEPTED, a 2 MiB request over pages of mixed state
 * PAGE_SIZE_MISMATCH. A shared page is not acceptable: the module takes a
 * TD exit to the VMM, which stops a real TD (strict), or converts it.
 */
static uint64_t tdg_mem_page_accept(CPUX86State *env)
{
    uint64_t rcx = env->regs[R_ECX];
    unsigned level = rcx & 7;
    uint64_t gpa = rcx & ~0xfffULL;
    uint64_t size = level ? 2 * MiB : TARGET_PAGE_SIZE;
    unsigned pending = 0, accepted_4k = 0, accepted_2m = 0, shared = 0;
    g_autofree uint8_t *zero = NULL;

    if (level > 1 || (rcx & 0xff8) || (rcx >> 52) ||
        (level == 1 && (gpa & 0x1fffff)) ||
        (gpa & ~tdx_emu_gpa_mask())) {
        return TDX_OPERAND_INVALID | TDX_OPERAND_ID_RCX;
    }
    if (gpa + size > tdx_emu_state->pages_end || !tdx_emu_gpa_is_ram(gpa)) {
        return TDX_OPERAND_INVALID | TDX_OPERAND_ID_RCX;
    }
    for (uint64_t p = gpa; p < gpa + size; p += TARGET_PAGE_SIZE) {
        switch (tdx_emu_page_state(p)) {
        case TDX_PAGE_PENDING:
            pending++;
            break;
        case TDX_PAGE_ACCEPTED:
            accepted_4k++;
            break;
        case TDX_PAGE_ACCEPTED_2M:
            accepted_2m++;
            break;
        default:
            shared++;
            break;
        }
    }
    if (shared) {
        if (tdx_emu_state->strict) {
            tdx_emu_stop("tdx-emu: TDG.MEM.PAGE.ACCEPT of a shared page at GPA"
                         " 0x%" PRIx64 " (the VMM would not map it private)",
                         gpa);
        }
        pending += shared;
    }
    /*
     * The status carries the Secure EPT level the walk reached: a 4 KiB page
     * inside an accepted 2 MiB mapping reports level 1; a 2 MiB request over
     * 4 KiB mappings finds a page table at level 1 (PAGE_SIZE_MISMATCH).
     */
    if (level == 0) {
        if (accepted_2m) {
            return TDX_PAGE_ALREADY_ACCEPTED | 1;
        }
        if (accepted_4k) {
            return TDX_PAGE_ALREADY_ACCEPTED;
        }
    } else {
        if (accepted_2m == 512) {
            return TDX_PAGE_ALREADY_ACCEPTED | 1;
        }
        if (accepted_4k || accepted_2m) {
            return TDX_PAGE_SIZE_MISMATCH | 1;
        }
    }
    zero = g_malloc0(TARGET_PAGE_SIZE);
    for (uint64_t p = gpa; p < gpa + size; p += TARGET_PAGE_SIZE) {
        address_space_write(&address_space_memory, p, MEMTXATTRS_UNSPECIFIED,
                            zero, TARGET_PAGE_SIZE);
    }
    tdx_emu_set_page_state(gpa, size,
                           level ? TDX_PAGE_ACCEPTED_2M : TDX_PAGE_ACCEPTED);
    return TDX_SUCCESS;
}

/*
 * The checks of the Secure EPT and the shared EPT at TLB fill, with the
 * translated GPA and whether the TD's mapping has the shared bit: an access
 * to MMIO through a shared mapping is the #VE the TD handles; the accesses
 * that would make the module or the VMM kill a real TD (a private mapping of
 * MMIO or of a shared page, a shared mapping of a private page, a pending
 * private page with PENDING_VE_DISABLE) stop the VM when strict, and are a
 * #VE otherwise. Returns the exception to raise, 0 for none.
 */
int tdx_emu_check_access(CPUX86State *env, vaddr addr, hwaddr paddr,
                         bool shared, MMUAccessType access_type)
{
    TdxEmuState *tdx = tdx_emu_state;
    bool is_ram = tdx_emu_gpa_is_ram(paddr);
    uint8_t state = is_ram ? tdx_emu_page_state(paddr) : TDX_PAGE_PENDING;
    uint64_t qual = access_type == MMU_DATA_STORE ? 2 :
                    access_type == MMU_INST_FETCH ? 4 : 1;
    uint8_t category = TDX_VE_CATEGORY_ARCH;
    const char *what = NULL;

    trace_tdx_emu_access(paddr, shared, is_ram, state);
    if (shared) {
        if (is_ram && state == TDX_PAGE_SHARED) {
            return 0;
        }
        if (is_ram) {
            what = "an access with the shared bit to a private page";
        }
        /* else MMIO: the #VE the TD expects */
    } else if (!is_ram) {
        what = "an access to MMIO without the shared bit";
    } else if (state == TDX_PAGE_SHARED) {
        what = "an access without the shared bit to a shared page";
    } else if (state == TDX_PAGE_PENDING) {
        if (tdx->td_ctls & TDX_TD_CTLS_PENDING_VE_DISABLE) {
            what = "an access to a private page the TD has not accepted";
        } else {
            category = TDX_VE_CATEGORY_PENDING;
        }
    } else {
        return 0;
    }
    if (what && tdx->strict) {
        tdx_emu_stop("tdx-emu: %s: GPA 0x%" PRIx64 " (linear 0x%" PRIx64
                     ", RIP 0x%" PRIx64 ")", what, (uint64_t)paddr,
                     (uint64_t)addr, (uint64_t)env->eip);
    }
    if (what) {
        qemu_log_mask(LOG_GUEST_ERROR, "tdx-emu: %s: GPA 0x%" PRIx64
                      " (linear 0x%" PRIx64 "): #VE\n", what,
                      (uint64_t)paddr, (uint64_t)addr);
    }
    trace_tdx_emu_ve(TDX_EXIT_REASON_EPT_VIOLATION, qual, 0, category);
    if (env->tdx_ve.valid) {
        return EXCP08_DBLE;
    }
    env->tdx_ve.valid = true;
    env->tdx_ve.exit_reason = TDX_EXIT_REASON_EPT_VIOLATION;
    env->tdx_ve.exit_qual = qual | (1 << 7);     /* GLA valid */
    env->tdx_ve.gla = addr;
    env->tdx_ve.gpa = paddr | (shared ? tdx_emu_shared_bit() : 0);
    env->tdx_ve.instr_len = 0;
    env->tdx_ve.instr_info = 0;
    env->tdx_ve.category = category;
    return EXCP14_VE;
}

/* RTMRs of the emulated TD: SHA-384, extended by TDG.MR.RTMR.EXTEND */
static uint8_t tdx_emu_rtmr[4][48];

static uint64_t tdg_mr_rtmr_extend(CPUX86State *env)
{
    hwaddr data_gpa = env->regs[R_ECX];
    uint64_t index = env->regs[R_EDX];
    uint8_t buf[96];
    uint8_t *digest = NULL;
    size_t digest_len = 0;

    if (data_gpa & 63) {
        return TDX_OPERAND_INVALID | TDX_OPERAND_ID_RCX;
    }
    if (index >= 4) {
        return TDX_OPERAND_INVALID | TDX_OPERAND_ID_RDX;
    }
    memcpy(buf, tdx_emu_rtmr[index], 48);
    address_space_read(&address_space_memory, data_gpa & tdx_emu_gpa_mask(),
                       MEMTXATTRS_UNSPECIFIED, buf + 48, 48);
    if (qcrypto_hash_bytes(QCRYPTO_HASH_ALGO_SHA384, buf, sizeof(buf),
                           &digest, &digest_len, NULL) < 0 ||
        digest_len != 48) {
        g_free(digest);
        return TDX_OPERAND_BUSY;
    }
    memcpy(tdx_emu_rtmr[index], digest, 48);
    g_free(digest);
    return TDX_SUCCESS;
}

/*
 * TDG.MR.REPORT: a TDREPORT_STRUCT with the report type, the caller's
 * REPORTDATA and the TD attributes, RTMRs and XFAM; the MAC and the
 * measurements of the TCB are zero (no attestation).
 */
static uint64_t tdg_mr_report(CPUX86State *env)
{
    hwaddr report_gpa = env->regs[R_ECX];
    hwaddr data_gpa = env->regs[R_EDX];
    uint64_t r8 = env->regs[R_R8];
    uint8_t report[1024] = { 0 };
    uint64_t v;

    if (report_gpa & 1023) {
        return TDX_OPERAND_INVALID | TDX_OPERAND_ID_RCX;
    }
    if (data_gpa & 63) {
        return TDX_OPERAND_INVALID | TDX_OPERAND_ID_RDX;
    }
    if (r8 & ~0x300ULL) {
        return TDX_OPERAND_INVALID | TDX_OPERAND_ID_R8;
    }
    report[0] = TDX_REPORT_TYPE_TDX;        /* REPORTMACSTRUCT.REPORTTYPE */
    address_space_read(&address_space_memory, data_gpa & tdx_emu_gpa_mask(),
                       MEMTXATTRS_UNSPECIFIED, report + 128, 64);
    v = cpu_to_le64(tdx_emu_state->attributes);
    memcpy(report + 512, &v, 8);            /* TDINFO.ATTRIBUTES */
    v = cpu_to_le64(env->xcr0);
    memcpy(report + 520, &v, 8);            /* TDINFO.XFAM */
    memcpy(report + 720, tdx_emu_rtmr, sizeof(tdx_emu_rtmr)); /* TDINFO.RTMR */
    address_space_write(&address_space_memory, report_gpa & tdx_emu_gpa_mask(),
                        MEMTXATTRS_UNSPECIFIED, report, sizeof(report));
    return TDX_SUCCESS;
}

static uint64_t *tdx_emu_td_field(uint64_t id, uint64_t *wr_mask)
{
    TdxEmuState *tdx = tdx_emu_state;
    static uint64_t scratch;

    *wr_mask = 0;
    switch (MD_FIELD_KEY(id)) {
    case MD_FIELD_KEY(TDCS_ATTRIBUTES):
        scratch = tdx->attributes;
        return &scratch;
    case MD_FIELD_KEY(TDCS_GPAW):
        scratch = tdx->gpaw == 52;
        return &scratch;
    case MD_FIELD_KEY(TDCS_NOTIFY_ENABLES):
        *wr_mask = ~0ULL;
        return &tdx->notify_enables;
    case MD_FIELD_KEY(TDCS_CONFIG_FLAGS):
        /* bit 0 GPAW; FLEXIBLE_PENDING_VE is 0 */
        scratch = (tdx->gpaw == 52);
        return &scratch;
    case MD_FIELD_KEY(TDCS_TD_CTLS):
        *wr_mask = TD_CTLS_WRITABLE;
        return &tdx->td_ctls;
    case MD_FIELD_KEY(TDCS_TOPOLOGY_ENUM_CONFIGURED):
        scratch = 1;        /* the VMM gives every vCPU its x2APIC id */
        return &scratch;
    default:
        return NULL;
    }
}

static uint64_t tdg_vm_rd(CPUX86State *env)
{
    uint64_t mask;
    uint64_t *f;

    if (env->regs[R_ECX] != 0) {
        return TDX_OPERAND_INVALID | TDX_OPERAND_ID_RCX;
    }
    f = tdx_emu_td_field(env->regs[R_EDX], &mask);
    if (!f) {
        return TDX_METADATA_FIELD_ID_INCORRECT;
    }
    env->regs[R_R8] = *f;
    env->regs[R_EDX] = -1ULL;           /* no "next field" enumeration */
    return TDX_SUCCESS;
}

/* TD_CTLS: the module's rules for the guest-writable control bits */
static uint64_t tdx_emu_td_ctls_write(uint64_t old, uint64_t new)
{
    if (old & TDX_TD_CTLS_LOCK) {
        return TDX_METADATA_FIELD_VALUE_NOT_VALID;
    }
    if ((new ^ old) & TDX_TD_CTLS_PENDING_VE_DISABLE) {
        /* CONFIG_FLAGS.FLEXIBLE_PENDING_VE is 0: fixed by the attributes */
        return TDX_METADATA_FIELD_VALUE_NOT_VALID;
    }
    if (new & TDX_TD_CTLS_REDUCE_VE) {
        /* REDUCE_VE implies ENUM_TOPOLOGY and VIRT_CPUID2 */
        new |= TDX_TD_CTLS_ENUM_TOPOLOGY | TDX_TD_CTLS_VIRT_CPUID2;
    }
    tdx_emu_state->td_ctls = new;
    return TDX_SUCCESS;
}

static uint64_t tdg_vm_wr(CPUX86State *env)
{
    uint64_t mask, old, new, wr = env->regs[R_R9], status;
    uint64_t *f;

    if (env->regs[R_ECX] != 0) {
        return TDX_OPERAND_INVALID | TDX_OPERAND_ID_RCX;
    }
    f = tdx_emu_td_field(env->regs[R_EDX], &mask);
    if (!f) {
        return TDX_METADATA_FIELD_ID_INCORRECT;
    }
    if (!(wr & mask)) {
        return TDX_METADATA_FIELD_NOT_WRITABLE;
    }
    old = *f;
    new = (old & ~wr) | (env->regs[R_R8] & wr);
    if (MD_FIELD_KEY(env->regs[R_EDX]) == MD_FIELD_KEY(TDCS_TD_CTLS)) {
        status = tdx_emu_td_ctls_write(old, new);
        if (status != TDX_SUCCESS) {
            return status;
        }
    } else {
        *f = new;
    }
    env->regs[R_R8] = old;
    return TDX_SUCCESS;
}

static uint64_t tdg_vp_rd_wr(CPUX86State *env, bool write)
{
    uint64_t id = env->regs[R_EDX], old;

    if (env->regs[R_ECX] != 0) {
        return TDX_OPERAND_INVALID | TDX_OPERAND_ID_RCX;
    }
    switch (MD_FIELD_KEY(id)) {
    case MD_FIELD_KEY(TDVPS_VCPU_INDEX):
        if (write) {
            return TDX_METADATA_FIELD_NOT_WRITABLE;
        }
        env->regs[R_R8] = env_cpu(env)->cpu_index;
        break;
    case MD_FIELD_KEY(TDVPS_CPUID_SUPERVISOR_VE):
    case MD_FIELD_KEY(TDVPS_CPUID_USER_VE): {
        unsigned bit = MD_FIELD_KEY(id) == MD_FIELD_KEY(TDVPS_CPUID_USER_VE);

        old = (env->tdx_cpuid_ve >> bit) & 1;
        if (write) {
            if (!(env->regs[R_R9] & 0xff)) {
                return TDX_METADATA_FIELD_NOT_WRITABLE;
            }
            if (env->regs[R_R8] & env->regs[R_R9] & 1) {
                env->tdx_cpuid_ve |= 1 << bit;
            } else if (env->regs[R_R9] & 1) {
                env->tdx_cpuid_ve &= ~(1 << bit);
            }
        }
        env->regs[R_R8] = old;
        break;
    }
    default:
        return TDX_METADATA_FIELD_ID_INCORRECT;
    }
    env->regs[R_EDX] = -1ULL;
    return TDX_SUCCESS;
}

/* TDCALL: the leaf in RAX[15:0], the version in RAX[23:16] */
void helper_tdcall(CPUX86State *env, int insn_len)
{
    uint64_t rax = env->regs[R_EAX];
    unsigned leaf = rax & 0xffff;
    unsigned version = (rax >> 16) & 0xff;
    uint64_t status;

    if (!(env->hflags & HF_LMA_MASK) || !(env->hflags & HF_CS64_MASK)) {
        /* TDCALL outside 64-bit mode */
        raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
    }
    if (rax >> 24) {
        status = TDX_OPERAND_INVALID | TDX_OPERAND_ID_RAX;
        goto out;
    }
    if (version != 0 && leaf != TDG_VP_VEINFO_GET && leaf != TDG_VM_RD) {
        status = TDX_OPERAND_INVALID | TDX_OPERAND_ID_RAX;
        goto out;
    }

    switch (leaf) {
    case TDG_VP_VMCALL:
        status = tdg_vp_vmcall(env, insn_len);
        break;
    case TDG_VP_INFO:
        status = tdg_vp_info(env);
        break;
    case TDG_MR_RTMR_EXTEND:
        status = tdg_mr_rtmr_extend(env);
        break;
    case TDG_VP_VEINFO_GET:
        status = tdg_vp_veinfo_get(env, version);
        break;
    case TDG_MR_REPORT:
        status = tdg_mr_report(env);
        break;
    case TDG_VP_CPUIDVE_SET:
        status = tdg_vp_cpuidve_set(env);
        break;
    case TDG_MEM_PAGE_ACCEPT:
        status = tdg_mem_page_accept(env);
        break;
    case TDG_VM_RD:
        status = tdg_vm_rd(env);
        break;
    case TDG_VM_WR:
        status = tdg_vm_wr(env);
        break;
    case TDG_VP_RD:
        status = tdg_vp_rd_wr(env, false);
        break;
    case TDG_VP_WR:
        status = tdg_vp_rd_wr(env, true);
        break;
    case TDG_SYS_RD:
    case TDG_SYS_RDALL:
        /* no global metadata is published */
        env->regs[R_R8] = 0;
        env->regs[R_EDX] = -1ULL;
        status = TDX_METADATA_FIELD_ID_INCORRECT;
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR, "tdx-emu: unsupported TDCALL leaf %u\n",
                      leaf);
        status = TDX_OPERAND_INVALID | TDX_OPERAND_ID_RAX;
        break;
    }
out:
    trace_tdx_emu_tdcall(leaf, status);
    env->regs[R_EAX] = status;
}
