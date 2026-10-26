/*
 * QEMU Intel TDX guest emulation for TCG (tdx-emu)
 *
 * A functional model of what a TD sees of the TDX module and its host VMM:
 * CPUID leaf 0x21, TDCALL, #VE, the TDG.VP.VMCALL interface. No attestation,
 * no memory encryption or isolation, no launch measurement.
 *
 * Copyright (C) 2026 The ASTERISC Research Lab
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef QEMU_I386_TDX_EMU_H
#define QEMU_I386_TDX_EMU_H

#include "qom/object.h"
#include "system/confidential-guest-support.h"
#include "confidential-guest.h"

#define TYPE_TDX_EMU "tdx-emu"
OBJECT_DECLARE_SIMPLE_TYPE(TdxEmuState, TDX_EMU)

/* VMX basic exit reasons that a #VE reports (Intel SDM Vol. 3, Appendix C) */
#define TDX_EXIT_REASON_CPUID           10
#define TDX_EXIT_REASON_HLT             12
#define TDX_EXIT_REASON_INVD            13
#define TDX_EXIT_REASON_RDPMC           15
#define TDX_EXIT_REASON_VMCALL          18
#define TDX_EXIT_REASON_IO_INSTRUCTION  30
#define TDX_EXIT_REASON_MSR_READ        31
#define TDX_EXIT_REASON_MSR_WRITE       32
#define TDX_EXIT_REASON_MWAIT           36
#define TDX_EXIT_REASON_MONITOR         39
#define TDX_EXIT_REASON_EPT_VIOLATION   48
#define TDX_EXIT_REASON_WBINVD          54

/* #VE categories (TDG.VP.VEINFO.GET version 1, RCX[39:32]) */
#define TDX_VE_CATEGORY_ARCH            0x00
#define TDX_VE_CATEGORY_PENDING         0x01
#define TDX_VE_CATEGORY_CONFIG_PARAVIRT 0x10
#define TDX_VE_CATEGORY_PARAVIRT        0x11
#define TDX_VE_CATEGORY_UNSUPPORTED     0x80

/* TD attributes (TDX Module ABI, TD_PARAMS.ATTRIBUTES) */
#define TDX_EMU_ATTR_DEBUG              (1ULL << 0)
#define TDX_EMU_ATTR_SEPT_VE_DISABLE    (1ULL << 28)

/* TDCS.TD_CTLS */
#define TDX_TD_CTLS_PENDING_VE_DISABLE  (1ULL << 0)
#define TDX_TD_CTLS_ENUM_TOPOLOGY       (1ULL << 1)
#define TDX_TD_CTLS_VIRT_CPUID2         (1ULL << 2)
#define TDX_TD_CTLS_REDUCE_VE           (1ULL << 3)
#define TDX_TD_CTLS_LOCK                (1ULL << 63)

struct TdxEmuState {
    X86ConfidentialGuest parent_obj;

    /* properties */
    uint32_t gpaw;              /* guest physical address width: 48 or 52 */
    uint64_t attributes;        /* TD attributes reported by TDG.VP.INFO */
    bool strict;                /* stop the VM on what would kill a real TD */

    /* TD-scope metadata (TDCS fields the guest may read or write) */
    uint64_t notify_enables;    /* TDCS.NOTIFY_ENABLES */
    uint64_t td_ctls;           /* TDCS.TD_CTLS */

    /* the TSC frequency the TD sees in CPUID leaf 0x15 */
    uint64_t tsc_khz;

    /* TDG.VP.VMCALL<SetupEventNotifyInterrupt> */
    int32_t event_notify_vector;
    int32_t event_notify_apicid;
};

#ifndef CONFIG_USER_ONLY
#include CONFIG_DEVICES /* CONFIG_TDX_EMU */
#endif

#if defined(CONFIG_TDX_EMU) && !defined(CONFIG_USER_ONLY)
extern TdxEmuState *tdx_emu_state;
static inline bool tdx_emu_enabled(void)
{
    return tdx_emu_state != NULL;
}
static inline uint64_t tdx_emu_td_ctls(void)
{
    return tdx_emu_state->td_ctls;
}
/*
 * Called by cpu_x86_cpuid() when the emulation is on: applies the TDX module's
 * CPUID virtualization (leaf 0x21, the maximum basic leaf, the fixed bits,
 * the TD_CTLS controls) to the leaf the guest asked for.
 */
void tdx_emu_cpuid(CPUX86State *env, uint32_t index, uint32_t count,
                   uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx);
/* The initial state of a TD vCPU (TDH.VP.INIT), applied at CPU reset. */
void tdx_emu_cpu_reset(X86CPU *cpu);
/* After the APIC reset: x2APIC mode, as the TDX module runs the TD. */
void tdx_emu_apic_reset(X86CPU *cpu);
#else
#define tdx_emu_enabled() 0
#define tdx_emu_td_ctls() 0
static inline void tdx_emu_cpuid(CPUX86State *env, uint32_t index,
                                 uint32_t count, uint32_t *eax, uint32_t *ebx,
                                 uint32_t *ecx, uint32_t *edx)
{
}
static inline void tdx_emu_cpu_reset(X86CPU *cpu)
{
}
static inline void tdx_emu_apic_reset(X86CPU *cpu)
{
}
#endif

#endif /* QEMU_I386_TDX_EMU_H */
