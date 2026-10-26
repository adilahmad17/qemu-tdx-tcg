# qemu-tdx-tcg: emulated Intel TDX for QEMU TCG

A fork of QEMU 11.1.2 that runs an Intel TDX guest (a trust domain) in software, under the TCG
accelerator. It needs no TDX hardware and no KVM: the guest-side interface of TDX is provided by QEMU
itself, so a TD image boots on any x86_64 machine. The emulation was developed for the TDX host of the
[Saguaro](https://github.com/ASTERISC-Release/saguaro) library OS (ASTERISC Research Lab, ASU), whose
TDX PAL boots from td-shim.

Branches: `main` is the unmodified QEMU v11.1.2 tag; `dev-tdx` (the default) carries the emulation as
a series of commits on top of it.

## Features

- Object type `tdx-emu`, used like `tdx-guest`: `-accel tcg -M q35,confidential-guest-support=tdx0
  -object tdx-emu,id=tdx0 -bios td-shim.bin` (properties `gpaw` 48 or 52, `sept-ve-disable`, `debug`,
  `strict`, `enum-topology`). The TD boots from its firmware (td-shim, TDVF) at the TDX reset vector,
  with the initial vCPU state the TDX module gives (32-bit flat mode, EFER.LME, RBX = GPAW, RSI = vCPU
  index) and x2APIC enabled. TCG initialises the object when the machine starts.
- Guest-visible state: CPUID leaf 0x21 and the module's CPUID virtualization (fixed bits, leaf 0x15 with
  the TSC frequency, the TD_CTLS controls, the TSC-deadline timer), the TDX module's MSR classification.
- `TDCALL`: TDG.VP.INFO, VEINFO.GET, VM.RD/WR, VP.RD/WR, CPUIDVE.SET, MEM.PAGE.ACCEPT, MR.RTMR.EXTEND,
  MR.REPORT (a report without MAC: no attestation), and TDG.VP.VMCALL answered as KVM and QEMU answer it
  (CPUID, HLT, IO, RDMSR/WRMSR, MMIO, GetTdVmCallInfo, MapGPA, GetQuote as "no quote service",
  ReportFatalError, SetupEventNotifyInterrupt).
- `#VE` (vector 20) for the CPUID leaves, MSRs, port I/O, HLT, INVD, WBINVD and VMCALL the module does
  not virtualize; `#DF` when the previous one was not consumed.
- The shared bit in the page tables, MapGPA, page acceptance, MMIO as `#VE`, and the launch from the TD
  firmware (td-shim, TDVF) with the TD HOB; `strict=on` (the default) stops the VM where a real TD would
  be killed (an access to a page it has not accepted, for example), `strict=off` continues with a `#VE`.
- The build is x86_64 system emulation with TCG only (`CONFIG_TDX_EMU`, independent of KVM).

## Build

    ./build.sh --install-deps        # Ubuntu or Debian: installs the packages first
    ./build.sh                       # otherwise; --prefix DIR, --jobs N, --clean

`build.sh` configures QEMU for `x86_64-softmmu` without KVM, builds and installs into `prefix/` (or
`--prefix`), then checks that the `tdx-emu` object, the TCG accelerator and the ROMs are present and prints
how to use the result. The binary stays where it was installed: it finds its ROMs in `../share/qemu`.

## Tests

The emulation is tested by small TDX guests in `tests/tcg/x86_64/system/`: `tdx.c` (the TDCALL and
`#VE` interface), `tdx-mem.c` and `tdx-mem-strict.c` (the shared bit, MapGPA and page acceptance),
built around a reset-vector stub by `mktdxbios.py`, and `tdx-payload.c`, a payload for td-shim.

    make -C build/tests/tcg/x86_64-softmmu run-tdx run-tdx-mem run-tdx-mem-strict
    make -C build/tests/tcg/x86_64-softmmu TD_SHIM_DIR=<td-shim>/target/x86_64-unknown-none/release \
        TD_SHIM_LD=<td-shim>/target/release/td-shim-ld run-tdx-shim

`run-tdx-shim` boots td-shim with the payload when `TD_SHIM_DIR` and `TD_SHIM_LD` point at a td-shim
build (`cargo build -p td-shim --target x86_64-unknown-none --release --no-default-features
--features=main,tdx` and `cargo build -p td-shim-tools --release --features=linker`).

## Credits and license

QEMU is licensed under the GNU General Public License, version 2 or later (see `LICENSE`); the emulation
is contributed under the same terms. The conventions of the TDX guest interface (status codes, the
CPUID and MSR virtualization, the TD_CTLS controls) follow the public source of the Intel TDX module
(Intel, MIT license), which was read, not copied. The initialisation of an emulated confidential guest
from the TCG accelerator follows the idea of Tommaso Califano's TCG-SEV RFC (qemu-devel, 2026-03-17).
The emulation is by the ASTERISC Research Lab.
