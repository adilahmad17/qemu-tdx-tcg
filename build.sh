#!/usr/bin/env bash
# build.sh -- build the QEMU with the emulated Intel TDX guest (branch dev-tdx)
#
# The emulation runs under TCG, without TDX hardware and without KVM. Everything goes to one prefix:
# bin/qemu-system-x86_64 and share/qemu (the ROMs and firmware QEMU looks for next to the binary,
# which is why the binary must stay where it was installed).
#
#   ./build.sh [--prefix DIR] [--jobs N] [--install-deps] [--clean]
#
#   --prefix DIR     install prefix (default: <this directory>/prefix)
#   --jobs N         parallel jobs (default: all CPUs)
#   --install-deps   install the Ubuntu/Debian packages the build needs first (apt-get, sudo unless root)
#   --clean          remove the build directory first
#
# Needs: a C toolchain, git (QEMU fetches a small subproject), ninja, python3 with venv, pkg-config
# and the glib, pixman, slirp and fdt development packages. When it finishes it checks the result
# and prints how to use it.
set -euo pipefail

HERE=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
PREFIX=$HERE/prefix
JOBS=$(nproc)
DEPS=0
CLEAN=0
APT_PACKAGES="build-essential ninja-build python3 python3-venv pkg-config libglib2.0-dev libpixman-1-dev
              libslirp-dev libfdt-dev flex bison git"

while [ $# -gt 0 ]; do
    case $1 in
        --prefix) PREFIX=$(readlink -m "${2:?--prefix needs a directory}"); shift ;;
        --jobs) JOBS=${2:?--jobs needs a number}; shift ;;
        --install-deps) DEPS=1 ;;
        --clean) CLEAN=1 ;;
        -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
        *) echo "build.sh: unknown argument: $1 (--help)" >&2; exit 2 ;;
    esac
    shift
done

BUILD=$HERE/build
log() { echo ">>> $*"; }
die() { echo "build.sh: $*" >&2; exit 1; }

if [ $DEPS = 1 ]; then
    command -v apt-get >/dev/null || die "--install-deps needs apt-get (Ubuntu or Debian)"
    sudo=; [ "$(id -u)" = 0 ] || sudo=sudo
    log "installing packages"
    $sudo apt-get update -qq
    # shellcheck disable=SC2086
    $sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $APT_PACKAGES
fi

missing=
for c in gcc make ninja pkg-config python3 flex bison git; do
    command -v "$c" >/dev/null || missing="$missing $c"
done
for p in glib-2.0 pixman-1 slirp; do
    pkg-config --exists "$p" 2>/dev/null || missing="$missing lib:$p"
done
python3 -c 'import venv, ensurepip' 2>/dev/null || missing="$missing python3-venv"
[ -z "$missing" ] || die "missing:$missing (on Ubuntu or Debian: ./build.sh --install-deps)"

[ $CLEAN = 0 ] || { log "cleaning"; rm -rf "$BUILD"; }
mkdir -p "$PREFIX"

# QEMU: x86_64 system emulation with TCG only. The emulated TDX guest does not use KVM, so KVM is
# left out of the build; the result runs on any machine.
log "configuring QEMU"
mkdir -p "$BUILD"
cd "$BUILD"
# a shallow checkout (a git submodule) has no tags for `git describe`: name the revision explicitly
PKGVERSION=
if rev=$(git -C "$HERE" rev-parse --short=10 HEAD 2>/dev/null); then PKGVERSION="--with-pkgversion=g$rev"; fi
../configure --prefix="$PREFIX" $PKGVERSION --target-list=x86_64-softmmu --enable-tcg --disable-kvm --enable-slirp \
    --disable-docs --disable-werror --disable-xen --disable-gtk --disable-sdl --disable-vnc \
    --disable-opengl --disable-virglrenderer
log "building QEMU ($JOBS jobs)"
make -j"$JOBS"
log "installing into $PREFIX"
make install

# check the result: the binary, the tdx-emu object, TCG and the ROMs the guest needs
Q=$PREFIX/bin/qemu-system-x86_64
[ -x "$Q" ] || die "$Q was not built"
for rom in bios-256k.bin kvmvapic.bin efi-e1000e.rom; do
    [ -f "$PREFIX/share/qemu/$rom" ] || die "$PREFIX/share/qemu/$rom is missing: the guest could not start"
done
"$Q" -object help 2>/dev/null | grep -qx "  tdx-emu" || die "$Q has no 'tdx-emu' object: is this the dev-tdx branch?"
"$Q" -accel help 2>/dev/null | grep -qx tcg || die "$Q has no TCG accelerator"

version=$("$Q" --version | sed -n '1s/^QEMU emulator version //p')
echo
log "done: QEMU $version"
echo "  $Q"
echo
echo "Use it (keep the binary where it is: it finds its ROMs in ../share/qemu):"
echo "  $Q -accel tcg -M q35,confidential-guest-support=tdx0 -object tdx-emu,id=tdx0 -cpu max -bios <td-shim image> ..."
echo "  with Saguaro: export SAGUARO_ACCEL=tcg QEMU_PATH=$Q"
echo "  tests: make -C $BUILD/tests/tcg/x86_64-softmmu run-tdx run-tdx-mem run-tdx-mem-strict"
