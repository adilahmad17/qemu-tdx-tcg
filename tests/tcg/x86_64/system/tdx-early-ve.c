/*
 * Emulated TDX guest test: a #VE before the TD has installed an IDT ends in
 * a triple fault and a reset of the VM, as on real TDX hardware.
 *
 * Copyright (C) 2026 The ASTERISC Research Lab
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define TDX_EARLY_VE_TEST
#include "tdx-mem.c"
