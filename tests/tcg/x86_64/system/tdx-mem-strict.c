/*
 * Emulated TDX guest test: an access to a private page the TD has not
 * accepted stops a strict TD.
 *
 * Copyright (C) 2026 The ASTERISC Research Lab
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define TDX_MEM_STRICT_TEST
#include "tdx-mem.c"
