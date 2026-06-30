/*
 * Boot configuration for the ravynOS XNU EFI loader
 *
 * Copyright (C) 2025-2026 Vihaan Nathan
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef __CONFIG_H
#define __CONFIG_H

#include "loader.h"

/*
 * Values the loader reads from \ravynOS\com.ravynos.boot.plist.  This is not a
 * generic plist dictionary; it is just the handful of settings the loader
 * actually consumes.  To add a new setting, add a field here, a sane default in
 * gBootConfig, and a key match in StoreConfigValue() (config.c).
 */
typedef struct {
    CHAR8   BootArgs[1024];     // "boot-args"          -> BOOT_ARGS.CommandLine
    CHAR8   KernelPath[256];    // "kernel"             -> path the booter opens
    UINT8   BootUUID[16];       // "boot-uuid"          -> /ACPI platform-uuid
    BOOLEAN HasBootUUID;        // TRUE if a valid boot-uuid was parsed
    UINT32  CsrActiveConfig;    // "csr-active-config"  -> BOOT_ARGS.csrActiveConfig
} BOOT_CONFIG;

extern BOOT_CONFIG gBootConfig;

/* Load and parse the boot plist, updating gBootConfig in place. */
VOID LoadBootConfig(VOID);

#endif // __CONFIG_H
