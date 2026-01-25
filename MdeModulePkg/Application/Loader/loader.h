/*
 * Copyright (C) 2025 Zoe Knox <zoe@pixin.net>
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

#ifndef __LOADER_H
#define __LOADER_H

/* host headers */
#if defined(__linux__)
# if defined(__x86_64__) || defined(__arm64__)
#  define __LITTLE_ENDIAN__ 1
# else
#  error Unknown endianness
# endif
# if defined(__GCC__)
#  error GCC is defined
# endif
#else
# include <i386/endian.h>
#endif

/* application headers */
#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/FileHandleLib.h>
#include <Library/PrintLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/Rng.h>
#include <Guid/SmBios.h>
#include <Guid/Acpi.h>

/* SDK headers */
#include <mach-o/loader.h>

extern EFI_GUID gEfiDtbTableGuid;
extern EFI_GUID gEfiAcpiTableGuid;
extern EFI_GUID gEfiSmbios3TableGuid;
extern EFI_GUID gEfiSmbiosTableGuid;
extern EFI_GUID gEfiRngProtocolGuid;

#define UEFI_STR(s) ((CHAR16 *)u##s)
#define GB (1024*1024*1024)
#define MB (1024*1024)
#define KB 1024
#define ENTROPY_SIZE 64

// Bitfields for boot_args->flags
#define kBootArgsFlagRebootOnPanic      (1 << 0)
#define kBootArgsFlagHiDPI              (1 << 1)
#define kBootArgsFlagBlack              (1 << 2)
#define kBootArgsFlagCSRActiveConfig    (1 << 3)
#define kBootArgsFlagCSRConfigMode      (1 << 4)
#define kBootArgsFlagCSRBoot            (1 << 5)
#define kBootArgsFlagBlackBg            (1 << 6)
#define kBootArgsFlagLoginUI            (1 << 7)
#define kBootArgsFlagInstallUI          (1 << 8)

// 'display' modes
#define GRAPHICS_MODE         1
#define FB_TEXT_MODE          2

#define ARGS_ADDR 0x5000000 // 80 MB - where we stash FDT and boot args

typedef struct {
    UINT32 baseAddr;
    UINT32 display;
    UINT32 bytesPerRow;
    UINT32 width;
    UINT32 height;
    UINT32 depth;
} VIDEO_INFO;

typedef struct {
    UINT32 display;
    UINT32 bytesPerRow;
    UINT32 width;
    UINT32 height;
    UINT32 depth;
    UINT8 rotate;
    UINT8 reserved0[3];
    UINT32 reserved1[6];
    UINT64 baseAddr;
} VIDEO_BOOT;

typedef struct {
    UINT16 Revision; // must be 0x0
    UINT16 Version; // must be 0x2
    UINT8 EFIMode; // 32 or 64
    UINT8 DebugMode; // bitfield
    UINT16 Flags;   // see boot flags above
    CHAR8 CommandLine[1024];
    UINT32 MemoryMap; // physical addr
    UINT32 MemoryMapSize;
    UINT32 MemoryMapDescriptorSize;
    UINT32 MemoryMapDescriptorVersion;
    VIDEO_INFO VideoV1;
    UINT32 DeviceTree;
    UINT32 DeviceTreeLength;
    UINT32 kaddr; // physical addr of kernel __TEXT
    UINT32 ksize; // kernel text + data + EFI
    UINT32 efiRuntimeServicesPageStart;
    UINT32 efiRuntimeServicesPageCount;
    UINT64 efiRuntimeServicesVirtualPageStart;
    UINT32 efiSystemTable;
    UINT32 kslide;
    UINT32 perfDataStart; // physical addr of log
    UINT32 perfDataSize;
    UINT32 keystoreDataStart;
    UINT32 keystoreDataSize;
    UINT64 bootMemStart;
    UINT64 bootMemSize;
    UINT64 physMemSize;
    UINT64 FSBFreq;
    UINT64 pciConfigSpaceBaseAddr;
    UINT32 pciConfigSpaceStartBusNumber;
    UINT32 pciConfigSpaceEndBusNumber;
    UINT32 csrActiveConfig;
    UINT32 csrCapabilities;
    UINT32 boot_smc_plimit;
    UINT16 bootProgressMeterStart;
    UINT16 bootProgressMeterEnd;
    VIDEO_BOOT Video;
    UINT32 APFSDataStart;
    UINT32 APFSDataSize;
    UINT32 _reserved[710];
} BOOT_ARGS;
extern char assert_boot_args_size_is_4096[sizeof(BOOT_ARGS) == 4096 ? 1 : -1];

// this is the FDT v17 header, but xnu doesn't use it
typedef struct {
    UINT32 magic;
    UINT32 totalsize;
    UINT32 off_dt_struct;
    UINT32 off_dt_strings;
    UINT32 off_mem_rsvmap;
    UINT32 version;
    UINT32 last_comp_version;
    UINT32 boot_cpuid_phys;
    UINT32 size_dt_strings;
    UINT32 size_dt_struct;
} FDT_HDR;

#define FDT_PROPNAME_MAX 32   // max length is 31 + null byte

// a XNU FDT node
typedef struct {
    UINT32 nProp;
    UINT32 nChildren;
    /* properties[nProp] */
    /* nodes[nChildren] */
} FdtNode;

// a XNU FDT property
typedef struct {
    CHAR8 name[FDT_PROPNAME_MAX];
    UINT32 length; // size of following data, aligned(4)
    /* data x length bytes */
} FdtProperty;

#define BIND_TYPE_THREADED_BIND 100
#define BIND_TYPE_THREADED_REBASE 102

UINT64 readULEB128(const UINT8 **p, const UINT8 *end);
INT64 readSLEB128(const UINT8 **p, const UINT8 *end);
int mapSegments(struct mach_header_64 *mh, UINTN *entry, EFI_FILE_HANDLE KernelFile);

UINTN BuildDTBFromACPI(VOID *ACPI, VOID *DTB);

FdtNode *FdtCreateEmpty(VOID);
EFI_STATUS FdtCreateNode(FdtNode *root, CHAR8 *ParentPath, CHAR8 *Name);
EFI_STATUS FdtSetProperty(FdtNode *root, CHAR8 *NodePath, CHAR8 *Name, VOID *Data, UINT32 Len);
CHAR8 *FdtGetProperty(FdtNode *root, CHAR8 *NodePtr, CHAR8 *Name, UINT32 *OutLen);
CHAR8 *FdtFindNode(FdtNode *root, CHAR8 *Path);
VOID FdtDump(FdtNode *root);

#endif // __LOADER_H
