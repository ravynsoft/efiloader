#ifndef __LOADER_H
#define __LOADER_H

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/FileHandleLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Guid/SmBios.h>
#include <Guid/Acpi.h>

/* XNU headers */
#include <mach-o/loader.h>
#include <i386/endian.h>

extern EFI_GUID gEfiDtbTableGuid;
extern EFI_GUID gEfiAcpiTableGuid;
extern EFI_GUID gEfiSmbios3TableGuid;
extern EFI_GUID gEfiSmbiosTableGuid;

#define UEFI_STR(s) ((CHAR16 *)u##s)

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

#define BIND_TYPE_THREADED_BIND 100
#define BIND_TYPE_THREADED_REBASE 102

UINT64 readULEB128(const UINT8 **p, const UINT8 *end);
INT64 readSLEB128(const UINT8 **p, const UINT8 *end);
void mapSegments(struct mach_header_64 *mh);

#endif // __LOADER_H
