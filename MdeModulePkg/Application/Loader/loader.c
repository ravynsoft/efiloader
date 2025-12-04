#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/FileHandleLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Guid/SmBios.h>
#include <Guid/Acpi.h>

EFI_GUID gEfiDtbTableGuid = {0xb1b621d5, 0xf19c, 0x41a5, \
        {0x83, 0x0b, 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0}};
EFI_GUID gEfiAcpiTableGuid = EFI_ACPI_20_TABLE_GUID;
EFI_GUID gEfiSmbios3TableGuid = SMBIOS3_TABLE_GUID;
EFI_GUID gEfiSmbiosTableGuid = SMBIOS_TABLE_GUID;

#define VERSION_STR UEFI_STR("v0.2 IN DEVELOPMENT")
#define KERNEL_LOAD_ADDRESS 0x40000000 // 1 GB
#define STACK_SIZE 128

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

// --- Load kernelcache from filesystem ---
EFI_STATUS LoadKernel(VOID **KernelBuffer, UINTN *KernelSize)
{
    EFI_STATUS Status;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs;
    EFI_FILE_HANDLE Root, KernelFile;

    Status = gBS->LocateProtocol(&gEfiSimpleFileSystemProtocolGuid, NULL, (VOID**)&Fs);
    if (EFI_ERROR(Status))
        return Status;

    Print(UEFI_STR("open volume\n"));
    Status = Fs->OpenVolume(Fs, &Root);
    if (EFI_ERROR(Status))
        return Status;

    Print(UEFI_STR("open kernel file\n"));
    Status = Root->Open(Root, &KernelFile, UEFI_STR("kernel"), EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(Status)) {
        Root->Close(Root);
        return Status;
    }

    Print(UEFI_STR("allocate zero pool\n"));
    EFI_FILE_INFO *FileInfo = AllocateZeroPool(sizeof(EFI_FILE_INFO) + 512);
    if (!FileInfo) {
        KernelFile->Close(KernelFile);
        Root->Close(Root);
        return EFI_OUT_OF_RESOURCES;
    }

    Print(UEFI_STR("file info\n"));
    UINTN FileInfoSize = sizeof(EFI_FILE_INFO) + 512;
    Status = KernelFile->GetInfo(KernelFile, &gEfiFileInfoGuid, &FileInfoSize, FileInfo);
    if (EFI_ERROR(Status)) {
        KernelFile->Close(KernelFile);
        Root->Close(Root);
        return Status;
    }

    Print(UEFI_STR("allocate pages\n"));
    *KernelSize = FileInfo->FileSize;
    *KernelBuffer = (VOID*)KERNEL_LOAD_ADDRESS;
    Status = gBS->AllocatePages(AllocateAddress, EfiLoaderData,
        EFI_SIZE_TO_PAGES(*KernelSize), (EFI_PHYSICAL_ADDRESS*)KernelBuffer);
    if (EFI_ERROR(Status)) {
        KernelFile->Close(KernelFile);
        Root->Close(Root);
        return Status;
    }

    Print(UEFI_STR("reading /kernel to buffer\n"));
    Status = KernelFile->Read(KernelFile, KernelSize, *KernelBuffer);
    KernelFile->Close(KernelFile);
    Root->Close(Root);
    return EFI_SUCCESS;
}

// --- Load any necessary file system drivers before reading kernel ---
EFI_STATUS LoadDrivers(EFI_HANDLE ImageHandle)
{
    EFI_STATUS Status;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs;
    EFI_FILE_HANDLE Root, ravynOS, driverHandle;
    EFI_DEVICE_PATH devicePath;

    Status = gBS->LocateProtocol(&gEfiSimpleFileSystemProtocolGuid, NULL, (VOID**)&Fs);
    if (EFI_ERROR(Status))
        return Status;

    Status = Fs->OpenVolume(Fs, &Root);
    if (EFI_ERROR(Status))
        return Status;

    Status = Root->Open(Root, &ravynOS, UEFI_STR("\\EFI\\ravynOS"), EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(Status)) {
        Root->Close(Root);
        return Status;
    }
    
    // get devicePath from ravynOS->Read(), iterating all drivers
    //gBS->LoadImage(0, ImageHandle, devicePath, NULL, 0, &driverHandle);

    ravynOS->Close(ravynOS);
    Root->Close(Root);
    return EFI_SUCCESS;
}

INT32 CompareGUIDs(EFI_GUID guid1, EFI_GUID guid2)
{
    char *a = (char *)&guid1;
    char *b = (char *)&guid2;

    for(int i = 0; i < 16; ++i) {
        if(*a < *b) return -1;
        if(*a > *b) return 1;
        ++a;
        ++b;
    }

    return 0;
}

EFI_STATUS EFIAPI UefiMain(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable)
{
    EFI_STATUS Status;
    VOID *KernelBuffer = NULL;
    UINTN KernelSize = 0;
    EFI_HANDLE SMBIOSHandle, ACPIHandle, DTBHandle;
    VOID *SMBIOS = NULL; // SMBIOS table pointer
    VOID *ACPI = NULL; // ACPI table pointer
    VOID *DTB = NULL; // Device Table Blob pointer

    gST->ConOut->ClearScreen(gST->ConOut);
    Print(UEFI_STR(":: ravynOS EFI Loader %s\n\n"), VERSION_STR);

    EFI_CONFIGURATION_TABLE *table = SystemTable->ConfigurationTable;
    for(int i = 0; i < SystemTable->NumberOfTableEntries; ++i) {
        EFI_GUID guid = table[i].VendorGuid;
        if(CompareGUIDs(guid, gEfiSmbiosTableGuid) == 0 || CompareGUIDs(guid, gEfiSmbios3TableGuid) == 0) {
            SMBIOS = table[i].VendorTable;
            Print(UEFI_STR("Found SMBIOS table at 0x%p\n"), SMBIOS);
        }
        else if(CompareGUIDs(guid, gEfiAcpiTableGuid) == 0) {
            ACPI = table[i].VendorTable;
            Print(UEFI_STR("Found ACPI table at 0x%p\n"), ACPI);
        }
        else if(CompareGUIDs(guid, gEfiDtbTableGuid) == 0) {
            DTB = table[i].VendorTable;
            Print(UEFI_STR("Found DTB table at 0x%p\n"), DTB);
        }
    }

    Print(UEFI_STR("Looking for drivers\n"));
    LoadDrivers(ImageHandle);

    // --- Load kernelcache ---
    Status = LoadKernel(&KernelBuffer, &KernelSize);
    if (EFI_ERROR(Status)) {
        Print(UEFI_STR("Failed to load kernel: %r\n"), Status);
        return Status;
    }
    Print(UEFI_STR("Kernel loaded: %u bytes at 0x%p\n"), KernelSize, KernelBuffer);

    VIDEO_INFO videoV1 = {0};
    VIDEO_BOOT video = {0};

    // --- Prepare boot_args ---
    BOOT_ARGS BootArgs;
    SetMem(&BootArgs, sizeof(BootArgs), 0);
    BootArgs.Version = 2;
    BootArgs.EFIMode = 32;
    BootArgs.Flags = kBootArgsFlagHiDPI;
    AsciiStrCpyS(BootArgs.CommandLine, 1024, "-v -s BootGraphics=No");
    BootArgs.VideoV1 = videoV1;
    BootArgs.DeviceTree = 0;
    BootArgs.DeviceTreeLength = 0;
    BootArgs.kaddr = KERNEL_LOAD_ADDRESS;
    BootArgs.ksize = KernelSize;
    BootArgs.kslide = 0;
    BootArgs.efiRuntimeServicesPageStart = (UINT32)(SystemTable->RuntimeServices);
    UINT32 size = SystemTable->RuntimeServices->Hdr.HeaderSize - sizeof(EFI_TABLE_HEADER);
    UINT32 pages = size / EFI_PAGE_SIZE + 1;
    BootArgs.efiRuntimeServicesPageCount = pages;
    BootArgs.efiRuntimeServicesVirtualPageStart = 0;
    BootArgs.efiSystemTable = (UINT32)SystemTable;
    BootArgs.perfDataStart = 0;
    BootArgs.perfDataSize = 0;
    BootArgs.keystoreDataStart = 0;
    BootArgs.keystoreDataSize = 0;
    BootArgs.bootMemStart = 0; // is this the addr of this loader? of bootservices?
    BootArgs.bootMemSize = 0;
    BootArgs.Video = video;

    // BootArgs.FSBFreq = no idea what it should be
    // BootArgs.pciConfigSpaceBaseAddr = 
    // BootArgs.pciConfigSpaceStartBusNumber = 
    // BootArgs.pciConfigSpaceEndBusNumber =
    // BootArgs.csrActiveConfig = 
    // BootArgs.csrCapabilities =
    // BootArgs.boot_smc_plimit =
    // BootArgs.bootProgressMeterStart =
    // BootArgs.bootProgressMeterEnd =    
    // BootArgs.APFSDataStart =
    // BootArgs.APFSDataSize =

    // --- Get memory map ---
    UINTN MapKey, DescriptorSize;
    UINT32 DescriptorVersion;
    EFI_MEMORY_DESCRIPTOR *MemoryMap = NULL;
    UINTN MemoryMapSize = 0;
    UINT8 *region = NULL;

    Status = gBS->GetMemoryMap(&MemoryMapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
    if (Status == EFI_BUFFER_TOO_SMALL) {
        MemoryMap = AllocatePool(MemoryMapSize);
        Status = gBS->GetMemoryMap(&MemoryMapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
    }
    if (EFI_ERROR(Status)) {
        Print(UEFI_STR("Memory map error: %r\n"), Status);
        return Status;
    }

    BootArgs.MemoryMap = (UINT32)MemoryMap;
    BootArgs.MemoryMapSize = MemoryMapSize;
    BootArgs.MemoryMapDescriptorSize = DescriptorSize;
    BootArgs.MemoryMapDescriptorVersion = DescriptorVersion;

    for(region = MemoryMap; region < ((UINT8 *)MemoryMap + MemoryMapSize); region += DescriptorSize) {
        if(((EFI_MEMORY_DESCRIPTOR *)region)->Type == EfiConventionalMemory)
            BootArgs.physMemSize += ((EFI_MEMORY_DESCRIPTOR *)region)->NumberOfPages;
    }
    BootArgs.physMemSize = BootArgs.physMemSize * EFI_PAGE_SIZE; // convert to bytes

    Print(UEFI_STR("%u MB usable memory found\n\n"), BootArgs.physMemSize/1024/1024);

    typedef void (*XnuEntry)(void);
    XnuEntry KernelEntry = (XnuEntry)((UINT64)KernelBuffer);
    Print(UEFI_STR(">>> Jumping to 0x%lx\n"), (UINT64)(KernelEntry));
    asm(
        "movq %0, %%rax\n"
        "movq %1, %%rdi\n"
        "jmpq *%%rdi\n"
        : : "mr"(&BootArgs), "mr"(KernelBuffer) : "rax", "rdi" // pass to xnu in eax
    );
    KernelEntry();

    while(1);
    return EFI_SUCCESS;
}
