#include "loader.h"

#define VERSION_STR UEFI_STR("v0.3 IN DEVELOPMENT")
#define KERNEL_LOAD_ADDRESS 0x100000;
#define STACK_SIZE 128

EFI_GUID gEfiDtbTableGuid = {0xb1b621d5, 0xf19c, 0x41a5, \
        {0x83, 0x0b, 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0}};
EFI_GUID gEfiAcpiTableGuid = EFI_ACPI_20_TABLE_GUID;
EFI_GUID gEfiSmbios3TableGuid = SMBIOS3_TABLE_GUID;
EFI_GUID gEfiSmbiosTableGuid = SMBIOS_TABLE_GUID;


// --- Load kernelcache from filesystem ---
EFI_STATUS LoadKernel(VOID **KernelBuffer, UINTN *KernelEntry)
{
    EFI_STATUS Status;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs;
    EFI_FILE_HANDLE Root, KernelFile;
    struct mach_header_64 *MachHeader;

    *KernelBuffer = (VOID *)KERNEL_LOAD_ADDRESS;
    Status = gBS->AllocatePages(AllocateAddress, EfiLoaderData,
        EFI_SIZE_TO_PAGES(16384), (EFI_PHYSICAL_ADDRESS *)*KernelBuffer);
    if(EFI_ERROR(Status)) {
        Print(UEFI_STR("Failed to allocate memory: %r\n"), Status);
        return Status;
    }

    Status = gBS->LocateProtocol(&gEfiSimpleFileSystemProtocolGuid, NULL, (VOID**)&Fs);
    if (EFI_ERROR(Status))
        return Status;

    Status = Fs->OpenVolume(Fs, &Root);
    if (EFI_ERROR(Status))
        return Status;

    Status = Root->Open(Root, &KernelFile, UEFI_STR("kernel"), EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(Status)) {
        Root->Close(Root);
        return Status;
    }

    UINT64 size = sizeof(struct mach_header_64);
    Status = KernelFile->Read(KernelFile, &size, (EFI_PHYSICAL_ADDRESS *)(*KernelBuffer));
    MachHeader = (struct mach_header_64 *)(*KernelBuffer);
    if(EFI_ERROR(Status) 
        || MachHeader->filetype != MH_EXECUTE
        || (MachHeader->cputype != CPU_TYPE_X86_64 && MachHeader->cputype != (unsigned)CPU_TYPE_ANY))
    {
        if(EFI_ERROR(Status))
            Print(UEFI_STR("Read Error: %r\n"), Status);
        else {
            Print(UEFI_STR("Incorrect Mach file header\n"));
            Status = EFI_UNSUPPORTED;
        }
        return Status;
    }

    Print(UEFI_STR("\n:: Mach-O %u-bit %s executable. Flags: %04x [%u commands, %u bytes]\n"),
        MachHeader->magic == MH_MAGIC_64 ? 64 : 32,
        MachHeader->cputype == CPU_TYPE_X86_64 ? UEFI_STR("x86-64") : UEFI_STR("i386"),
        MachHeader->flags, MachHeader->ncmds, MachHeader->sizeofcmds);

    *KernelBuffer += size;
    size = MachHeader->sizeofcmds;
    Status = KernelFile->Read(KernelFile, &size, (EFI_PHYSICAL_ADDRESS *)(*KernelBuffer));
    size = mapSegments(MachHeader, KernelEntry, KernelFile);

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
    UINTN KernelEntry = 0;
    EFI_HANDLE SMBIOSHandle, ACPIHandle, DTBHandle;
    VOID *SMBIOS = NULL; // SMBIOS table pointer
    VOID *ACPI = NULL; // ACPI table pointer
    VOID *DTB = NULL; // Device Table Blob pointer
    UINTN MapKey, DescriptorSize;
    UINT32 DescriptorVersion;
    EFI_MEMORY_DESCRIPTOR *MemoryMap = NULL;
    UINTN MemoryMapSize = 0;
    UINT8 *region = NULL;
    UINT64 physPages = 0;

    gST->ConOut->ClearScreen(gST->ConOut);
    Print(UEFI_STR(":: ravynOS EFI Loader %s\n\n"), VERSION_STR);

    EFI_CONFIGURATION_TABLE *table = SystemTable->ConfigurationTable;
    for(int i = 0; i < SystemTable->NumberOfTableEntries; ++i) {
        EFI_GUID guid = table[i].VendorGuid;
        if(CompareGUIDs(guid, gEfiSmbiosTableGuid) == 0 || CompareGUIDs(guid, gEfiSmbios3TableGuid) == 0) {
            SMBIOS = table[i].VendorTable;
            Print(UEFI_STR("[] Found SMBIOS table at 0x%p\n"), SMBIOS);
        }
        else if(CompareGUIDs(guid, gEfiAcpiTableGuid) == 0) {
            ACPI = table[i].VendorTable;
            Print(UEFI_STR("[] Found ACPI table at 0x%p\n"), ACPI);
        }
        else if(CompareGUIDs(guid, gEfiDtbTableGuid) == 0) {
            DTB = table[i].VendorTable;
            Print(UEFI_STR("[] Found DTB table at 0x%p\n"), DTB);
        }
    }

    Status = gBS->GetMemoryMap(&MemoryMapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
    if (Status == EFI_BUFFER_TOO_SMALL) {
        MemoryMap = AllocatePool(MemoryMapSize);
        Status = gBS->GetMemoryMap(&MemoryMapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
    }
    if (EFI_ERROR(Status)) {
        Print(UEFI_STR("!! Error: failed to retrieve memory map [%r]\n"), Status);
        return Status;
    }

    for(region = MemoryMap; region < ((UINT8 *)MemoryMap + MemoryMapSize); region += DescriptorSize) {
        switch(((EFI_MEMORY_DESCRIPTOR *)region)->Type) {
            case EfiConventionalMemory:
            case EfiBootServicesCode:
            case EfiBootServicesData:
            case EfiLoaderCode:
            case EfiLoaderData:
                physPages += ((EFI_MEMORY_DESCRIPTOR *)region)->NumberOfPages;
                break;
        }
    }

    LoadDrivers(ImageHandle);
    Status = LoadKernel(&KernelBuffer, &KernelEntry);
    if (EFI_ERROR(Status))
        return Status;

    VIDEO_INFO videoV1 = {0};
    VIDEO_BOOT video = {0};

    BOOT_ARGS BootArgs;
    SetMem(&BootArgs, sizeof(BootArgs), 0);
    BootArgs.Version = 2;
    BootArgs.EFIMode = 32;
    BootArgs.Flags = kBootArgsFlagHiDPI;
    AsciiStrCpyS(BootArgs.CommandLine, 1024, "-v -s");
    BootArgs.VideoV1 = videoV1;
    BootArgs.DeviceTree = 0;
    BootArgs.DeviceTreeLength = 0;
    BootArgs.kaddr = KERNEL_LOAD_ADDRESS;
    BootArgs.ksize = 0; // FIXME: KernelSize
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

    BootArgs.MemoryMap = (UINT32)MemoryMap;
    BootArgs.MemoryMapSize = MemoryMapSize;
    BootArgs.MemoryMapDescriptorSize = DescriptorSize;
    BootArgs.MemoryMapDescriptorVersion = DescriptorVersion;
    BootArgs.physMemSize = physPages * EFI_PAGE_SIZE; // convert to bytes

    Print(UEFI_STR("%u MB usable memory found\n\n"), BootArgs.physMemSize/1024/1024);

    typedef void (*XnuEntry)(void);
    XnuEntry _start = (XnuEntry)(KernelEntry);
    Print(UEFI_STR(">>> Jumping to 0x%lx\n"), KernelEntry);
    asm(
        "movq %0, %%rax\n"
        "movq %1, %%rdi\n"
        "jmpq *%%rdi\n"
        : : "mr"(&BootArgs), "r"(KernelEntry) : "rax", "rdi" // pass to xnu in eax
    );
    _start();

    while(1);
    return EFI_SUCCESS;
}
