/*
 * Copyright (C) 2025-2026 Zoe Knox <zoe@pixin.net>
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

#include "loader.h"

#define VERSION_STR UEFI_STR("v0.6 IN DEVELOPMENT")
#define KERNEL_LOAD_ADDRESS 0x100000; // 1 MB

EFI_GUID gEfiDtbTableGuid = {0xb1b621d5, 0xf19c, 0x41a5, \
        {0x83, 0x0b, 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0}};
EFI_GUID gEfiAcpiTableGuid = EFI_ACPI_20_TABLE_GUID;
EFI_GUID gEfiSmbios3TableGuid = SMBIOS3_TABLE_GUID;
EFI_GUID gEfiSmbiosTableGuid = SMBIOS_TABLE_GUID;
EFI_GUID gEfiRngProtocolGuid = EFI_RNG_PROTOCOL_GUID;

CHAR8 cmdLine[1024];

EFI_STATUS GetVideoInfo(VIDEO_INFO *v1, VIDEO_BOOT *v)
{
    EFI_STATUS Status;
    EFI_GRAPHICS_OUTPUT_PROTOCOL *GOP;

    Status = gBS->LocateProtocol(&gEfiGraphicsOutputProtocolGuid, NULL, (VOID**)&GOP);
    if (EFI_ERROR(Status))
        return Status;

    EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE *mode = GOP->Mode;
    EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *info = mode->Info;
    Print(UEFI_STR("[] Framebuffer: %dx%dx32 %d MB at 0x%lx\n"),
        info->HorizontalResolution, info->VerticalResolution,
        mode->FrameBufferSize / MB, mode->FrameBufferBase);

    v1->baseAddr = mode->FrameBufferBase;
    v1->display = GRAPHICS_MODE;
    v1->bytesPerRow = info->PixelsPerScanLine * 4; // UEFI only has RGBA, BGRA, or mono
    v1->width = info->HorizontalResolution;
    v1->height = info->VerticalResolution;
    v1->depth = 4;

    v->display = GRAPHICS_MODE;
    v->bytesPerRow = info->PixelsPerScanLine * 4;
    v->width = info->HorizontalResolution;
    v->height = info->VerticalResolution;
    v->depth = 4;
    v->rotate = 0;
    v->baseAddr = mode->FrameBufferBase;

    return EFI_SUCCESS;
}

EFI_STATUS LoadKernel(VOID **KernelBuffer, UINTN *KernelEntry, UINTN *KernelSize)
{
    EFI_STATUS Status;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs;
    EFI_FILE_HANDLE Root, KernelFile;
    struct mach_header_64 *MachHeader = (VOID *)MH_ADDR;

    Status = gBS->LocateProtocol(&gEfiSimpleFileSystemProtocolGuid, NULL, (VOID**)&Fs);
    if (EFI_ERROR(Status))
        return Status;

    Status = Fs->OpenVolume(Fs, &Root);
    if (EFI_ERROR(Status))
        return Status;

    Status = Root->Open(Root, &KernelFile, UEFI_STR("\\ravynOS\\kernel"), EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(Status)) {
        Root->Close(Root);
        return Status;
    }

    UINT64 size = sizeof(struct mach_header_64);
    Status = KernelFile->Read(KernelFile, &size, (EFI_PHYSICAL_ADDRESS *)MachHeader);
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

    size += MachHeader->sizeofcmds;
    KernelFile->SetPosition(KernelFile, 0);
    Status = KernelFile->Read(KernelFile, &size, (EFI_PHYSICAL_ADDRESS *)MachHeader);

    if(!EFI_ERROR(Status)) {
        *KernelBuffer = (VOID *)KERNEL_LOAD_ADDRESS;
        *KernelSize = mapSegments(MachHeader, KernelEntry, KernelFile);
    }

    KernelFile->Close(KernelFile);
    Root->Close(Root);
    return Status;
}

// --- Load any necessary file system drivers before reading kernel ---
EFI_STATUS LoadDrivers(EFI_HANDLE ImageHandle)
{
    EFI_STATUS Status;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs;
    EFI_FILE_HANDLE Root, ravynOS /*, driverHandle*/ ;
    /* EFI_DEVICE_PATH devicePath; */

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

#define SET_BUFFER(x) CopyMem(buffer, x, AsciiStrSize(x))
FdtNode *InitDTB(EFI_SYSTEM_TABLE *SystemTable)
{
    EFI_STATUS Status;
    UINT8 buffer[256];
    UINT8 entropy[ENTROPY_SIZE];
    UINT64 val64;
    UINT32 val;
    EFI_RNG_PROTOCOL *RNG = 0;

    FdtNode *DTB = FdtCreateEmpty();
    if(!DTB)
        return NULL;

    Status = gBS->LocateProtocol(&gEfiRngProtocolGuid, NULL, (VOID**)&RNG);
    if(EFI_ERROR(Status))
        Print(UEFI_STR("!! Failed to find entropy source: %r\n"), Status); // kernel will panic
    else
        RNG->GetRNG(RNG, NULL, ENTROPY_SIZE, entropy);

    FdtCreateNode(DTB, "/", "cpus");
    FdtCreateNode(DTB, "/", "memory");

    FdtCreateNode(DTB, "/", "chosen");
    FdtSetProperty(DTB, "/chosen", "random-seed", entropy, ENTROPY_SIZE);
    FdtCreateNode(DTB, "/chosen", "memory-map");
    FdtCreateNode(DTB, "/chosen", "osenvironment");
    FdtCreateNode(DTB, "/chosen", "ephemeral-storage");
    FdtCreateNode(DTB, "/chosen", "use-recovery-securityd");

    val = 1024;
    FdtCreateNode(DTB, "/", "defaults");
    FdtSetProperty(DTB, "/defaults", "kern.max_task_pmem", &val, 4);
    
    FdtCreateNode(DTB, "/", "efi");
    FdtSetProperty(DTB, "/efi", "firmware-revision", &SystemTable->FirmwareRevision, 4);
    FdtSetProperty(DTB, "/efi", "firmware-vendor", SystemTable->FirmwareVendor, StrSize(SystemTable->FirmwareVendor));
    SET_BUFFER("EFI64");
    FdtSetProperty(DTB, "/efi", "firmware-abi", buffer, AsciiStrSize((char *)buffer));

    FdtCreateNode(DTB, "/efi", "kernel-compatibility");
    SET_BUFFER("x86_64");
    FdtSetProperty(DTB, "/efi/kernel-compatibility", "kernel-compatibility", buffer, AsciiStrSize((char *)buffer));

    FdtCreateNode(DTB, "/efi", "runtime-services");
    SET_BUFFER("runtime-services");
    FdtSetProperty(DTB, "/efi/runtime-services", "name", buffer, AsciiStrSize((char *)buffer));
    FdtSetProperty(DTB, "/efi/runtime-services", "table", (UINTN *)(SystemTable->RuntimeServices), sizeof(UINTN));

    FdtCreateNode(DTB, "/efi/runtime-services", "configuration-table");
    SET_BUFFER("configuration-table");
    FdtSetProperty(DTB, "/efi/runtime-services/configuration-table", "name", buffer, AsciiStrSize((char *)buffer));

    val = 0;
    FdtCreateNode(DTB, "/efi", "platform");
    FdtSetProperty(DTB, "/efi/platform", "apple-coprocessor-version", &val, 4);
    FdtSetProperty(DTB, "/efi/platform", "boot-chime-on-last-boot", &val, 4);

    val64 = 133000000;
    FdtSetProperty(DTB, "/efi/platform", "FSBFrequency", &val64, 8); // FIXME: get from ACPI?
    val64 = 24000000;
    FdtSetProperty(DTB, "/efi/platform", "ARTFrequency", &val64, 8); // FIXME: read actual ART

    // Read the TSC and give xnu a suggestion
    UINT32 low, high;
    asm("       rdtsc; \
                movl %%eax, %0; \
                movl %%edx, %1;"
        : "=m"(low), "=m"(high) : : "eax", "edx" );

    val64 = high;
    val64 <<= 32;
    val64 |= low;
    FdtSetProperty(DTB, "/efi/platform", "InitialTSC", &val64, 8);

    return DTB;
}

VOID LoadConfigFile(VOID)
{
    CHAR8 rawConfig[EFI_PAGE_SIZE];
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs;
    EFI_FILE_HANDLE Root, cfgFile;

    if(EFI_ERROR(gBS->LocateProtocol(&gEfiSimpleFileSystemProtocolGuid, NULL, (VOID**)&Fs)))
        return;

    if(EFI_ERROR(Fs->OpenVolume(Fs, &Root)))
        return;

    if(EFI_ERROR(Root->Open(Root, &cfgFile, UEFI_STR("\\ravynOS\\com.ravynos.boot.plist"), EFI_FILE_MODE_READ, 0))) {
        Root->Close(Root);
        return;
    }

    UINT64 size = EFI_PAGE_SIZE;
    cfgFile->Read(cfgFile, &size, &rawConfig);
    cfgFile->Close(cfgFile);
    Root->Close(Root);

    CopyMem(cmdLine, rawConfig, size > 1024 ? 1024 : size);
    return;
}

EFI_STATUS EFIAPI UefiMain(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable)
{
    EFI_STATUS Status;
    VOID *KernelBuffer = NULL;
    UINTN KernelEntry = 0, KernelSize = 0;
    VOID *SMBIOS = NULL; // SMBIOS table pointer
    VOID *ACPI = NULL; // ACPI table pointer
    VOID *DTB = NULL; // Device Table Blob pointer
    UINTN MapKey, DescriptorSize, MemoryMapSize = 0;
    UINT64 physPages = 0;
    UINT32 DescriptorVersion;
    EFI_MEMORY_DESCRIPTOR *MemoryMap = NULL;
    UINT8 *region = NULL;

    gST->ConOut->ClearScreen(gST->ConOut);
    Print(UEFI_STR(":: ravynOS EFI Loader %s\n"), VERSION_STR);
    LoadConfigFile();

    Status = gBS->GetMemoryMap(&MemoryMapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
    if (Status == EFI_BUFFER_TOO_SMALL) {
        MemoryMap = (EFI_MEMORY_DESCRIPTOR *)MMAP_ADDR;
        Status = gBS->GetMemoryMap(&MemoryMapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
    }
    if (EFI_ERROR(Status)) {
        Print(UEFI_STR("!! Error: failed to retrieve memory map [%r]\n"), Status);
        return Status;
    }

    DTB = InitDTB(SystemTable);

    for(region = (UINT8 *)MemoryMap; region < ((UINT8 *)MemoryMap + MemoryMapSize); region += DescriptorSize) {
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
    Print(UEFI_STR("\n[] Memory: %u MB usable\n"), physPages * EFI_PAGE_SIZE / MB);

    VIDEO_INFO videoV1 = {0};
    VIDEO_BOOT video = {0};
    GetVideoInfo(&videoV1, &video);

    EFI_CONFIGURATION_TABLE *table = SystemTable->ConfigurationTable;
    CHAR8 buffer[128], buffer2[128];
    for(int i = 0; i < SystemTable->NumberOfTableEntries; ++i) {
        EFI_GUID guid = table[i].VendorGuid;
        
        AsciiSPrint(buffer, sizeof(buffer), "%g", guid);
        FdtCreateNode(DTB, "/efi/runtime-services/configuration-table", buffer);
        AsciiSPrint(buffer2, sizeof(buffer), "/efi/runtime-services/configuration-table/%g", guid);
        FdtSetProperty(DTB, buffer2, "name", buffer, AsciiStrSize((char *)buffer));
        FdtSetProperty(DTB, buffer2, "table", table[i].VendorTable, sizeof(UINTN));
        FdtSetProperty(DTB, buffer2, "guid", (void *)&guid, sizeof(guid));
    
        if(CompareGUIDs(guid, gEfiSmbiosTableGuid) == 0 || CompareGUIDs(guid, gEfiSmbios3TableGuid) == 0) {
            SMBIOS = table[i].VendorTable;
            Print(UEFI_STR("[] SMBIOS at 0x%p\n"), SMBIOS);
        }
        else if(CompareGUIDs(guid, gEfiAcpiTableGuid) == 0) {
            ACPI = table[i].VendorTable;
            FdtSetProperty(DTB, buffer2, "alias", "ACPI_20", 8);
            Print(UEFI_STR("[] ACPI RSDP at 0x%p\n"), ACPI);
        }
        else if(CompareGUIDs(guid, gEfiDtbTableGuid) == 0) {
            DTB = table[i].VendorTable;
            Print(UEFI_STR("[] DTB at 0x%p\n"), DTB);
        }
    }

    UINT32 DTBLength = 0;
    if(ACPI != 0)
        DTBLength = BuildDTBFromACPI(ACPI, DTB);
    Print(UEFI_STR("[] Created device tree at 0x%p\n"), DTB);

    LoadDrivers(ImageHandle);
    Status = LoadKernel(&KernelBuffer, &KernelEntry, &KernelSize);
    if (EFI_ERROR(Status))
        return Status;

    BOOT_ARGS *BootArgs = (BOOT_ARGS *)(KernelBuffer + KernelSize);
    SetMem(BootArgs, sizeof(BOOT_ARGS), 0);
    BootArgs->Version = 2;
    BootArgs->EFIMode = 64;
    BootArgs->Flags = kBootArgsFlagCSRActiveConfig | kBootArgsFlagCSRConfigMode | kBootArgsFlagCSRBoot;
    AsciiStrCpyS(BootArgs->CommandLine, 1024, cmdLine); 
    BootArgs->VideoV1 = videoV1;

    UINT32 ps = EFI_PAGE_SIZE - 1;
    KernelSize += (sizeof(BOOT_ARGS) + ps) & ~ps; // pad and align

    // Rebase the efi tables to the end of boot args
    VOID *p = KernelBuffer + KernelSize;
    CopyMem(p, SystemTable, SystemTable->Hdr.HeaderSize);
    CopyMem(p + SystemTable->Hdr.HeaderSize, SystemTable->RuntimeServices, SystemTable->RuntimeServices->Hdr.HeaderSize);

    EFI_SYSTEM_TABLE *st = ((EFI_SYSTEM_TABLE *)p);
    st->RuntimeServices = (EFI_RUNTIME_SERVICES *)((UINT64)(p + SystemTable->Hdr.HeaderSize) | 0xffffff8000000000);
    st->Hdr.CRC32 = 0;
    gBS->CalculateCrc32(&st->Hdr, st->Hdr.HeaderSize, &st->Hdr.CRC32);
    BootArgs->efiSystemTable = (UINT32)((UINT64)st);

    KernelSize += (SystemTable->Hdr.HeaderSize + SystemTable->RuntimeServices->Hdr.HeaderSize + ps) & ~ps;

    BootArgs->DeviceTree = (UINTN)DTB;
    BootArgs->DeviceTreeLength = DTBLength;
    BootArgs->kaddr = KERNEL_LOAD_ADDRESS;
    BootArgs->ksize = KernelSize;
    BootArgs->kslide = 0;
    BootArgs->efiRuntimeServicesPageStart = (UINT32)((UINT64)st->RuntimeServices);
    UINT32 size = SystemTable->RuntimeServices->Hdr.HeaderSize;
    UINT32 pages = size / EFI_PAGE_SIZE + 1;
    BootArgs->efiRuntimeServicesPageCount = pages;
    BootArgs->efiRuntimeServicesVirtualPageStart = (UINT64)st->RuntimeServices;
    BootArgs->keystoreDataStart = 0; // phys addr of keystore data for iokit
    BootArgs->keystoreDataSize = 0;
    BootArgs->Video = video;
    BootArgs->csrActiveConfig = CSR_ALLOW_UNTRUSTED_KEXTS | CSR_ALLOW_UNRESTRICTED_FS |
                                CSR_ALLOW_KERNEL_DEBUGGER | CSR_ALLOW_APPLE_INTERNAL |
                                CSR_ALLOW_UNRESTRICTED_DTRACE | CSR_ALLOW_UNRESTRICTED_NVRAM |
                                CSR_ALLOW_DEVICE_CONFIGURATION | CSR_ALLOW_ANY_RECOVERY_OS |
                                CSR_ALLOW_UNAPPROVED_KEXTS;
    BootArgs->csrCapabilities = CSR_CAPABILITY_UNLIMITED | CSR_CAPABILITY_CONFIG | CSR_CAPABILITY_APPLE_INTERNAL;
    BootArgs->MemoryMap = (UINT32)((UINT64)MemoryMap);
    BootArgs->MemoryMapSize = MemoryMapSize;
    BootArgs->MemoryMapDescriptorSize = DescriptorSize;
    BootArgs->MemoryMapDescriptorVersion = DescriptorVersion;
    BootArgs->physMemSize = physPages * EFI_PAGE_SIZE; // convert to bytes

    Print(UEFI_STR("\nStarting kernel at 0x%lx\n"), KernelEntry);
    gBS->ExitBootServices(ImageHandle, MapKey);
    
    /* jump to kernel _start with bootargs in eax */
    asm(
        "movq %0, %%rax\n"
        "movq %1, %%rdi\n"
        "movq %2, %%rsp\n"
        "movq %%rsp, %%rbp\n"
        "jmpq *%%rdi\n"
        : : "mr"(BootArgs), "r"(KernelEntry), "r"(bootStackTop) : "rax", "rdi"
    );

    return EFI_SUCCESS;
}
