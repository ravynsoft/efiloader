#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/FileHandleLib.h>
#include <Protocol/SimpleFileSystem.h>

#define VERSION_STR UEFI_STR("v0.0 IN DEVELOPMENT")

#define KERNEL_LOAD_ADDRESS 0x2000000  // 16 MB typical for XNU 20
#define FRAMEBUFFER_ADDRESS 0xE000000  // 224 MB framebuffer
#define MAX_KEXTS 4
#define MAX_PCI_DEVICES 4

// Macro for proper CHAR16 literals
#define UEFI_STR(s) ((CHAR16 *)u##s)

// Minimal device tree
typedef struct {
    CHAR8 Name[32];
    UINT64 Base;
    UINT64 Size;
    UINT32 Flags;
} DEVICE_NODE;

typedef struct {
    DEVICE_NODE Cpu;
    DEVICE_NODE Memory;
    DEVICE_NODE Pci[MAX_PCI_DEVICES];
    UINT32 NumPci;
} DEVICE_TREE;

// Minimal kext
typedef struct {
    CHAR8 Name[32];
    VOID *Address;
    UINTN Size;
} KEXT_ENTRY;

typedef struct {
    UINT32 Version;
    UINT32 Flags;
    UINT64 MemoryMap;
    UINT64 DeviceTree;
    UINT64 KernelSlide;
    UINT64 FramebufferBase;
    UINT32 FramebufferWidth;
    UINT32 FramebufferHeight;
    UINT32 FramebufferStride;
    UINT32 NumKexts;
    KEXT_ENTRY *Kexts;
} BOOT_ARGS;

// --- Load kernelcache from filesystem ---
EFI_STATUS LoadKernel(EFI_HANDLE ImageHandle, VOID **KernelBuffer, UINTN *KernelSize)
{
    EFI_STATUS Status;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs;
    EFI_FILE_HANDLE Root, KernelFile;

    Status = gBS->LocateProtocol(&gEfiSimpleFileSystemProtocolGuid, NULL, (VOID**)&Fs);
    if (EFI_ERROR(Status))
        return Status;

    Status = Fs->OpenVolume(Fs, &Root);
    if (EFI_ERROR(Status))
        return Status;

    Status = Root->Open(Root, &KernelFile, UEFI_STR("kernel"), EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(Status))
        return Status;

    EFI_FILE_INFO *FileInfo = AllocateZeroPool(sizeof(EFI_FILE_INFO) + 512);
    if (!FileInfo)
        return EFI_OUT_OF_RESOURCES;

    UINTN FileInfoSize = sizeof(EFI_FILE_INFO) + 512;
    Status = KernelFile->GetInfo(KernelFile, &gEfiFileInfoGuid, &FileInfoSize, FileInfo);
    if (EFI_ERROR(Status))
        return Status;

    *KernelSize = FileInfo->FileSize;
    *KernelBuffer = (VOID*)KERNEL_LOAD_ADDRESS;
    Status = gBS->AllocatePages(AllocateAddress, EfiLoaderData,
        EFI_SIZE_TO_PAGES(*KernelSize), (EFI_PHYSICAL_ADDRESS*)KernelBuffer);
    if (EFI_ERROR(Status))
        return Status;

    Status = KernelFile->Read(KernelFile, KernelSize, *KernelBuffer);
    KernelFile->Close(KernelFile);
    return Status;
}

// --- Build minimal device tree ---
DEVICE_TREE* BuildDeviceTree()
{
    DEVICE_TREE *DT = AllocateZeroPool(sizeof(DEVICE_TREE));
    if (!DT)
        return NULL;

    // CPU node
    AsciiStrCpyS(DT->Cpu.Name, sizeof(DT->Cpu.Name), "cpu0");
    DT->Cpu.Flags = 1;

    // Memory node
    AsciiStrCpyS(DT->Memory.Name, sizeof(DT->Memory.Name), "memory0");
    DT->Memory.Base = 0x0;
    DT->Memory.Size = 0x40000000; // 1GB RAM

    // Minimal PCI devices
    DT->NumPci = 2;
    AsciiStrCpyS(DT->Pci[0].Name, sizeof(DT->Pci[0].Name), "pci0");
    AsciiStrCpyS(DT->Pci[1].Name, sizeof(DT->Pci[1].Name), "pci1");

    return DT;
}

// --- Load minimal kexts (dummy placeholders) ---
KEXT_ENTRY* LoadMinimalKexts(UINT32 *NumKexts)
{
    *NumKexts = 1;
    KEXT_ENTRY *Kexts = AllocateZeroPool(sizeof(KEXT_ENTRY) * (*NumKexts));
    if (!Kexts) {
        *NumKexts = 0;
        return NULL;
    }

    AsciiStrCpyS(Kexts[0].Name, sizeof(Kexts[0].Name), "DummyKext");
    Kexts[0].Address = (VOID*)0x5000000; // fake address
    Kexts[0].Size = 0x1000;

    return Kexts;
}

EFI_STATUS EFIAPI UefiMain(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable)
{
    EFI_STATUS Status;
    VOID *KernelBuffer = NULL;
    UINTN KernelSize = 0;

    Print(UEFI_STR(":: ravynOS EFI Loader %s\n"), VERSION_STR);

    // --- Load kernelcache ---
    Status = LoadKernel(ImageHandle, &KernelBuffer, &KernelSize);
    if (EFI_ERROR(Status)) {
        Print(UEFI_STR("Failed to load kernel: %r\n"), Status);
        return Status;
    }
    Print(UEFI_STR("Kernel loaded: %u bytes at 0x%p\n"), KernelSize, KernelBuffer);

    // --- Build device tree ---
    DEVICE_TREE *DeviceTree = BuildDeviceTree();
    if (!DeviceTree) {
        Print(UEFI_STR("Failed to build device tree\n"));
        return EFI_OUT_OF_RESOURCES;
    }

    // --- Load kexts ---
    UINT32 NumKexts;
    KEXT_ENTRY *Kexts = LoadMinimalKexts(&NumKexts);

    // --- Prepare boot_args ---
    BOOT_ARGS BootArgs;
    SetMem(&BootArgs, sizeof(BootArgs), 0);
    BootArgs.Version = 1;
    BootArgs.DeviceTree = (UINT64)DeviceTree;
    BootArgs.FramebufferBase = FRAMEBUFFER_ADDRESS;
    BootArgs.FramebufferWidth = 640;
    BootArgs.FramebufferHeight = 480;
    BootArgs.FramebufferStride = 640*4;
    BootArgs.NumKexts = NumKexts;
    BootArgs.Kexts = Kexts;

    // --- Get memory map ---
    UINTN MapKey, DescriptorSize;
    UINT32 DescriptorVersion;
    EFI_MEMORY_DESCRIPTOR *MemoryMap = NULL;
    UINTN MemoryMapSize = 0;

    Status = gBS->GetMemoryMap(&MemoryMapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
    if (Status == EFI_BUFFER_TOO_SMALL) {
        MemoryMap = AllocatePool(MemoryMapSize);
        Status = gBS->GetMemoryMap(&MemoryMapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
    }
    if (EFI_ERROR(Status)) {
        Print(UEFI_STR("Memory map error: %r\n"), Status);
        return Status;
    }

    BootArgs.MemoryMap = (UINT64)MemoryMap;

    // --- Exit Boot Services ---
    Status = gBS->ExitBootServices(ImageHandle, MapKey);
    if (EFI_ERROR(Status)) {
        Print(UEFI_STR("ExitBootServices failed: %r\n"), Status);
        return Status;
    }

    Print(UEFI_STR("Exiting boot services, jumping to kernel...\n"));

    // --- Jump to kernel ---
    typedef void (*XnuEntry)(BOOT_ARGS *Args);
    XnuEntry KernelEntry = (XnuEntry)KernelBuffer;
    // KernelEntry(&BootArgs);

    while(1);
    return EFI_SUCCESS;
}
