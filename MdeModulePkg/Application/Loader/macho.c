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
UINT64 bootStackTop = 0;
EFI_GUID gEfiCpuArchProtocolGuid = EFI_CPU_ARCH_PROTOCOL_GUID;

UINT64 readULEB128(const UINT8 **p, const UINT8 *end)
{
    UINT64 result = 0;
    UINT8 q = 0;
    int bit = 0;
    do {
        if (*p == end)
            goto error;

        UINT64 slice = **p & 0x7f;
        if (bit > 63)
            goto error;
	    else {
	        result |= (slice << bit);
	        bit += 7;
        }
	    q = **p & 0x80;
	    (*p)++;
    } while (q);
    return result;
error:
    Print(UEFI_STR("Incorrect ULEB128 value\n"));
    return -1;
}

INT64 readSLEB128(const UINT8 **p, const UINT8 *end)
{
    INT64 result = 0;
    int bit = 0;
    UINT8 byte;
    do {
    	if (*p == end)
            goto error;

    	byte = **p;
	    (*p)++;
	    result |= (((INT64)(byte & 0x7f)) << bit);
	    bit += 7;
    } while (byte & 0x80);

    // sign extend negative numbers
    if ( ((byte & 0x40) != 0) && (bit < 64) )
	    result |= (~0ULL) << bit;
    return result;
error:
    Print(UEFI_STR("Incorrect SLEB128 value\n"));
    return 0;
}

#if !defined(SECTION_TYPE)
# define SECTION_TYPE(x) ((UINT32)x & 0xff000000)
#endif
#if !defined(SECTION_ATTR)
# define SECTION_ATTR(x) ((UINT32)x & 0xffffff)
#endif

int mapSegments(struct mach_header_64 *mh, UINTN *KernelEntry, EFI_FILE_HANDLE KernelFile)
{
    UINT32 kernelTop = 0, kernelBase = 0;
    struct mach_header_64 *mh_exec_hdr = 0;

    uint32_t offset = sizeof(struct mach_header_64);
    for(int i = 0; i < mh->ncmds; ++i) {
        const struct load_command *lc = (const struct load_command *)((UINT64)mh + offset);
        switch(lc->cmd) {
            case LC_SEGMENT_64: {
                const struct segment_command_64 *ls = (const struct segment_command_64 *)lc;
                CHAR16 segname[16], sectname[16];
                AsciiStrToUnicodeStrS(ls->segname, segname, sizeof(segname));
#ifdef DEBUG_LOADER
                Print(UEFI_STR("  %s at %lx (%d) sz %lx\n"),
                    segname, ls->vmaddr, offset, ls->vmsize);
#endif
                if(PHYSADDR(ls->vmaddr) + ls->vmsize > kernelTop)
                    kernelTop = PHYSADDR(ls->vmaddr) + ls->vmsize;
                
                if(ls->vmsize == 0)
                    break;

                struct section_64 *lsect = 
                    (struct section_64 *)((UINT64)(((UINT64)ls) + sizeof(struct segment_command_64)));
                for(int x=0; x<ls->nsects; ++x) {
                    AsciiStrToUnicodeStrS(lsect->sectname, sectname, sizeof(sectname));

#ifdef DEBUG_LOADER
                    Print(UEFI_STR("   %s at %lx (%d) sz %lx align %x, rel %d at %d, flags %x\n"),
                        sectname, lsect->addr, lsect->offset, lsect->size, lsect->align,
                        lsect->nreloc, lsect->reloff, lsect->flags);
#endif
                    if(!StrCmp(segname, UEFI_STR("__HIB"))) {
                        if(!StrCmp(sectname, UEFI_STR("__text")))
                            *KernelEntry = (UINT32)lsect->addr; // _start is the first routine
                        else if(!StrCmp(sectname, UEFI_STR("__data")))
                            bootStackTop = lsect->addr;
                        else if(!StrCmp(sectname, UEFI_STR("__bootPT")))
                            kernelBase = PHYSADDR(lsect->addr);
                    } else if(!StrCmp(segname, UEFI_STR("__TEXT")) && !StrCmp(sectname, UEFI_STR("__text")))
                        mh_exec_hdr = (struct mach_header_64 *)((UINTN)PHYSADDR(ls->vmaddr));

                    EFI_STATUS Status = EFI_SUCCESS;
                    if(lsect->size) {
                        VOID *physaddr = (VOID *)((UINTN)PHYSADDR(lsect->addr));
                        UINTN align = 1;
                        for(int x = 0; x < lsect->align; ++x) align *= 2;
                        --align;
                        UINTN size = (lsect->size + align) & ~align;
                        Status = gBS->AllocatePages(AllocateAnyPages, EfiLoaderData, EFI_SIZE_TO_PAGES(size), physaddr);
                        SetMem(physaddr, size, 0);
                        if(EFI_ERROR(Status))
                            Print(UEFI_STR("!! ERROR %r\n"), Status);
                        if((UINTN)physaddr != PHYSADDR(lsect->addr))
                            Print(UEFI_STR("!! ERROR physaddr != lsect->addr\n"));

                        Status = KernelFile->SetPosition(KernelFile, lsect->offset);
                        size = lsect->size;
                        Status = KernelFile->Read(KernelFile, &size, (EFI_PHYSICAL_ADDRESS *)physaddr);
                    }
                    if(EFI_ERROR(Status))
                        Print(UEFI_STR("!! ERROR: failed to read kernel data!\n"));
                    lsect = (struct section_64 *)((UINT64)lsect + sizeof(struct section_64));
                }
                break;
            }

            default:
                break;
        }
        offset += lc->cmdsize;
    }

    /* Put the kernel header where it belongs */
    CopyMem(mh_exec_hdr, mh, mh->sizeofcmds);

    return kernelTop - kernelBase;
}

/* We've already loaded and decompressed the entire kernelcache for a prelinked
 * kernel. Now parse the header and copy the sections to our final location,
 * filling in essential addresses along the way as with mapSegments. On entry,
 * `mh` points to the decompressed kernel data and global var `KernelBuffer`
 * is the destination address of the kernel sections. Returns the kernel size.
 * FIXME: remove duplication with mapSegments (DRY)
 */
int mapDecompressedSegments(struct mach_header_64 *mh, UINTN *KernelEntry)
{
    UINT32 kernelTop = 0, kernelBase = 0;
    struct mach_header_64 *mh_exec_hdr = 0;

    uint32_t offset = sizeof(struct mach_header_64);
    for(int i = 0; i < mh->ncmds; ++i) {
        const struct load_command *lc = (const struct load_command *)((UINT64)mh + offset);
        switch(lc->cmd) {
            case LC_SEGMENT_64: {
                const struct segment_command_64 *ls = (const struct segment_command_64 *)lc;
                CHAR16 segname[16], sectname[16];
                AsciiStrToUnicodeStrS(ls->segname, segname, sizeof(segname));
		SetMem((VOID *)(ls->vmaddr & 0xffffffff), 0, ls->vmsize);
#ifdef DEBUG_LOADER
                Print(UEFI_STR("  %s at %lx (%d) sz %lx\n"),
                    segname, ls->vmaddr, offset, ls->vmsize);
#endif
                if(PHYSADDR(ls->vmaddr) + ls->vmsize > kernelTop)
                    kernelTop = (PHYSADDR(ls->vmaddr) + ls->vmsize + EFI_PAGE_SIZE-1) & ~(EFI_PAGE_SIZE-1);

                if(ls->vmsize == 0)
                    break;

                struct section_64 *lsect = 
                    (struct section_64 *)((UINT64)(((UINT64)ls) + sizeof(struct segment_command_64)));
                for(int x=0; x<ls->nsects; ++x) {
                    AsciiStrToUnicodeStrS(lsect->sectname, sectname, sizeof(sectname));

#ifdef DEBUG_LOADER
                    Print(UEFI_STR("   %s at %lx (%d) sz %lx align %x, rel %d at %d, flags %x\n"),
                        sectname, lsect->addr, lsect->offset, lsect->size, lsect->align,
                        lsect->nreloc, lsect->reloff, lsect->flags);
#endif
                    if(!StrCmp(segname, UEFI_STR("__HIB"))) {
                        if(!StrCmp(sectname, UEFI_STR("__text")))
                            *KernelEntry = (UINT32)lsect->addr; // _start is the first routine
                        else if(!StrCmp(sectname, UEFI_STR("__data")))
                            bootStackTop = lsect->addr;
                        else if(!StrCmp(sectname, UEFI_STR("__bootPT")))
                            kernelBase = PHYSADDR(lsect->addr);
                    } else if(!StrCmp(segname, UEFI_STR("__TEXT")) && !StrCmp(sectname, UEFI_STR("__text")))
                        mh_exec_hdr = (struct mach_header_64 *)((UINTN)PHYSADDR(ls->vmaddr));

                    EFI_STATUS Status = EFI_SUCCESS;
                    if(lsect->size) {
                        VOID *physaddr = (VOID *)((UINTN)PHYSADDR(lsect->addr));
                        UINTN align = (1 << lsect->align) - 1;
                        UINTN size = (lsect->size + align) & ~align;
                        CopyMem(physaddr, (VOID *)mh + lsect->offset, size);
                        if(EFI_ERROR(Status))
                            Print(UEFI_STR("!! ERROR %r\n"), Status);
                        if((UINTN)physaddr != PHYSADDR(lsect->addr))
                            Print(UEFI_STR("!! ERROR physaddr != lsect->addr\n"));
                    }
                    lsect = (struct section_64 *)((UINT64)lsect + sizeof(struct section_64));
                }
                break;
            }

            default:
                break;
        }
        offset += lc->cmdsize;
    }

    /* Put the kernel header where it belongs */
    CopyMem(mh_exec_hdr, mh, mh->sizeofcmds);

    Print(UEFI_STR("    Base Address 0x%p, Top 0x%p, Size %d bytes\n"), kernelBase, kernelTop, kernelTop - kernelBase);
    return kernelTop - kernelBase;
}
