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

#include "loader.h"


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

#define SECTION_TYPE(x) ((UINT32)x & 0xff000000)
#define SECTION_ATTR(x) ((UINT32)x & 0xffffff)

int mapSegments(struct mach_header_64 *mh, UINTN *KernelEntry, EFI_FILE_HANDLE KernelFile)
{
    int size = 0;
    uint32_t offset = sizeof(struct mach_header_64);
    for(int i = 0; i < mh->ncmds; ++i) {
        const struct load_command *lc = (const struct load_command *)((UINT64)mh + offset);
        switch(lc->cmd) {
            case LC_SEGMENT_64: {
                const struct segment_command_64 *ls = (const struct segment_command_64 *)lc;
                size += ls->vmsize;
                CHAR16 segname[16], sectname[16];
                AsciiStrToUnicodeStrS(ls->segname, segname, sizeof(segname));
#ifdef DEBUG_LOADER
                Print(UEFI_STR("  %s at %lx (%d) sz %lx\n"),
                    segname, ls->vmaddr, offset, ls->vmsize);
#endif
                if(ls->vmsize == 0)
                    break;

                VOID *physaddr = (VOID *)(ls->vmaddr & 0xffffffff);
                UINTN size = ls->vmsize;
                EFI_STATUS Status = gBS->AllocatePages(AllocateAnyPages, EfiLoaderData,
                    EFI_SIZE_TO_PAGES(size), physaddr);
                SetMem(physaddr, size, 0);

                struct section_64 *lsect = 
                    (struct section_64 *)((UINT64)(((UINT64)ls) + sizeof(struct segment_command_64)));
                for(int x=0; x<ls->nsects; ++x) {
                    AsciiStrToUnicodeStrS(lsect->sectname, sectname, sizeof(sectname));

#ifdef DEBUG_LOADER
                    Print(UEFI_STR("   %s at %lx (%d) sz %lx align %x, rel %d at %d, flags %x\n"),
                        sectname, lsect->addr, lsect->offset, lsect->size, lsect->align,
                        lsect->nreloc, lsect->reloff, lsect->flags);
#endif
                    if(!StrCmp(segname, UEFI_STR("__HIB")) && !StrCmp(sectname, UEFI_STR("__text")))
                        *KernelEntry = (UINT32)lsect->addr; // _start is the first routine

                    Status = EFI_SUCCESS;
                    if(lsect->size) {
                        Status = KernelFile->SetPosition(KernelFile, lsect->offset);
                        size = lsect->size;
                        physaddr = (void *)(lsect->addr & 0xffffffff);
                        Status = KernelFile->Read(KernelFile, &size, (EFI_PHYSICAL_ADDRESS *)physaddr);
                    }
                    if(EFI_ERROR(Status))
                        Print(UEFI_STR("!! Error: failed to read kernel data!\n"));
                    lsect = (struct section_64 *)((UINT64)lsect + sizeof(struct section_64));
                }
                break;
            }

            default:
                break;
        }
        offset += lc->cmdsize;
    }

    return size;
}