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


int mapSegments(struct mach_header_64 *mh, UINTN *KernelEntry, EFI_FILE_HANDLE KernelFile)
{
    int size = 0;
    uint32_t offset = sizeof(struct mach_header_64);
    for(int i = 0; i < mh->ncmds; ++i) {
        const struct load_command *lc = (const struct load_command *)((UINT64)mh + offset);
        switch(lc->cmd) {
            case LC_SEGMENT_64: {
                const struct segment_command_64 *ls = (const struct segment_command_64 *)lc;
                CHAR16 segname[16];
                AsciiStrToUnicodeStrS(ls->segname, segname, sizeof(segname));
                if(!StrCmp(segname, UEFI_STR("__PRELINK_TEXT"))
                    || !StrCmp(segname, UEFI_STR("__PRELINK_INFO"))
                    || !StrCmp(segname, UEFI_STR("__LINKEDIT"))
                    || ls->vmsize == 0)
                    break;
                Print(UEFI_STR("   %s at %lx (%d) sz %lx -> "),
                    segname, ls->vmaddr, offset, ls->vmsize);
                VOID *physaddr = (VOID *)(ls->vmaddr & 0xffffffff);
                UINTN size = ls->vmsize;
                EFI_STATUS Status = gBS->AllocatePages(AllocateAnyPages, EfiLoaderData,
                    EFI_SIZE_TO_PAGES(size), physaddr);
                Print(UEFI_STR("%u pages at 0x%p [%r]\n"), EFI_SIZE_TO_PAGES(size),
                    physaddr, Status);
                if(!StrCmp(segname, UEFI_STR("__HIB")))
                    *KernelEntry = (UINTN)physaddr + 0xa7000; // this is where _start lives. FIXME: look up symbol
                Status = KernelFile->SetPosition(KernelFile, ls->fileoff);
                Status = KernelFile->Read(KernelFile, &size, (EFI_PHYSICAL_ADDRESS *)physaddr);
                if(EFI_ERROR(Status))
                    Print(UEFI_STR("!! Error: failed to read kernel data!\n"));
                break;
            }

            default:
                break;
        }
        offset += lc->cmdsize;
    }
}