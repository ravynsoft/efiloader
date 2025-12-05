#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
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


void mapSegments(struct mach_header_64 *mh)
{
    uint32_t offset = sizeof(struct mach_header_64);
    for(int i = 0; i < mh->ncmds; ++i) {
        const struct load_command *lc = (const struct load_command *)((UINT64)mh + offset);
        switch(lc->cmd) {
            case LC_SEGMENT_64: {
                const struct segment_command_64 *ls = (const struct segment_command_64 *)lc;
                CHAR16 segname[16];
                AsciiStrToUnicodeStrS(ls->segname, segname, sizeof(segname));
                Print(UEFI_STR("LC_SEGMENT_64 %s at %lx (%d) sz %lx\n"), 
                    segname, ls->vmaddr, offset, ls->vmsize);
                break;
            }

            default:
                break;
        }
        offset += lc->cmdsize;
    }
}