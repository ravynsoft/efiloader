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

#define FDT_MAGIC       0xd00dfeed
#define FDT_BEGIN_NODE  0x1
#define FDT_END_NODE    0x2
#define FDT_PROP        0x3
#define FDT_NOP         0x4
#define FDT_END         0x9

/* Static helper functions */
STATIC BOOLEAN FdtValidateHeader(FDT_HDR *hdr)
{
    if(!hdr || SwapBytes32(hdr->magic) != FDT_MAGIC)
        return FALSE;
    return TRUE;
}

STATIC CHAR8 *FdtGetString(FDT_HDR *hdr, UINT32 nameoff)
{
    CHAR8 *strings = (UINT8*)hdr + SwapBytes32(hdr->off_dt_strings);
    return strings + nameoff;
}

#define FdtToken(p) FdtReadU32(p)
STATIC UINT32 FdtReadU32(UINT8 *p)
{
    UINT32 v;
    CopyMem(&v, p, 4);
    return SwapBytes32(v);
}

STATIC VOID FdtWriteU32(UINT8 *p, UINT32 v)
{
    v = SwapBytes32(v);
    CopyMem(p, &v, 4);
}

// Find a node by path, e.g. "/soc/i2c@4000"
UINT8 *FdtFindNode(FDT_HDR *hdr, CHAR8 *Path)
{
    if(!hdr || !Path || Path[0] != '/')
        return NULL;

    UINT8 *ptr = (UINT8*)hdr + SwapBytes32(hdr->off_dt_struct);
    CHAR8 segment[128];
    CHAR8 *p = Path + 1;

    // Extract first path component
    while(1) {
        // Get next segment
        UINTN idx = 0;
        while(*p && *p != '/' && idx < sizeof(segment)-1)
            segment[idx++] = *p++;
        segment[idx] = 0;

        // we've consumed a level
        if(*p == '/')
            p++;

        // Scan tokens looking for this BEGIN_NODE
        BOOLEAN found = FALSE;
        while(1) {
            UINT32 tok = FdtToken(ptr);
            ptr += 4;

            if(tok == FDT_BEGIN_NODE) {
                CHAR8 *name = (CHAR8*)ptr;
                UINTN namelen = AsciiStrLen(name);
                if(AsciiStrCmp(name, segment) == 0) {
                    // Move ptr past node name
                    ptr += namelen + 1;
                    // Align to 4 bytes
                    ptr = (UINT8*)ALIGN_POINTER(ptr, 4);
                    found = TRUE;
                    break;
                } else {
                    // skip this node (depth traversal)
                    UINT32 depth = 1;
                    ptr += namelen + 1;
                    ptr = (UINT8*)ALIGN_POINTER(ptr, 4);
                    while(depth) {
                        UINT32 nt = FdtToken(ptr);
                        ptr += 4;

                        if(nt == FDT_BEGIN_NODE) {
                            CHAR8 *dummy = (CHAR8*)ptr;
                            ptr += AsciiStrLen(dummy) + 1;
                            ptr = (UINT8*)ALIGN_POINTER(ptr, 4);
                            depth++;
                        } else if(nt == FDT_END_NODE) {
                            depth--;
                        } else if(nt == FDT_PROP) {
                            UINT32 len = FdtReadU32(ptr);
                            ptr += 8 + len;
                            ptr = (UINT8*)ALIGN_POINTER(ptr, 4);
                        } else if(nt == FDT_END) {
                            return NULL;
                        }
                    }
                }
            }
            else if(tok == FDT_END) {
                return NULL;
            } else {
                Print(UEFI_STR("!! Unknown token 0x%x\n"), tok);
                return NULL;
            }
        }

        if (!found)
            return NULL;

        if (*p == 0)
            return ptr;    // Node found
    }
}

UINT8 *FdtGetProperty(FDT_HDR *hdr, UINT8 *NodePtr, CHAR8 *Name, UINT32 *OutLen)
{
    UINT8 *ptr = NodePtr;

    while(1) {
        UINT32 tok = FdtToken(ptr);
        ptr += 4;

        if(tok == FDT_PROP) {
            UINT32 len = FdtReadU32(ptr);
            UINT32 noffs = FdtReadU32(ptr+4);
            CHAR8 *propName = FdtGetString(hdr, noffs);

            if(AsciiStrCmp(propName, Name) == 0) {
                if (OutLen)
                    *OutLen = len;
                return ptr + 8;     // property data
            }

            ptr += 8 + len;
            ptr = (UINT8*)ALIGN_POINTER(ptr, 4);
        }
        else if(tok == FDT_BEGIN_NODE) {
            CHAR8 *n = (CHAR8*)ptr;
            ptr += AsciiStrLen(n) + 1;
            ptr = (UINT8*)ALIGN_POINTER(ptr, 4);
        }
        else if(tok == FDT_END_NODE) {
            return NULL;
        }
        else if(tok == FDT_END) {
            return NULL;
        }
    }
}

EFI_STATUS FdtSetProperty(FDT_HDR *hdr, CHAR8 *NodePath, CHAR8 *Name, VOID *Data, UINT32 Len)
{
    UINT8 *node = FdtFindNode(hdr, NodePath);
    if(!node)
        return EFI_NOT_FOUND;

    // Try replacing first
    UINT32 oldLen;
    UINT8 *prop = FdtGetProperty(hdr, node, Name, &oldLen);
    if(prop && oldLen == Len) {
        CopyMem(prop, Data, Len);
        return EFI_SUCCESS;
    }

    // Creating (append before END_NODE)
    UINT8 *ptr = node;
    while(FdtToken(ptr) != FDT_END_NODE)
        ptr += 4;

    // Insert:
    //   FDT_PROP
    //   len (4)
    //   nameoff (4)
    //   data[len]

    UINT32 off_dt_strings = SwapBytes32(hdr->off_dt_strings);
    UINT32 size_dt_strings = SwapBytes32(hdr->size_dt_strings);

    // Find name in string table or append
    CHAR8 *strblk = (CHAR8*)hdr + off_dt_strings;
    UINT32 nameoff = 0xFFFFFFFF;

    // scan for existing
    UINT32 p = 0;
    while(p < size_dt_strings) {
        if(AsciiStrCmp(strblk + p, Name) == 0) {
            nameoff = p;
            break;
        }
        p += AsciiStrSize(strblk + p);
    }

    if(nameoff == 0xFFFFFFFF) {
        // append
        CopyMem(strblk + size_dt_strings, Name, AsciiStrSize(Name));
        nameoff = size_dt_strings;
        size_dt_strings += AsciiStrSize(Name);

        hdr->size_dt_strings = SwapBytes32(size_dt_strings);
    }

    // Now append PROP token
    UINT8 *insert = ptr;  // before END_NODE
    UINT32 propSize = 12 + Len;

    // shift tail
    UINT8 *end = (UINT8*)hdr + SwapBytes32(hdr->totalsize);
    UINTN move = end - insert;
    CopyMem(insert + propSize, insert, move);

    // write new prop
    FdtWriteU32(insert, FDT_PROP);
    FdtWriteU32(insert + 4, Len);
    FdtWriteU32(insert + 8, nameoff);
    CopyMem(insert + 12, Data, Len);

    // align 4
    UINT32 new_tot = SwapBytes32(hdr->totalsize) + propSize;
    hdr->totalsize = SwapBytes32(new_tot);

    return EFI_SUCCESS;
}

EFI_STATUS FdtDeleteProperty(FDT_HDR *hdr, CHAR8 *NodePath, CHAR8 *Name)
{
    UINT8 *node = FdtFindNode(hdr, NodePath);
    if(!node)
        return EFI_NOT_FOUND;

    UINT32 plen;
    UINT8 *prop = FdtGetProperty(hdr, node, Name, &plen);
    if(!prop)
        return EFI_NOT_FOUND;

    UINT8 *tokPtr = prop - 8;  // back to PROP token
    UINT8 *after  = prop + plen;
    after = (UINT8*)ALIGN_POINTER(after, 4);

    UINT32 removeSize = after - tokPtr;

    UINT8 *end = (UINT8*)hdr + SwapBytes32(hdr->totalsize);
    UINTN tail = end - after;

    CopyMem(tokPtr, after, tail);

    UINT32 newtot = SwapBytes32(hdr->totalsize) - removeSize;
    hdr->totalsize = SwapBytes32(newtot);

    return EFI_SUCCESS;
}

EFI_STATUS FdtCreateNode(FDT_HDR *hdr, CHAR8 *ParentPath, CHAR8 *Name)
{
    UINT8 *parent = FdtFindNode(hdr, ParentPath);
    if(!parent)
        return EFI_NOT_FOUND;

    // Find END_NODE of the parent
    UINT8 *ptr = parent;
    UINT32 depth = 1;

    while(depth) {
        UINT32 tok = FdtToken(ptr);
        ptr += 4;

        if(tok == FDT_BEGIN_NODE) {
            CHAR8 *n = (CHAR8*)ptr;
            ptr += AsciiStrLen(n) + 1;
            ptr = (UINT8*)ALIGN_POINTER(ptr, 4);
            depth++;
        }
        else if(tok == FDT_END_NODE) {
            depth--;
        }
        else if(tok == FDT_PROP) {
            UINT32 len = FdtReadU32(ptr);
            ptr += 8 + len;
            ptr = (UINT8*)ALIGN_POINTER(ptr, 4);
        }
    }

    // ptr now points at parent's FDT_END_NODE
    UINT8 *insert = ptr - 4;

    // new node:
    // BEGIN_NODE, name\0 (aligned), END_NODE
    UINT32 namelen = AsciiStrSize(Name);
    UINT32 padded  = (namelen + 3) & ~3;

    UINT32 newsize =
          4                                 // BEGIN_NODE
        + namelen                           // name
        + (padded - namelen)                // pad
        + 4;                                // END_NODE

    UINT8 *end = (UINT8*)hdr + SwapBytes32(hdr->totalsize);
    UINTN tail = end - insert;

    CopyMem(insert + newsize, insert, tail);
    FdtWriteU32(insert, FDT_BEGIN_NODE);
    CopyMem(insert + 4, Name, namelen);
    SetMem(insert + 4 + namelen, padded - namelen, 0);

    FdtWriteU32(insert + 4 + padded, FDT_END_NODE);

    hdr->totalsize = SwapBytes32(SwapBytes32(hdr->totalsize) + newsize);

    return EFI_SUCCESS;
}

EFI_STATUS FdtDeleteNode(FDT_HDR *hdr, CHAR8 *Path)
{
    UINT8 *node = FdtFindNode(hdr, Path);
    if(!node)
        return EFI_NOT_FOUND;

    // node points at name after BEGIN_NODE

    UINT8 *start = node - 8;   // BACK to BEGIN_NODE token
    UINT8 *ptr   = node;

    UINT32 depth = 1;

    while(depth) {
        UINT32 tok = FdtToken(ptr);
        ptr += 4;

        if(tok == FDT_BEGIN_NODE) {
            CHAR8 *n = (CHAR8*)ptr;
            ptr += AsciiStrLen(n) + 1;
            ptr = (UINT8*)ALIGN_POINTER(ptr, 4);
            depth++;
        }
        else if(tok == FDT_PROP) {
            UINT32 len = FdtReadU32(ptr);
            ptr += 8 + len;
            ptr = (UINT8*)ALIGN_POINTER(ptr, 4);
        }
        else if(tok == FDT_END_NODE) {
            depth--;
        }
        else if(tok == FDT_END) {
            return EFI_PROTOCOL_ERROR;
        }
    }

    UINT8 *end = ptr;  // after END_NODE

    UINT8 *blobEnd = (UINT8*)hdr + SwapBytes32(hdr->totalsize);
    UINTN tail = blobEnd - end;

    CopyMem(start, end, tail);

    UINT32 removed = end - start;
    hdr->totalsize = SwapBytes32(SwapBytes32(hdr->totalsize) - removed);

    return EFI_SUCCESS;
}

STATIC VOID PrintIndent(UINTN level)
{
    for(UINTN i = 0; i < level; i++)
        Print(UEFI_STR("  "));
}

 // Dump FDT tree starting at hdr
VOID FdtDump(FDT_HDR *hdr)
{
    UINT8 *base = (UINT8*)hdr;
    UINT8 *struct_block = base + SwapBytes32(hdr->off_dt_struct);
    UINT8 *strings_block = base + SwapBytes32(hdr->off_dt_strings);
    UINT8 *ptr = struct_block;
    UINT8 *end = struct_block + SwapBytes32(hdr->size_dt_struct);
    UINTN indent = 0;

    Print(UEFI_STR(":: Flattened Device Tree\n"));
    while(ptr < end) {
        UINT32 token = FdtToken(ptr);
        ptr += 4;

        switch (token) {
        case FDT_BEGIN_NODE:
        {
            CHAR8 *name = (CHAR8*)ptr;

            // Print indent + node name
            PrintIndent(indent);
            Print(UEFI_STR("%a/ {\n"), name);

            // Skip name + padding to next 4-byte boundary
            UINTN len = AsciiStrLen(name) + 1;
            ptr += len;
            ptr = (UINT8*)ALIGN_POINTER(ptr, 4);

            indent++;
            break;
        }

        case FDT_END_NODE:
            indent--;
            PrintIndent(indent);
            Print(UEFI_STR("}\n"));
            break;

        case FDT_PROP:
        {
            UINT32 len  = FdtReadU32(ptr);
            ptr += 4;
            UINT32 nameoff = FdtReadU32(ptr);
            ptr += 4;
            CHAR8 *propname = (CHAR8*)strings_block + nameoff;
            PrintIndent(indent);
            Print(UEFI_STR("%a (len=%u)\n"), propname, len);

            // Skip property value (padded to 4-byte alignment)
            ptr += len;
            ptr = (UINT8*)ALIGN_POINTER(ptr, 4);
            break;
        }

        case FDT_NOP:
            PrintIndent(indent);
            Print(UEFI_STR("(nop)\n"));
            break;

        case FDT_END:
            Print(UEFI_STR(":: End of FDT\n"));
            return;

        default:
            Print(UEFI_STR("!! Unknown token 0x%x\n"), token);
            return;
        }
    }

    Print(UEFI_STR("!! Reached end of structure block without FDT_END token\n"));
}


/**
 * Create a minimal empty Flattened Device Tree.
 *
 * Returns: Pointer to allocated FDT_HDR (caller must FreePool),
 *          or NULL on failure.
 */
FDT_HDR *FdtCreateEmpty(VOID)
{
    UINT32 StructBlock[4] = { 
        FDT_BEGIN_NODE, 0x00000000, FDT_END_NODE, FDT_END
    };

    for(int j = 0; j < 4; j++)
        StructBlock[j] = SwapBytes32(StructBlock[j]);

    UINT32 struct_size = sizeof(StructBlock);
    UINT32 strings_size = 0;
    unsigned long long MemRsvMap[2] = {0, 0};
    UINT32 mem_rsv_size = sizeof(MemRsvMap);

    UINT32 off_mem_rsvmap = sizeof(FDT_HDR);
    UINT32 off_dt_struct  = off_mem_rsvmap + mem_rsv_size;
    UINT32 off_dt_strings = off_dt_struct + struct_size;
    UINT32 total_size = off_dt_strings + strings_size;

    FDT_HDR *hdr = AllocateZeroPool(EFI_PAGE_SIZE);
    if (!hdr)
        return NULL;

    hdr->magic = SwapBytes32(FDT_MAGIC);
    hdr->totalsize = SwapBytes32(total_size);
    hdr->off_dt_struct = SwapBytes32(off_dt_struct);
    hdr->off_dt_strings = SwapBytes32(off_dt_strings);
    hdr->off_mem_rsvmap = SwapBytes32(off_mem_rsvmap);
    hdr->version = SwapBytes32(17); // current version
    hdr->last_comp_version = SwapBytes32(16); // Compatible with older loaders
    hdr->boot_cpuid_phys = 0;
    hdr->size_dt_strings = SwapBytes32(strings_size);
    hdr->size_dt_struct = SwapBytes32(struct_size);

    CopyMem(((UINT8*)hdr) + off_mem_rsvmap, MemRsvMap, mem_rsv_size);
    CopyMem(((UINT8*)hdr) + off_dt_struct, StructBlock, struct_size);
    // Strings block is empty; no copy needed.

    return hdr;
}
