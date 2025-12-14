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
#include <sys/cdefs.h>

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
    CHAR8 *strings = (CHAR8 *)hdr + SwapBytes32(hdr->off_dt_strings);
    return strings + nameoff;
}

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

STATIC BOOLEAN _isprint(const UINT8 ch)
{
    if((ch >= 0x20 && ch < 0x7f))
        return TRUE;
    return FALSE;
}

// Find a node by path, e.g. "/soc/i2c@4000"
UINT8 *FdtFindNode(FDT_HDR *hdr, CHAR8 *Path)
{
    if(!hdr || !Path || Path[0] != '/')
        return NULL;

    UINT32 off_dt_struct = SwapBytes32(hdr->off_dt_struct);
    UINT32 size_dt_struct = SwapBytes32(hdr->size_dt_struct);
    UINT8 *ptr = (UINT8*)hdr + off_dt_struct;
    UINT8 *end = ptr + size_dt_struct;
    
    CHAR8 segment[128];
    CHAR8 *p = Path + 1;

    // ptr is beginning of struct block
    // p is char after leading / in path (\0 for root path)

    // Print(L"FindNode Path=%a p=%p (%a)\n", Path, p, p);
    if(!*p) // this is the root node
        return ptr+8; // point after BEGIN_NODE and name;

    UINT32 depth = 0; // root node
    while(1) {
        UINT32 idx = 0;
        while(*p && *p != '/') { // find end of segment
            segment[idx++] = *p;
            ++p;
        }
        segment[idx] = 0;

        if(*p == '/') p++; // skip path separator
        // Print(L"FindNode segment=%a p=%p (%a) depth=%d\n", segment, p, p, depth);

        // walk the tree depth first until we find it
        BOOLEAN found = FALSE;
        while(ptr < end && !found) {
            UINT32 tok = FdtReadU32(ptr);
            ptr += 4;
            switch(tok) {
                case FDT_NOP:
                    break;
                case FDT_END:
                    return NULL;
                case FDT_END_NODE:
                    --depth;
                    // Print(L"END_NODE(depth=%d)\n", depth);
                    if(depth == 0)
                        return NULL;
                    break;
                case FDT_BEGIN_NODE: {
                    ++depth;
                    UINT32 namesize = AsciiStrSize(ptr);
                    if(AsciiStrCmp(ptr, segment) == 0)
                        found = TRUE;
                    namesize = (namesize + 3) & ~3; // align 4
                    // Print(L"BEGIN_NODE(depth=%d, size=0x%x, ptr=%p%a) ", depth, namesize, ptr+namesize,
                    //    found ? " FOUND" : "");
                    ptr += namesize; // skip to next token
                    break;
                }
                case FDT_PROP: {
                    UINT32 datasize = FdtReadU32(ptr);
                    datasize = (datasize + 8 + 3) & ~3; // align 4
                    // Print(L"PROP(size=0x%x, ptr=%p) ", datasize, ptr+datasize);
                    ptr += datasize;
                    break;
                }
                default:
                    Print(UEFI_STR("Unknown token %x at %p\n"), tok, ptr);
            }
        }
        // Print(L"\n");

        if(!found)
            return NULL;
        if(!*p)
            return ptr;
    }

    return NULL;
}

UINT8 *FdtGetProperty(FDT_HDR *hdr, UINT8 *NodePtr, CHAR8 *Name, UINT32 *OutLen)
{
    UINT8 *ptr = NodePtr;

    while(1) {
        UINT32 tok = FdtReadU32(ptr);
        ptr += 4;

        if(tok == FDT_PROP) {
            UINT32 len = FdtReadU32(ptr);
            UINT32 noffs = FdtReadU32(ptr+4);
            CHAR8 *propName = FdtGetString(hdr, noffs);

            if(AsciiStrCmp(propName, Name) == 0) {
                if(OutLen)
                    *OutLen = len;
                return ptr + 8;     // property data
            }

            UINT32 increment = (len + 8 + 3) & ~3; // align 4
            ptr += increment;
        }
        else if(tok == FDT_BEGIN_NODE) {
            UINT32 namesize = AsciiStrSize(ptr);
            namesize = (namesize + 3) & ~3; // align 4
            ptr += namesize; // skip to next token
            break;
        }
        else if(tok == FDT_END_NODE || tok == FDT_END)
            return NULL;
    }
}

/* Skip over a node and all its children 
 * Call with: ptr = after BEGIN_NODE token, at start of padded name
 * Returns: new ptr
 */
UINT8 *_fastForward(UINT8 *ptr)
{
    UINT32 tok;
    int depth = 1;
    ptr += (AsciiStrSize(ptr) + 3) & ~3; // skip node name
    while(1) {
        tok = FdtReadU32(ptr);
        ptr += 4;
        switch(tok) {
            case FDT_BEGIN_NODE:
                ptr += (AsciiStrSize(ptr) + 3) & ~3;
                ++depth;
                break;
            case FDT_END_NODE:
                --depth;
                if(depth == 0)
                    return ptr;
                break;
            case FDT_PROP: {
                UINT32 datasize = FdtReadU32(ptr);
                datasize = (datasize + 8 + 3) & ~3; // align 4
                // Print(L"PROP(size=0x%x, ptr=%p) ", datasize, ptr+datasize);
                ptr += datasize;
                break;
            }
            case FDT_END:
                return NULL;
            default:
                Print(UEFI_STR("!! Unknown token %x at %p (depth %d)\n"), tok, ptr, depth);
                return NULL;
        }
    }
    return NULL;
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
    // FIXME: if the len is different, we should still modify the prop
    // instead of appending a new one

    UINT32 off_dt_strings = SwapBytes32(hdr->off_dt_strings);
    UINT32 size_dt_strings = SwapBytes32(hdr->size_dt_strings);
    UINT8 *ptr = node;
    UINT32 tok;

    // find the END_NODE
    while((tok = FdtReadU32(ptr)) != FDT_END_NODE) {
        ptr += 4;

        // if we have child nodes, we need to skip over them
        if(tok == FDT_BEGIN_NODE)
            ptr = _fastForward(ptr);
        if(ptr > (CHAR8 *)((UINTN)hdr + off_dt_strings))
            return EFI_OUT_OF_RESOURCES;
    }

    // Insert:
    //   FDT_PROP
    //   len (4)
    //   nameoff (4)
    //   data[len]

    // Find name in string table or append
    CHAR8 *strblk = (CHAR8*)hdr + off_dt_strings;
    UINT32 nameoff = size_dt_strings;

    // scan for existing
    UINT32 p = 0;
    while(p < size_dt_strings) {
        if(AsciiStrCmp(strblk + p, Name) == 0) {
            nameoff = p;
            break;
        }
        p += AsciiStrSize(strblk + p);
    }

    if(nameoff == size_dt_strings) { // not found, append
        UINT32 namesize = AsciiStrSize(Name);
        CopyMem(strblk + nameoff, Name, namesize);
        size_dt_strings += namesize;
        hdr->size_dt_strings = SwapBytes32(size_dt_strings);
        hdr->totalsize = SwapBytes32(SwapBytes32(hdr->totalsize) + namesize);
    }

    // Now append PROP token
    UINT8 *insert = ptr;  // before END_NODE
    UINT32 propSize = (3 + 12 + Len) & ~3;

    // shift tail
    UINT8 *end = (UINT8*)hdr + SwapBytes32(hdr->totalsize);
    UINTN move = end - insert;
    CopyMem(insert + propSize, insert, move);

    // write new prop
    FdtWriteU32(insert, FDT_PROP);
    FdtWriteU32(insert + 4, Len);
    FdtWriteU32(insert + 8, nameoff);
    CopyMem(insert + 12, Data, Len);

    hdr->totalsize = SwapBytes32(SwapBytes32(hdr->totalsize) + propSize);
    hdr->size_dt_struct = SwapBytes32(SwapBytes32(hdr->size_dt_struct) + propSize);
    hdr->off_dt_strings = SwapBytes32(SwapBytes32(hdr->off_dt_strings) + propSize);

    return EFI_SUCCESS;
}

EFI_STATUS FdtCreateNode(FDT_HDR *hdr, CHAR8 *ParentPath, CHAR8 *Name)
{
    UINT8 *parent = FdtFindNode(hdr, ParentPath);
    if(!parent)
        return EFI_NOT_FOUND;

    UINT32 size_dt_struct = SwapBytes32(hdr->size_dt_struct);
    UINT32 off_dt_struct = SwapBytes32(hdr->off_dt_struct);
    UINT32 off_dt_strings = SwapBytes32(hdr->off_dt_strings);

    // Find END_NODE of the parent
    UINT8 *ptr = parent;
    UINT32 tok;
    // Print(UEFI_STR("Finding END_NODE of parent %p\n"), parent);
    while((tok = FdtReadU32(ptr)) != FDT_END_NODE) {
        ptr += 4;

        // if we have child nodes, we need to skip over them
        if(tok == FDT_BEGIN_NODE)
            ptr = _fastForward(ptr);
        if(ptr > (CHAR8 *)((UINTN)hdr + off_dt_strings))
            return EFI_OUT_OF_RESOURCES;
    }

    if(tok != FDT_END_NODE)
        return EFI_NOT_FOUND;

    // Print(UEFI_STR("Found at %p\n"), ptr);

    // BEGIN_NODE, name\0 (aligned), END_NODE
    UINT32 namelen = AsciiStrSize(Name);
    UINT32 padded  = (namelen + 3) & ~3;

    UINT32 newsize =
          4                                 // BEGIN_NODE
        + namelen                           // name
        + (padded - namelen)                // pad
        + 4;                                // END_NODE

    UINT8 *insert = ptr;
    UINT8 *end = (UINT8*)hdr + SwapBytes32(hdr->totalsize);
    UINTN tail = end - insert;

    // now shift everything forward and insert the node
    // Print(UEFI_STR("insert %p newsize %d end %p tail %d\n"), insert, newsize, end, tail);
    CopyMem(insert + newsize, insert, tail);
    FdtWriteU32(insert, FDT_BEGIN_NODE);
    insert += 4;
    CopyMem(insert, Name, namelen);
    insert += namelen;
    SetMem(insert, padded - namelen, 0);
    insert += (padded - namelen);
    FdtWriteU32(insert, FDT_END_NODE);

    hdr->totalsize = SwapBytes32(SwapBytes32(hdr->totalsize) + newsize);
    hdr->size_dt_struct = SwapBytes32(SwapBytes32(hdr->size_dt_struct) + newsize);
    hdr->off_dt_strings = SwapBytes32(SwapBytes32(hdr->off_dt_strings) + newsize);
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

    Print(UEFI_STR("\n:: Device Tree (0x%x, %d bytes)\n"),
        hdr, SwapBytes32(hdr->totalsize));
    
    while(ptr < end) {
        UINT32 token = FdtReadU32(ptr);
        ptr += 4;

        switch (token) {
        case FDT_BEGIN_NODE:
        {
            CHAR8 *name = (CHAR8*)ptr;

            // Print indent + node name
            PrintIndent(indent);
            Print(UEFI_STR("%a/ {\n"), name);

            // Skip name + padding to next 4-byte boundary
            UINTN len = (AsciiStrSize(name) + 3) & ~3;
            ptr += len;
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
            Print(UEFI_STR("%a (len=%u) = "), propname, len);

            if(len == 4)
                Print(UEFI_STR("<0x%08x>\n"), *(UINT32 *)ptr);
            else if(len == 8)
                Print(UEFI_STR("<0x%016lx>\n"), *(UINT64 *)ptr);
            else {
                Print(L"[");
                UINT8 *p = ptr;
                while(p < ptr+len) {
                    Print(L"%c", _isprint(*p) ? *p : '.');
                    ++p;
                }
                Print(L" [ ");
                p = ptr;
                while(p < ptr+len) {
                    Print(L"%02x ", *p);
                    ++p;
                }
                Print(L"]\n");
            }

            // Skip property value (padded to 4-byte alignment)
            ptr += (len + 3) & ~3;
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
