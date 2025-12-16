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
STATIC VOID PrintIndent(UINTN level)
{
    for(UINTN i = 0; i < level; i++)
        Print(UEFI_STR("  "));
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

STATIC VOID dumpHex(UINT8 *addr, UINTN size, const CHAR8 *source)
{
    Print(L"DUMPHEX %a %p %x", source, addr, size);
    for(int i = 0; i < size; ++i) {
        if(i == 0 || i % 16 == 0)
            Print(L"\n0x%08x: ", addr+i);
        Print(L"%02x ", addr[i]);
    }
    Print(L"\n");
}

STATIC UINT8 *skipProperty(UINT8 *ptr)
{
    CHAR8 *name = ptr;
    ptr += FDT_PROPNAME_MAX; // skip name
    UINT32 datasize = FdtReadU32(ptr);
    ptr += 4;
    datasize = (datasize + 3) & ~3; // align 4
    // Print(L"skipProperty(size=0x%x, name=%a, ptr=%p)\n", datasize, name, ptr+datasize);
    ptr += datasize;

    return ptr;
}

STATIC VOID incProps(VOID *node)
{
    FdtNode *n = (FdtNode *)(node - 8);
    n->nProp++;
}

STATIC VOID incChildren(VOID *node)
{
    FdtNode *n = (FdtNode *)(node - 8);
    n->nChildren++;
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

    // Print(L"FindNode Path=%a p=%p (%a)\n", Path, p, FdtGetProperty(hdr, ptr + 4, "name", NULL));
    if(!*p) // this is the root node
        return ptr+12; // point after BEGIN_NODE and counts;

    UINT32 depth = 0; // root node
    while(1) {
        UINT32 idx = 0;
        while(*p && *p != '/') { // find end of segment
            segment[idx++] = *p;
            ++p;
        }
        segment[idx] = 0;

        if(*p == '/')
            p++; // skip path separator
        // Print(L"FindNode segment=%a p=%a depth=%d\n", segment, p, depth);

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
                    // Print(L"BEGIN_NODE(depth=%d, ptr=%p)\n", depth, ptr);
                    ptr += 8; // skip counts
                    CHAR8 *name = FdtGetProperty(hdr, ptr, "name", NULL);
                    // Print(L"name = %a\n", name);
                    if(AsciiStrCmp(name, segment) == 0) {
                        found = TRUE;
                        // Print(L"FOUND\n");
                    }
                    break;
                }
                case FDT_PROP: {
                    ptr = skipProperty(ptr);
                    break;
                }
                default:
                    Print(UEFI_STR("!! FdtFindNode: Unknown token %x at %p\n"), tok, ptr);
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
            CHAR8 *propName = ptr;
            ptr += FDT_PROPNAME_MAX;
            UINT32 len = FdtReadU32(ptr);
            ptr += 4;

            if(AsciiStrCmp(propName, Name) == 0) {
                if(OutLen)
                    *OutLen = len;
                return ptr; // property data
            }

            UINT32 increment = (len + 3) & ~3; // align 4
            ptr += increment;
        }
        else if(tok == FDT_BEGIN_NODE) {
            ptr += 8; // skip counts
            break;
        }
        else if(tok == FDT_END_NODE || tok == FDT_END)
            return NULL;
    }
    return NULL;
}

/* Skip over a node and all its children 
 * Call with: ptr = after BEGIN_NODE token
 * Returns: new ptr
 */
UINT8 *_fastForward(UINT8 *ptr)
{
    // Print(L"fast forward (%p)\n", ptr);
    UINT32 tok;
    int depth = 1;
    ptr += 8; // skip counts
    while(1) {
        tok = FdtReadU32(ptr);
        ptr += 4;
        switch(tok) {
            case FDT_BEGIN_NODE:
                ptr += 8; // skip counts
                ++depth;
                break;
            case FDT_END_NODE:
                --depth;
                if(depth == 0)
                    return ptr;
                break;
            case FDT_PROP: {
                ptr = skipProperty(ptr);
                break;
            }
            case FDT_END:
                return NULL;
            default:
                Print(UEFI_STR("!! _fastForward: Unknown token %x at %p (depth %d)\n"), tok, ptr, depth);
                return NULL;
        }
    }
    return NULL;
}

EFI_STATUS FdtSetProperty(FDT_HDR *hdr, CHAR8 *NodePath, CHAR8 *Name, VOID *Data, UINT32 Len)
{
    UINT32 tok;
    FdtProperty prop = {0};
    CopyMem(prop.name, Name, AsciiStrSize(Name));
    prop.length = SwapBytes32(Len);
    
    UINT8 *node = FdtFindNode(hdr, NodePath);
    if(!node)
        return EFI_NOT_FOUND;

    // Try replacing first
    UINT32 oldLen;
    UINT8 *oldprop = FdtGetProperty(hdr, node, Name, &oldLen);
    if(oldprop && oldLen == Len) {
        CopyMem(oldprop, Data, Len);
        return EFI_SUCCESS;
    }
    // FIXME: if the len is different, we should still modify the prop
    // instead of appending a new one (and we should delete the old if appending new)

    // shift tail
    UINT8 *end = (UINT8*)hdr + SwapBytes32(hdr->totalsize);
    UINTN tail = end - node;
    UINT32 propSize = (4 + Len + sizeof(prop) + 3) & ~3;
    CopyMem(node + propSize, node, tail);

    incProps(node);

    // write new prop
    FdtWriteU32(node, FDT_PROP);
    node += 4;
    CopyMem(node, &prop, sizeof(prop));
    node += sizeof(prop);
    SetMem(node, (Len + 3) & ~3, 0); // pad to align 4
    CopyMem(node, Data, Len);

    hdr->totalsize = SwapBytes32(SwapBytes32(hdr->totalsize) + propSize);
    hdr->size_dt_struct = SwapBytes32(SwapBytes32(hdr->size_dt_struct) + propSize);

    // dumpHex((UINT8 *)hdr + SwapBytes32(hdr->off_dt_struct), SwapBytes32(hdr->size_dt_struct), "FdtSetProperty()");
    return EFI_SUCCESS;
}

EFI_STATUS FdtCreateNode(FDT_HDR *hdr, CHAR8 *ParentPath, CHAR8 *Name)
{
    UINT32 tok;
    UINT8 *parent = FdtFindNode(hdr, ParentPath);
    if(!parent)
        return EFI_NOT_FOUND;

    incChildren(parent);
    
    // Print(UEFI_STR("Finding END_NODE of parent %p\n"), parent);
    while((tok = FdtReadU32(parent)) != FDT_END_NODE) {
        parent += 4;

        // if we have child nodes, we need to skip over them
        switch(tok) {
            case FDT_BEGIN_NODE: {
                parent = _fastForward(parent);
                break;
            }
            case FDT_PROP: {
                parent = skipProperty(parent);
                break;
            }
            case FDT_END_NODE:
                break;
            case FDT_END:
                return EFI_NOT_FOUND;
            default:
                Print(L"!! FdtCreateNode: Unknown token %x at %p\n", tok, parent);
                return EFI_ABORTED; // found invalid token
        }
        if(parent > (CHAR8 *)((UINTN)hdr + SwapBytes32(hdr->off_dt_struct) + SwapBytes32(hdr->size_dt_struct)))
            return EFI_OUT_OF_RESOURCES;
    }

    // Print(UEFI_STR("Found at %p\n"), parent);
    UINT32 namesize = AsciiStrSize(Name);
    FdtProperty prop = {0};
    CopyMem(prop.name, "name", 4);
    prop.length = SwapBytes32(namesize);

    UINT32 datasize = (namesize + 3) & ~3;
    UINT32 newsize = 20 + sizeof(prop) + datasize;
    UINT8 *end = ((UINT8*)hdr) + SwapBytes32(hdr->totalsize);
    UINTN tail = end - parent;

    // now shift everything forward and insert the node
    // Print(UEFI_STR("newsize %d end %p tail %d prop size %d name %a len %d\n"),
        // newsize, end, tail, sizeof(prop), prop.name, SwapBytes32(prop.length));
    CopyMem(parent + newsize, parent, tail);

    FdtWriteU32(parent, FDT_BEGIN_NODE);
    parent += 4;
    FdtWriteU32(parent, 1); // 1 prop = "name"
    parent += 4;
    FdtWriteU32(parent, 0); // no child nodes
    parent += 4;
    FdtWriteU32(parent, FDT_PROP);
    parent += 4;
    CopyMem(parent, &prop, sizeof(prop));
    parent += sizeof(prop);
    CopyMem(parent, Name, namesize);
    parent += datasize;
    FdtWriteU32(parent, FDT_END_NODE);
    parent += 4;

    hdr->totalsize = SwapBytes32(SwapBytes32(hdr->totalsize) + newsize);
    hdr->size_dt_struct = SwapBytes32(SwapBytes32(hdr->size_dt_struct) + newsize);

    // dumpHex((UINT8 *)hdr + SwapBytes32(hdr->off_dt_struct), SwapBytes32(hdr->size_dt_struct), "FdtCreateNode()");
    return EFI_SUCCESS;
}

 // Dump FDT tree starting at hdr
VOID FdtDump(FDT_HDR *hdr)
{
    UINT8 *struct_block = (UINT8*)hdr + SwapBytes32(hdr->off_dt_struct);
    UINT8 *end = struct_block + SwapBytes32(hdr->size_dt_struct);
    UINT8 *ptr = struct_block;
    UINTN indent = 0;

    Print(UEFI_STR("\n:: Device Tree (0x%x, %d bytes)\n"),
        hdr, SwapBytes32(hdr->totalsize));
    
    while(ptr < end) {
        UINT32 token = FdtReadU32(ptr);
        ptr += 4;

        switch (token) {
        case FDT_BEGIN_NODE:
        {
            FdtNode *n = ptr;
            ptr += 8; // skip nChildren and nProp
            CHAR8 *name = FdtGetProperty(hdr, ptr, "name", NULL);
            PrintIndent(indent);
            Print(UEFI_STR("%a(%d,%d) / {\n"), n->nProp, n->nChildren, name);
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
            CHAR8 *name = ptr;
            ptr += FDT_PROPNAME_MAX;
            UINT32 len  = FdtReadU32(ptr);
            ptr += 4;
            PrintIndent(indent);
            Print(UEFI_STR("%a (len=%u) = "), name, len);

            if(len == 4)
                Print(UEFI_STR("<0x%08x>\n"), *(UINT32 *)ptr);
            else if(len == 8)
                Print(UEFI_STR("<0x%016lx>\n"), *(UINT64 *)ptr);
            else {
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
            Print(UEFI_STR("!! FdtDump: Unknown token 0x%x\n"), token);
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
    FdtProperty prop = {"name", 4};
    UINT32 StructBlock[] = { 
        FDT_BEGIN_NODE, 1, 0,  // 1 prop, no children
          FDT_PROP,0,0,0,0,0,0,0,0,4,0,
        FDT_END_NODE, FDT_END 
    };

    for(int j = 0; j < sizeof(StructBlock)/4; j++)
        StructBlock[j] = SwapBytes32(StructBlock[j]);

    UINT32 propSize = (sizeof(prop) + 4) & ~3;
    UINT32 struct_size = sizeof(StructBlock) + propSize;

    unsigned long long MemRsvMap[2] = {0, 0};
    UINT32 mem_rsv_size = sizeof(MemRsvMap);

    UINT32 off_mem_rsvmap = sizeof(FDT_HDR);
    UINT32 off_dt_struct  = off_mem_rsvmap + mem_rsv_size;
    UINT32 total_size = off_dt_struct + struct_size;

    FDT_HDR *hdr = AllocateZeroPool(EFI_PAGE_SIZE);
    if (!hdr)
        return NULL;

    hdr->magic = SwapBytes32(FDT_MAGIC);
    hdr->totalsize = SwapBytes32(total_size);
    hdr->off_dt_struct = SwapBytes32(off_dt_struct);
    hdr->off_mem_rsvmap = SwapBytes32(off_mem_rsvmap);
    hdr->version = SwapBytes32(17); // current version
    hdr->last_comp_version = SwapBytes32(16); // Compatible with older loaders
    hdr->boot_cpuid_phys = 0;
    hdr->size_dt_strings = 0;
    hdr->size_dt_struct = SwapBytes32(struct_size);

    CopyMem(((UINT8*)hdr) + off_mem_rsvmap, MemRsvMap, mem_rsv_size);
    CopyMem(((UINT8*)hdr) + off_dt_struct, StructBlock, struct_size);
    prop.length = SwapBytes32(prop.length);
    CopyMem((UINT8 *)hdr + off_dt_struct + 16, &prop, sizeof(FdtProperty));
    // Strings block is empty; no copy needed.

    // dumpHex((UINT8 *)hdr + off_dt_struct, struct_size, "FdtCreateEmpty()");
    return hdr;
}
