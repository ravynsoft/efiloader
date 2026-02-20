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
#include <sys/cdefs.h>

UINT32 DTBLength;

CHAR8 *_fastForward(CHAR8 *ptr);
CHAR8* gEnd = 0;

/* Static helper functions */
STATIC UINT32 FdtReadU32(CHAR8 *p)
{
    UINT32 v;
    CopyMem(&v, p, 4);
    return v; //SwapBytes32(v);
}

#if defined(DEBUG)
STATIC BOOLEAN _isprint(const CHAR8 ch)
{
    if((ch >= 0x20 && ch < 0x7f))
        return TRUE;
    return FALSE;
}

VOID dumpHex(CHAR8 *addr, UINTN size, const CHAR8 *source) 
{
    int index = 0;
    Print(L"DUMPHEX %a %p %x", source, addr, size);
    for(int i = 0; i < size; ++i) {
        if(i == 0 || i % 16 == 0)
            Print(L"\n0x%08x: ", addr+i);
        Print(L"%02x ", addr[i]);
        ++index;
        if(index == 16) {
            Print(L"\t");
            for(int j = 15; j >= 0; --j) {
                CHAR8 ch = *(addr+(i-j));
                Print(L"%c", _isprint(ch) ? ch : '.');
            }
            index = 0;
        }
    }
    Print(L"\n");
}
#endif /* DEBUG */

STATIC CHAR8 *skipProperty(CHAR8 *ptr)
{
    ptr += FDT_PROPNAME_MAX; // skip name
    UINT32 datasize = FdtReadU32(ptr);
    ptr += 4;
    return (CHAR8 *)(((UINTN)ptr + datasize + 3) & ~3);
}

STATIC CHAR8 *skipProperties(FdtNode *node)
{
    CHAR8 *ptr = (CHAR8 *)node + sizeof(node);
    for(int i = 0; i < node->nProp; ++i) {
        ptr = skipProperty(ptr);
    }
    return ptr;
}

/* Skip over a node and all its children 
 * Call with: ptr at start of node
 * Returns: new ptr -> next node
 */
CHAR8 *_fastForward(CHAR8 *ptr)
{
    FdtNode *cur = (FdtNode *)ptr;

    ptr += sizeof(FdtNode); // skip node counts and point at first child
    if(cur->nProp > 0)
        ptr = skipProperties(cur);

    // now iterate nodes. if none, we already point at next element
    for(int i = 0; i < cur->nChildren; ++i) {
        ptr = _fastForward(ptr);
        cur = (FdtNode *)ptr;
    }

    return ptr;
}

STATIC VOID incProps(VOID *node)
{
    ((FdtNode *)node)->nProp++;
}

STATIC VOID incChildren(VOID *node)
{
    ((FdtNode *)node)->nChildren++;
}

// Find a node by path, e.g. "/soc/i2c@4000"
CHAR8 *FdtFindNode(FdtNode *root, CHAR8 *Path)
{
    if(!root || !Path || Path[0] != '/')
        return NULL;
    
    CHAR8 *p = Path + 1;
    if(!*p) // this is the root node
        return (CHAR8 *)root;

    CHAR8 segment[128];

    // ptr is beginning of nodes block
    // p is char after leading / in path (\0 for root path)

    FdtNode *cur = root;
    while(1) {
        UINT32 idx = 0;
        while(*p && *p != '/') { // find end of segment
            segment[idx++] = *p;
            ++p;
        }
        segment[idx] = 0;

        if(*p == '/')
            p++; // skip path separator

        // walk the tree until we find it
        CHAR8 *ptr;
        BOOLEAN found = FALSE;
        while(!found) {
            CHAR8 *name = FdtGetProperty(root, (CHAR8 *)cur, "name", NULL);
            if(AsciiStrCmp(name, segment) == 0) {
                found = TRUE;
                ptr = (CHAR8 *)cur;
                break;
            }
            ptr = skipProperties(cur);
            for(int i = 0; i < cur->nChildren; ++i) {
                name = FdtGetProperty(root, ptr, "name", NULL);
                if(AsciiStrCmp(name, segment) == 0) {
                    found = TRUE;
                    break;
                }
                ptr = _fastForward((CHAR8 *)ptr);
            }
            cur = (FdtNode *)ptr;
        }

        if(!found)
            return NULL;

        if(!*p)
            return (CHAR8 *)cur;
    }

    return NULL;
}

CHAR8 *FdtGetProperty(FdtNode *root, CHAR8 *NodePtr, CHAR8 *Name, UINT32 *OutLen)
{
    CHAR8 *ptr = NodePtr + sizeof(FdtNode);

    if(((FdtNode *)NodePtr)->nProp == 0)
        return NULL;

    for(int i = 0; i < ((FdtNode *)NodePtr)->nProp; ++i) {
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
    return NULL;
}

EFI_STATUS FdtSetProperty(FdtNode *root, CHAR8 *NodePath, CHAR8 *Name, VOID *Data, UINT32 Len)
{
    FdtProperty prop = {0};
    prop.length = Len;
    AsciiStrCpyS(prop.name, FDT_PROPNAME_MAX, Name);
    
    CHAR8 *node = FdtFindNode(root, NodePath);
    if(!node)
        return EFI_NOT_FOUND;

    CHAR8 *ptr = node + sizeof(node);
 
    // shift tail
    CHAR8 *end = gEnd;
    UINTN tail = (UINTN)end - (UINTN)ptr;
    UINT32 propSize = (Len + sizeof(prop) + 3) & ~3;
    CopyMem(ptr + propSize, ptr, tail);

    // write new prop
    CopyMem(ptr, &prop, sizeof(prop));
    ptr += sizeof(prop);
    CopyMem(ptr, Data, Len);

    incProps((FdtNode *)node);
    gEnd += propSize;
    DTBLength += propSize;

    return EFI_SUCCESS;
}

EFI_STATUS FdtCreateNode(FdtNode *root, CHAR8 *ParentPath, CHAR8 *Name)
{
    CHAR8 *parent = FdtFindNode(root, ParentPath);
    if(!parent)
        return EFI_NOT_FOUND;

    FdtNode *cur = (FdtNode *)parent;
    UINT32 namesize = AsciiStrSize(Name);

    parent = skipProperties((FdtNode *)parent);

    FdtNode node = {1, 0}; // 1 prop = "name"
    FdtProperty prop = {"name", namesize};
    UINT32 newsize = (sizeof(node) + sizeof(prop) + namesize + 3) & ~3;

    CHAR8 *end = gEnd;
    UINTN tail = end - parent;
    CopyMem(parent + newsize, parent, tail);
    CopyMem(parent, &node, sizeof(node));
    CopyMem(parent + sizeof(node), &prop, sizeof(prop));
    parent += sizeof(prop) + sizeof(node);
    CopyMem(parent, Name, namesize);

    incChildren(cur);
    gEnd += newsize;
    DTBLength += newsize;
    return EFI_SUCCESS;
}

FdtNode *FdtCreateEmpty(UINTN addr)
{
    FdtNode node = {1, 0}; // 1 prop, no children
    FdtProperty prop = {"name", 4};

    CHAR8 *root = (CHAR8 *)addr;
    SetMem(root, sizeof(node)+sizeof(prop)+4, 0);
    CopyMem(root, &node, sizeof(node));
    CopyMem(root+sizeof(node), &prop, sizeof(prop));
    gEnd = root + sizeof(node) + sizeof(prop) + 4;
    DTBLength = gEnd - root;

    return (FdtNode *)root;
}
