/*
 * Boot configuration parser for the ravynOS XNU EFI loader
 *
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
 *
 * This is a deliberately minimal reader for the macOS XML plist format.  It
 * understands a single flat <dict> of <string> and <integer> values and copies
 * the recognized keys into gBootConfig.  Nested dictionaries, arrays and every
 * other value type are ignored.  It is not a general purpose plist library.
 */

#include "config.h"
#include <Library/BaseLib.h>

/* Compiled-in defaults, used when the plist is missing or a key is absent. */
BOOT_CONFIG gBootConfig = {
    .BootArgs        = "",
    .KernelPath      = "\\ravynOS\\kernelcache",
    .BootUUID        = {0},
    .HasBootUUID     = FALSE,
    .CsrActiveConfig = CSR_ALLOW_UNTRUSTED_KEXTS | CSR_ALLOW_UNRESTRICTED_FS |
                       CSR_ALLOW_KERNEL_DEBUGGER | CSR_ALLOW_APPLE_INTERNAL |
                       CSR_ALLOW_UNRESTRICTED_DTRACE | CSR_ALLOW_UNRESTRICTED_NVRAM |
                       CSR_ALLOW_DEVICE_CONFIGURATION | CSR_ALLOW_ANY_RECOVERY_OS |
                       CSR_ALLOW_UNAPPROVED_KEXTS,
};

/* TRUE for the XML whitespace that may appear between a </key> and its value. */
STATIC BOOLEAN IsSpace(CHAR8 c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

/* TRUE if [key, key+len) equals the NUL-terminated name exactly. */
STATIC BOOLEAN KeyMatch(CONST CHAR8 *key, UINTN len, CONST CHAR8 *name)
{
    return AsciiStrLen(name) == len && AsciiStrnCmp(key, name, len) == 0;
}

/* Bounded copy of a non-terminated source into a NUL-terminated buffer. */
STATIC VOID CopyValue(CHAR8 *dst, UINTN dstSize, CONST CHAR8 *src, UINTN srcLen)
{
    if(srcLen > dstSize - 1)
        srcLen = dstSize - 1;
    CopyMem(dst, src, srcLen);
    dst[srcLen] = '\0';
}

/* Single hex digit -> value, or -1 if not a hex digit. */
STATIC INTN HexDigit(CHAR8 c)
{
    if(c >= '0' && c <= '9') return c - '0';
    if(c >= 'a' && c <= 'f') return c - 'a' + 10;
    if(c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Parse "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" into 16 bytes. Hyphens optional. */
STATIC BOOLEAN ParseUUID(CONST CHAR8 *s, UINTN len, UINT8 out[16])
{
    UINTN n = 0;
    INTN hi = -1;

    for(UINTN i = 0; i < len && n < 16; i++) {
        if(s[i] == '-')
            continue;
        INTN v = HexDigit(s[i]);
        if(v < 0)
            return FALSE;
        if(hi < 0) {
            hi = v;
        } else {
            out[n++] = (UINT8)((hi << 4) | v);
            hi = -1;
        }
    }
    return n == 16 && hi < 0;
}

/* Parse a decimal or 0x-prefixed hexadecimal <integer> body. */
STATIC UINT32 ParseInteger(CONST CHAR8 *s, UINTN len)
{
    UINT32 value = 0;
    UINTN i = 0;

    if(len >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        for(i = 2; i < len; i++) {
            INTN v = HexDigit(s[i]);
            if(v < 0)
                break;
            value = (value << 4) | (UINT32)v;
        }
    } else {
        for(i = 0; i < len; i++) {
            if(s[i] < '0' || s[i] > '9')
                break;
            value = value * 10 + (UINT32)(s[i] - '0');
        }
    }
    return value;
}

/*
 * Store one key/value pair.  'isString' distinguishes <string> from <integer>;
 * keys whose value is the wrong type, or that we don't recognize, are ignored.
 */
STATIC VOID StoreConfigValue(CONST CHAR8 *key, UINTN keyLen,
                             CONST CHAR8 *val, UINTN valLen, BOOLEAN isString)
{
    if(isString && KeyMatch(key, keyLen, "boot-args")) {
        CopyValue(gBootConfig.BootArgs, sizeof(gBootConfig.BootArgs), val, valLen);
    } else if(isString && KeyMatch(key, keyLen, "kernel")) {
        CopyValue(gBootConfig.KernelPath, sizeof(gBootConfig.KernelPath), val, valLen);
    } else if(isString && KeyMatch(key, keyLen, "boot-uuid")) {
        gBootConfig.HasBootUUID = ParseUUID(val, valLen, gBootConfig.BootUUID);
    } else if(!isString && KeyMatch(key, keyLen, "csr-active-config")) {
        gBootConfig.CsrActiveConfig = ParseInteger(val, valLen);
    }
}

/*
 * Walk a flat <dict> picking up <key> elements and the <string>/<integer> that
 * follows each one.  Any other value element is skipped over.
 */
STATIC VOID ParseBootConfig(CHAR8 *xml)
{
    CHAR8 *p = xml;

    for(;;) {
        CHAR8 *key = AsciiStrStr(p, "<key>");
        if(key == NULL)
            return;
        key += 5; // past "<key>"

        CHAR8 *keyEnd = AsciiStrStr(key, "</key>");
        if(keyEnd == NULL)
            return;
        UINTN keyLen = keyEnd - key;

        p = keyEnd + 6; // past "</key>"
        while(IsSpace(*p))
            p++;

        if(AsciiStrnCmp(p, "<string>", 8) == 0) {
            CHAR8 *val = p + 8;
            CHAR8 *end = AsciiStrStr(val, "</string>");
            if(end == NULL)
                return;
            StoreConfigValue(key, keyLen, val, end - val, TRUE);
            p = end + 9;
        } else if(AsciiStrnCmp(p, "<integer>", 9) == 0) {
            CHAR8 *val = p + 9;
            CHAR8 *end = AsciiStrStr(val, "</integer>");
            if(end == NULL)
                return;
            StoreConfigValue(key, keyLen, val, end - val, FALSE);
            p = end + 10;
        } else {
            /* Unsupported value type (dict/array/bool/etc.): skip and continue. */
            p++;
        }
    }
}

VOID LoadBootConfig(VOID)
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

    UINT64 size = sizeof(rawConfig) - 1;
    cfgFile->Read(cfgFile, &size, &rawConfig);
    cfgFile->Close(cfgFile);
    Root->Close(Root);

    rawConfig[size] = '\0'; // terminate for the string scanner
    ParseBootConfig(rawConfig);
}
