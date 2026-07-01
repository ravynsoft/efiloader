/*
 * Boot configuration parser for the ravynOS XNU EFI loader
 *
 * Copyright (C) 2025-2026 Vihaan Nathan
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
    .PlatformUUID    = "",
    .BootUUID        = "",
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

/*
 * Store one key/value pair.  'isString' distinguishes <string> from <integer>;
 * keys whose value is the wrong type, or that we don't recognize, are ignored.
 */
STATIC VOID StoreConfigValue(CONST CHAR8 *key, UINTN keyLen,
                             CONST CHAR8 *val, UINTN valLen, BOOLEAN isString)
{
    if(isString && KeyMatch(key, keyLen, "boot-args")) {
        CopyValue(gBootConfig.BootArgs, sizeof(gBootConfig.BootArgs), val, valLen);
    } else if(isString && KeyMatch(key, keyLen, "boot-file")) {
        CopyValue(gBootConfig.KernelPath, sizeof(gBootConfig.KernelPath), val, valLen);
    } else if(isString && KeyMatch(key, keyLen, "boot-uuid")) {
        CopyValue(gBootConfig.BootUUID, sizeof(gBootConfig.BootUUID), val, valLen);
    } else if(isString && KeyMatch(key, keyLen, "platform-uuid")) {
        CopyValue(gBootConfig.PlatformUUID, sizeof(gBootConfig.PlatformUUID), val, valLen);
    } else if(!isString && KeyMatch(key, keyLen, "csr-active-config")) {
        CHAR8 buf[32];
        UINTN n = valLen < sizeof(buf) - 1 ? valLen : sizeof(buf) - 1;
        CopyMem(buf, val, n);
        buf[n] = '\0';
        if(n >= 2 && buf[0] == '0' && (buf[1] == 'x' || buf[1] == 'X'))
            gBootConfig.CsrActiveConfig = (UINT32)AsciiStrHexToUintn(buf);
        else
            gBootConfig.CsrActiveConfig = (UINT32)AsciiStrDecimalToUintn(buf);
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
