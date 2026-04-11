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
#include <stdint.h>

#define ACPI_TID_APIC "APIC"
#define ACPI_TID_BERT "BERT"
#define ACPI_TID_APIC "APIC"
#define ACPI_TID_BGRT "BGRT"
#define ACPI_TID_CPEP "CPEP"
#define ACPI_TID_DSDT "DSDT"
#define ACPI_TID_ECDT "ECDT"
#define ACPI_TID_EINJ "EINJ"
#define ACPI_TID_ERST "ERST"
#define ACPI_TID_FACP "FACP" // FADT
#define ACPI_TID_FACS "FACS"
#define ACPI_TID_FPDT "FPDT"
#define ACPI_TID_GTDT "GTDT"
#define ACPI_TID_HEST "HEST"
#define ACPI_TID_MSCT "MSCT"
#define ACPI_TID_MPST "MPST"
#define ACPI_TID_NFIT "NFIT"
#define ACPI_TID_OEMx "OEMx"
#define ACPI_TID_PCCT "PCCT"
#define ACPI_TID_PHAT "PHAT"
#define ACPI_TID_PMTT "PMTT"
#define ACPI_TID_PSDT "PSDT"
#define ACPI_TID_RASF "RASF"
#define ACPI_TID_RSDT "RSDT"
#define ACPI_TID_SBST "SBST"
#define ACPI_TID_SDEV "SDEV"
#define ACPI_TID_SLIT "SLIT"
#define ACPI_TID_SRAT "SRAT"
#define ACPI_TID_SSDT "SSDT"
#define ACPI_TID_XSDT "XSDT"

#define SDT_HEADER \
    UINT8 signature[4]; \
    UINT32 length; \
    UINT8 revision; \
    UINT8 checksum; \
    UINT8 OEMID[6]; \
    UINT8 OEMTableID[8]; \
    UINT32 OEMRevision; \
    UINT32 creator; \
    UINT32 creatorRevision;

typedef struct {
    SDT_HEADER
} ACPI_SDT_HEADER;

typedef struct {
    SDT_HEADER
    UINT32 FIRMWARE_CTRL;
    UINT32 DSDT;
    UINT8 _resv0;
    UINT8 Preferred_PM_Profile;
    UINT16 SCI_INT;
    UINT32 SMI_CMD;
    UINT8 ACPI_ENABLE;
    UINT8 ACPI_DISABLE;
    UINT8 S4BIOS_REQ;
    UINT8 PSTATE_CNT;
    UINT32 PM1a_EVT_BLK;
    UINT32 PM1b_EVT_BLK;
    UINT32 PM1a_CNT_BLK;
    UINT32 PM1b_CNT_BLK;
    UINT32 PM2_CNT_BLK;
    UINT32 PM_TMR_BLK;
    UINT32 GPE0_BLK;
    UINT32 GPE1_BLK;
    UINT8 PM1_EVT_LEN;
    UINT8 PM1_CNT_LEN;
    UINT8 PM2_CNT_LEN;
    UINT8 PM_TMR_LEN;
    UINT8 GPE0_BLK_LEN;
    UINT8 GPE1_BLK_LEN;
    UINT8 GPE1_BASE;
    UINT8 CST_CNT;
    UINT16 P_LVL2_LAT;
    UINT16 P_LVL3_LAT;
    UINT16 FLUSH_SIZE;
    UINT16 FLUSH_STRIDE;
    UINT8 DUTY_OFFSET;
    UINT8 DUTY_WIDTH;
    UINT8 DAY_ALARM;
    UINT8 MON_ALARM;
    UINT8 CENTURY;
    UINT16 IAPC_BOOT_ARCH;
    UINT8 _resv1;
    UINT32 Flags;
    UINT8 RESET_REG[12];
    UINT8 RESET_VALUE;
    UINT16 ARM_BOOT_ARCH;
    UINT8 minor;
    UINT64 X_FIRMWARE_CTRL;
    UINT64 X_DSDT;
    UINT8 X_PM1a_EVT_BLK[12];
    UINT8 X_PM1b_EVT_BLK[12];
    UINT8 X_PM1a_CNT_BLK[12];
    UINT8 X_PM1b_CNT_BLK[12];
    UINT8 X_PM2_CNT_BLK[12];
    UINT8 X_PM_TMR_BLK[12];
    UINT8 X_GPE0_BLK[12];
    UINT8 X_GPE1_BLK[12];
    UINT8 SLEEP_CONTROL_REG[12];
    UINT8 SLEEP_STATUS_REG[12];
    UINT64 hypervisorID;
} ACPI_FADT;

typedef struct {
    SDT_HEADER
    UINT32 LAPICAddr;
    UINT32 Flags;
} ACPI_APIC;

typedef struct {
    SDT_HEADER
    UINT64 baseAddress;
    UINT16 segmentGroup;
    UINT8 startBus;
    UINT8 endBus;
    UINT32 reserved;
} ACPI_MCFG;

VOID GetPCIConfigSpace(ACPI_RSDP *rsdp, BOOT_ARGS *boot, void *DTB)
{
    ACPI_SDT_HEADER *xsdt = (ACPI_SDT_HEADER *)(rsdp->XSDT);
    if (CompareMem(xsdt->signature, "XSDT", 4)) {
        Print(UEFI_STR("No XSDT!\n"));
        return;
    }

    ACPI_SDT_HEADER **tableP
        = (ACPI_SDT_HEADER **) (rsdp->XSDT + sizeof(ACPI_SDT_HEADER));
    ACPI_SDT_HEADER **end = (ACPI_SDT_HEADER **) (rsdp->XSDT + xsdt->length);

    while (tableP < end) {
        ACPI_SDT_HEADER *table = *tableP;
        if(table->length == 0) break;
        if (!CompareMem(table->signature, "MCFG", 4)) {
            ACPI_MCFG *entry = (ACPI_MCFG *) table;
            boot->pciConfigSpaceBaseAddr = entry->baseAddress;
            boot->pciConfigSpaceStartBusNumber = entry->startBus;
            boot->pciConfigSpaceEndBusNumber = entry->endBus;
	    return;
	}
        tableP++;
    }
}

