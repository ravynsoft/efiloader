/*
 * Stub libkern/OSByteOrder.h for UEFI builds on little-endian x86_64/arm64.
 * UEFI always runs little-endian on these architectures.
 */
#ifndef _LIBKERN_OSBYTEORDER_H
#define _LIBKERN_OSBYTEORDER_H

#include <stdint.h>

static __inline__ uint16_t OSSwapInt16(uint16_t x) { return __builtin_bswap16(x); }
static __inline__ uint32_t OSSwapInt32(uint32_t x) { return __builtin_bswap32(x); }
static __inline__ uint64_t OSSwapInt64(uint64_t x) { return __builtin_bswap64(x); }

/* Host is little-endian: host-to-big swaps, host-to-little is identity */
#define OSSwapHostToBigInt16(x)    OSSwapInt16((uint16_t)(x))
#define OSSwapHostToBigInt32(x)    OSSwapInt32((uint32_t)(x))
#define OSSwapHostToBigInt64(x)    OSSwapInt64((uint64_t)(x))
#define OSSwapBigToHostInt16(x)    OSSwapInt16((uint16_t)(x))
#define OSSwapBigToHostInt32(x)    OSSwapInt32((uint32_t)(x))
#define OSSwapBigToHostInt64(x)    OSSwapInt64((uint64_t)(x))
#define OSSwapHostToLittleInt16(x) ((uint16_t)(x))
#define OSSwapHostToLittleInt32(x) ((uint32_t)(x))
#define OSSwapHostToLittleInt64(x) ((uint64_t)(x))
#define OSSwapLittleToHostInt16(x) ((uint16_t)(x))
#define OSSwapLittleToHostInt32(x) ((uint32_t)(x))
#define OSSwapLittleToHostInt64(x) ((uint64_t)(x))

#endif /* _LIBKERN_OSBYTEORDER_H */
