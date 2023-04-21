/*
 * zipl - zSeries Initial Program Loader tool
 *
 * os-info definitions
 *
 * Copyright IBM Corp. 2013, 2023
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef OS_INFO_H
#define OS_INFO_H

#include "lib/zt_common.h"
#include "boot/error.h"
#include "boot/s390.h"
#include <stdint.h>

#define OS_INFO_MAGIC			0x4f53494e464f535aULL /* OSINFOSZ */
#define OS_INFO_CSUM_SIZE		(sizeof(struct os_info) - offsetof(struct os_info, version_major))

#define OS_INFO_VMCOREINFO		0
#define OS_INFO_REIPL_BLOCK		1

struct os_info_entry {
	uint64_t addr;
	uint64_t size;
	uint32_t csum;
} __packed;

struct os_info {
	uint64_t magic;
	uint32_t csum;
	uint16_t version_major;
	uint16_t version_minor;
	uint64_t crashkernel_addr;
	uint64_t crashkernel_size;
	struct os_info_entry entry[2];
	uint8_t reserved[4024];
} __packed;

/*
 * Return 0 in case of valid os_info
 * Return -EOS_INFO_MISSING if os_info address is not page aligned or page is
 * not accessible or os_info magic value is missing.
 * Return -EOS_INFO_CSUM_FAILED if os_info checksum is invalid.
 */
static inline int os_info_check(const struct os_info *os_info)
{
	if (!os_info ||
	    (unsigned long)os_info % PAGE_SIZE ||
	    !page_is_valid((unsigned long)os_info) ||
	    os_info->magic != OS_INFO_MAGIC)
		return -EOS_INFO_MISSING;
	if (os_info->csum != csum_partial(&os_info->version_major, OS_INFO_CSUM_SIZE, 0))
		return -EOS_INFO_CSUM_FAILED;
	return 0;
}

/*
 * Return 1 in case of valid os_info_entry, otherwise 0
 * Make sure that the entire os_info structure is checked first with os_info_check().
 */
static inline int os_info_entry_is_valid(const struct os_info_entry *entry)
{
	return (entry &&
		entry->addr &&
		entry->size &&
		page_is_valid(entry->addr) &&
		entry->csum == csum_partial((void *)entry->addr, entry->size, 0));
}

#endif /* OS_INFO_H */
