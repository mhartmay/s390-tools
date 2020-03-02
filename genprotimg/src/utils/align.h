/*
 * Alignment utils
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ALIGN_H
#define ALIGN_H

#include "boot/s390.h"

#define ALIGN(addr, size)      ((addr + size - 1) & (~(size - 1)))
#define IS_ALIGNED(addr, size) (!(addr & (size - 1)))

/* align addr to the next page boundary */
#define PAGE_ALIGN(addr) ALIGN((unsigned long)addr, PAGE_SIZE)

/* test whether an address is aligned to PAGE_SIZE or not */
#define IS_PAGE_ALIGNED(addr) IS_ALIGNED((unsigned long)(addr), PAGE_SIZE)

#endif
