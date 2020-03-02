/*
 * genprotimg - common definitions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef COMMON_H
#define COMMON_H

#define GETTEXT_PACKAGE "genprotimg"
#include <glib.h>
#include <glib/gi18n-lib.h>

#include "lib/zt_common.h"
#include "boot/linux_layout.h"

static const gchar tool_name[] = "genprotimg";
static const gchar copyright_notice[] = "Copyright IBM Corp. 2020";

/* default values */
#define GENPROTIMG_STAGE3A_PATH	 (STRINGIFY(PKGDATADIR) "/stage3a.bin")
#define GENPROTIMG_STAGE3B_PATH	 (STRINGIFY(PKGDATADIR) "/stage3b_reloc.bin")

#define PSW_SHORT_ADDR_MASK	 0x000000007FFFFFFFULL
#define PSW_MASK_BA		 0x0000000080000000ULL
#define PSW_MASK_EA		 0x0000000100000000ULL
#define PSW_MASK_BIT_12		 0x0008000000000000ULL

#define DEFAULT_INITIAL_PSW_ADDR IMAGE_ENTRY
#define DEFAULT_INITIAL_PSW_MASK (PSW_MASK_EA | PSW_MASK_BA)

#endif
