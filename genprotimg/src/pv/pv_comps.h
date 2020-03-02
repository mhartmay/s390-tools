/*
 * PV components related definitions and functions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PV_COMPS_H
#define PV_COMPS_H

#include <stdint.h>
#include <stddef.h>
#include <glib.h>
#include <openssl/evp.h>

#include "boot/s390.h"
#include "utils/buffer.h"

#include "pv_comp.h"
#include "pv_stage3.h"

typedef struct _pv_img_comps PvImgComps;

PvImgComps *pv_img_comps_new(const EVP_MD *ald_md, const EVP_MD *pld_md, const EVP_MD *tld_md,
			     GError **err);
unsigned int pv_img_comps_length(const PvImgComps *comps);
GSList *pv_img_comps_get_comps(const PvImgComps *comps);
struct stage3b_args *pv_img_comps_get_stage3b_args(const PvImgComps *comps, struct psw_t *psw);
int pv_img_comps_add_component(PvImgComps *comps, PvComponent *comp, GError **err G_GNUC_UNUSED);
PvComponent *pv_img_comps_get_nth_comp(PvImgComps *comps, unsigned int n);
int pv_img_comps_set_offset(PvImgComps *comps, size_t offset, GError **err);
int pv_img_comps_finalize(PvImgComps *comps, Buffer **pld_digest, Buffer **ald_digest,
			  Buffer **tld_digest, uint64_t *nep, GError **err);
void pv_img_comps_free(PvImgComps *comps);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(PvImgComps, pv_img_comps_free)
void pv_img_comps_clear(PvImgComps **comps);

#endif
