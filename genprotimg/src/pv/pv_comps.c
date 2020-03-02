/*
 * PV components related definitions and functions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdint.h>
#include <stdbool.h>
#include <glib.h>
#include <openssl/evp.h>
#include <glib/gtypes.h>

#include "boot/s390.h"
#include "boot/stage3b.h"

#include "common.h"
#include "utils/align.h"
#include "utils/crypto.h"
#include "pv_comp.h"
#include "pv_comps.h"
#include "pv_error.h"
#include "pv_stage3.h"

struct _pv_img_comps {
	bool finalized;
	uint64_t next_src;
	uint64_t nep;
	EVP_MD_CTX *ald; /* context used for the hash of the addresses */
	EVP_MD_CTX *pld; /* context used for the hash of the pages content */
	EVP_MD_CTX *tld; /* context used for the hash of the tweaks */
	GSList *comps; /* list sorted by component type */
};

void pv_img_comps_free(PvImgComps *comps)
{
	if (!comps)
		return;

	EVP_MD_CTX_free(comps->ald);
	EVP_MD_CTX_free(comps->pld);
	EVP_MD_CTX_free(comps->tld);
	g_slist_free_full(comps->comps, (GDestroyNotify)pv_component_free);
	g_free(comps);
}

PvImgComps *pv_img_comps_new(const EVP_MD *ald_md, const EVP_MD *pld_md, const EVP_MD *tld_md,
			     GError **err)
{
	g_autoptr(PvImgComps) ret = g_new0(PvImgComps, 1);

	ret->ald = digest_ctx_new(ald_md, err);
	if (!ret->ald)
		return NULL;

	ret->pld = digest_ctx_new(pld_md, err);
	if (!ret->pld)
		return NULL;

	ret->tld = digest_ctx_new(tld_md, err);
	if (!ret->tld)
		return NULL;

	return g_steal_pointer(&ret);
}

unsigned int pv_img_comps_length(const PvImgComps *comps)
{
	return g_slist_length(comps->comps);
}

/* Update hashes and nep */
/* Returns 0 in case of success and -1 in case of a failure */
static int pv_img_comps_hash_comp(PvImgComps *comps, const PvComponent *comp, GError **err)
{
	int64_t nep_1 = 0;
	int64_t nep_2 = 0;
	int64_t nep_3 = 0;

	/* update pld */
	nep_1 = pv_component_update_pld(comp, comps->pld, err);
	if (nep_1 < 0)
		return -1;

	/* update ald */
	nep_2 = pv_component_update_ald(comp, comps->ald, err);
	if (nep_2 < 0)
		return -1;

	/* update tld */
	nep_3 = pv_component_update_tld(comp, comps->tld, err);
	if (nep_3 < 0)
		return -1;

	g_assert(nep_1 == nep_2);
	g_assert(nep_2 == nep_3);

	/* update comps->nep */
	g_assert_true(g_uint64_checked_add(&comps->nep, comps->nep, (uint64_t)nep_1));
	return 0;
}

int pv_img_comps_add_component(PvImgComps *comps, PvComponent *comp, GError **err)
{
	g_assert(comp);
	g_assert(comps);
	g_assert(IS_PAGE_ALIGNED(comps->next_src));

	uint64_t src_addr = comps->next_src;
	uint64_t src_size = pv_component_size(comp) ? PAGE_ALIGN(pv_component_size(comp)) :
						      PAGE_SIZE;

	if (comps->finalized) {
		g_set_error(err, PV_COMPONENT_ERROR, PV_COMPONENT_ERROR_FINALIZED,
			    _("Failed to add a component as the PV header is already created"));
		return -1;
	}

	/* set the address of the component in the memory layout */
	comp->src_addr = src_addr;

	g_info("%12s:\t0x%012lx (%12ld / %12ld Bytes)", pv_component_name(comp),
	       pv_component_get_src_addr(comp), pv_component_size(comp),
	       pv_component_get_orig_size(comp));

	comps->comps = g_slist_append(comps->comps, comp);
	comps->next_src += src_size;

	g_assert(IS_PAGE_ALIGNED(comps->next_src));
	return 0;
}

struct stage3b_args *pv_img_comps_get_stage3b_args(const PvImgComps *comps, struct psw_t *psw)
{
	/* For `stage3b_args` big-endian format must be used */
	g_autofree struct stage3b_args *ret = g_new0(struct stage3b_args, 1);

	for (GSList *iterator = comps->comps; iterator; iterator = iterator->next) {
		const PvComponent *img_comp = iterator->data;
		g_assert(img_comp);
		uint64_t src_addr = pv_component_get_src_addr(img_comp);
		uint64_t dest_size = pv_component_get_orig_size(img_comp);
		g_assert(dest_size <= pv_component_size(img_comp));

		switch ((PvComponentType)pv_component_type(img_comp)) {
		case PV_COMP_TYPE_KERNEL:
			memblob_init(&ret->kernel, src_addr, dest_size);
			break;
		case PV_COMP_TYPE_CMDLINE:
			memblob_init(&ret->cmdline, src_addr, dest_size);
			break;
		case PV_COMP_TYPE_INITRD:
			memblob_init(&ret->initrd, src_addr, dest_size);
			break;
		case PV_COMP_TYPE_STAGE3B:
			/* nothing needs to be done since it is the
			 * stage3b itself */
			break;
		default:
			/* should never happen */
			g_assert(false);
			break;
		}
	}

	ret->psw.mask = GUINT64_TO_BE(psw->mask);
	ret->psw.addr = GUINT64_TO_BE(psw->addr);
	return g_steal_pointer(&ret);
}

int pv_img_comps_set_offset(PvImgComps *comps, size_t offset, GError **err)
{
	g_assert(IS_PAGE_ALIGNED(comps->next_src));
	g_assert(IS_PAGE_ALIGNED(offset));

	if (pv_img_comps_length(comps) > 0) {
		g_set_error(err, PV_IMAGE_ERROR, PV_IMAGE_ERROR_OFFSET,
			    _("Offset cannot be changed after a component was added"));
		return -1;
	}

	comps->next_src += offset;

	g_assert(IS_PAGE_ALIGNED(comps->next_src));
	return 0;
}

GSList *pv_img_comps_get_comps(const PvImgComps *comps)
{
	return comps->comps;
}

int pv_img_comps_finalize(PvImgComps *comps, Buffer **pld_digest, Buffer **ald_digest,
			  Buffer **tld_digest, uint64_t *nep, GError **err)
{
	g_autoptr(Buffer) tmp_pld_digest = NULL;
	g_autoptr(Buffer) tmp_ald_digest = NULL;
	g_autoptr(Buffer) tmp_tld_digest = NULL;

	comps->finalized = true;
	for (GSList *iterator = comps->comps; iterator; iterator = iterator->next) {
		const PvComponent *comp = iterator->data;
		int rc;

		/* update hashes and nep */
		rc = pv_img_comps_hash_comp(comps, comp, err);
		if (rc < 0)
			return -1;
	}

	tmp_pld_digest = digest_ctx_finalize(comps->pld, err);
	if (!tmp_pld_digest)
		return -1;

	tmp_ald_digest = digest_ctx_finalize(comps->ald, err);
	if (!tmp_ald_digest)
		return -1;

	tmp_tld_digest = digest_ctx_finalize(comps->tld, err);
	if (!tmp_tld_digest)
		return -1;

	*pld_digest = g_steal_pointer(&tmp_pld_digest);
	*ald_digest = g_steal_pointer(&tmp_ald_digest);
	*tld_digest = g_steal_pointer(&tmp_tld_digest);
	*nep = comps->nep;
	return 0;
}

PvComponent *pv_img_comps_get_nth_comp(PvImgComps *comps, unsigned int n)
{
	return g_slist_nth_data(comps->comps, n);
}
