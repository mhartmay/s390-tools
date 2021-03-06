/*
 * PV image related definitions and functions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PV_IMAGE_H
#define PV_IMAGE_H

#include <stdbool.h>
#include <stdint.h>
#include <glib.h>
#include <glib/gtypes.h>
#include <openssl/evp.h>

#include "boot/s390.h"
#include "utils/buffer.h"

#include "pv_args.h"
#include "pv_comp.h"
#include "pv_comps.h"
#include "pv_stage3.h"

typedef struct {
	char *tmp_dir; /* temporary directory used for the temporary
			* files (e.g. encrypted kernel) */
	Buffer *stage3a; /* stage3a containing IPIB and PV header */
	gsize stage3a_size; /* size of stage3a.bin */
	struct psw_t stage3a_psw; /* (short) PSW that is written to
				   * location 0 of the created image */
	struct psw_t initial_psw; /* PSW loaded by stage3b */
	EVP_PKEY *cust_pub_priv_key; /* customer private/public key */
	GSList *host_pub_keys; /* public host keys */
	int nid; /* Elliptic Curve used for the key derivation */
	/* keys and cipher used for the AES-GCM encryption */
	Buffer *cust_root_key;
	Buffer *gcm_iv;
	const EVP_CIPHER *gcm_cipher;
	/* Information for the IPIB and PV header */
	uint64_t pcf;
	uint64_t scf;
	Buffer *cust_comm_key;
	const EVP_CIPHER *cust_comm_cipher;
	Buffer *xts_key;
	const EVP_CIPHER *xts_cipher;
	GSList *key_slots;
	GSList *optional_items;
	PvImgComps *comps;
} PvImage;

PvImage *pv_img_new(PvArgs *args, const gchar *stage3a_path, GError **err);
void pv_img_free(PvImage *img);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(PvImage, pv_img_free)

int pv_img_add_component(PvImage *img, const PvArg *arg, GError **err);
int pv_img_finalize(PvImage *img, const gchar *stage3b_path, GError **err);
int pv_img_calc_pld_ald_tld_nep(const PvImage *img, Buffer **pld, Buffer **ald, Buffer **tld,
				uint64_t *nep, GError **err);
int pv_img_load_and_set_stage3a(PvImage *img, const gchar *path, GError **err);
const PvComponent *pv_img_get_stage3b_comp(const PvImage *img, GError **err);
int pv_img_add_stage3b_comp(PvImage *img, const gchar *path, GError **err);
uint32_t pv_img_get_enc_size(const PvImage *img);
uint32_t pv_img_get_pv_hdr_size(const PvImage *img);
int pv_img_write(PvImage *img, const char *path, GError **err);

#endif
