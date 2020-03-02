/*
 * PV image related definitions and functions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <glib.h>
#include <openssl/evp.h>

#include "boot/stage3a.h"
#include "include/pv_hdr_def.h"
#include "utils/align.h"
#include "utils/crypto.h"
#include "utils/file_utils.h"
#include "include/pv_crypto_defs.h"
#include "common.h"

#include "pv_args.h"
#include "pv_error.h"
#include "pv_hdr.h"
#include "pv_image.h"
#include "pv_ipib.h"
#include "pv_opt_item.h"
#include "pv_stage3.h"
#include "pv_comps.h"

const PvComponent *pv_img_get_stage3b_comp(const PvImage *img, GError **err)
{
	const PvComponent *comp;

	g_return_val_if_fail(pv_img_comps_length(img->comps) >= 1, NULL);

	comp = pv_img_comps_get_nth_comp(img->comps, pv_img_comps_length(img->comps) - 1);
	if (!pv_component_is_stage3b(comp)) {
		g_set_error(err, PV_ERROR, PV_ERROR_INTERNAL,
			    _("Failed to get 'stage3b' component"));
		return NULL;
	}
	return comp;
}

typedef int (*prepare_func)(PvComponent *obj, const char *tmp_path, void *opaque, GError **err);

static int pv_img_prepare_component(const PvImage *img, PvComponent *comp, GError **err)
{
	int rc;
	prepare_func func = NULL;
	void *opaque = NULL;
	struct cipher_parms parms = { 0 };

	if (img->pcf & PV_CONTROL_FLAG_NO_DECRYPTION) {
		/* we only need to align the components */
		func = pv_component_align;
		opaque = NULL;
	} else {
		g_assert((int)img->xts_key->size == EVP_CIPHER_key_length(img->xts_cipher));
		g_assert(sizeof(parms.key) == EVP_CIPHER_key_length(img->xts_cipher));
		g_assert(sizeof(parms.tweak) == EVP_CIPHER_iv_length(img->xts_cipher));

		func = pv_component_align_and_encrypt;
		parms.cipher = img->xts_cipher;
		parms.padding = PAGE_SIZE;
		memcpy(&parms.key, img->xts_key->data, sizeof(parms.key));
		memcpy(&parms.tweak, &comp->tweak, sizeof(parms.tweak));

		opaque = &parms;
	}

	rc = (*func)(comp, img->tmp_dir, opaque, err);
	if (rc)
		return -1;

	return 0;
}

static Buffer *pv_img_read_key(const char *path, unsigned int key_size, GError **err)
{
	Buffer *ret = NULL;
	g_autoptr(Buffer) tmp_ret = NULL;
	size_t bytes_read;
	FILE *f = NULL;
	gsize size;

	if (file_size(path, &size, err) != 0)
		return NULL;

	if (size - key_size != 0) {
		g_set_error(err, PV_ERROR, PV_CRYPTO_ERROR_INVALID_KEY_SIZE,
			    _("Invalid key size in file '%s': read %zd, expected %u"), path, size,
			    key_size);
		return NULL;
	}

	f = file_open(path, "rb", err);
	if (!f)
		return NULL;

	tmp_ret = buffer_alloc(size);
	if (file_read(f, tmp_ret->data, 1, tmp_ret->size, &bytes_read, err) < 0)
		goto err;

	if (bytes_read - key_size != 0) {
		g_set_error(err, PV_ERROR, PV_CRYPTO_ERROR_INVALID_KEY_SIZE,
			    _("Invalid key size in file '%s': read %zd, expected %u"), path,
			    bytes_read, key_size);
		goto err;
	}

	ret = g_steal_pointer(&tmp_ret);
err:
	if (f)
		fclose(f);
	return ret;
}

static EVP_PKEY *pv_img_get_cust_pub_priv_key(int nid, GError **err)
{
	return generate_ec_key(nid, err);
}

static HostKeyList *pv_img_get_host_keys(gchar **host_cert_paths, X509_STORE *store, int nid,
					 GError **err)
{
	g_autoslist(EVP_PKEY) ret = NULL;

	g_assert(host_cert_paths);

	for (gchar **iterator = host_cert_paths; iterator != NULL && *iterator != NULL;
	     iterator++) {
		g_autoptr(EVP_PKEY) host_key = NULL;
		const gchar *path = *iterator;

		g_assert(path);

		host_key = read_ec_pubkey_cert(store, nid, path, err);
		if (!host_key)
			return NULL;

		ret = g_slist_append(ret, g_steal_pointer(&host_key));
	}

	return g_steal_pointer(&ret);
}

static Buffer *pv_img_get_key(const EVP_CIPHER *cipher, const char *path, GError **err)
{
	int key_len = EVP_CIPHER_key_length(cipher);
	g_assert(key_len > 0);

	if (path)
		return pv_img_read_key(path, (unsigned int)key_len, err);

	return generate_aes_key((unsigned int)key_len, err);
}

static Buffer *pv_img_get_iv(const EVP_CIPHER *cipher, const char *path, GError **err)
{
	int key_len = EVP_CIPHER_iv_length(cipher);
	g_assert(key_len > 0);

	if (path)
		return pv_img_read_key(path, (unsigned int)key_len, err);

	return generate_aes_key((unsigned int)key_len, err);
}

static uint64_t hex_str_toull(const gchar *nptr, GError **err)
{
	gchar *end = NULL;
	if (!g_str_is_ascii(nptr)) {
		g_set_error(err, PV_ERROR, EINVAL,
			    _("Invalid value: '%s' (must be a hexadecimal value, e.g. '0xcfe')"),
			    nptr);
		return 0;
	}

	uint64_t value = g_ascii_strtoull(nptr, &end, 16);
	if ((value == G_MAXUINT64 && errno == ERANGE) || (end && *end != '\0')) {
		g_set_error(err, PV_ERROR, EINVAL,
			    _("Invalid value: '%s' (must be a hexadecimal value, e.g. '0xcfe')"),
			    nptr);
		return 0;
	}
	return value;
}

static int pv_img_set_psw_addr(PvImage *img, const gchar *psw_addr_s, GError **err)
{
	g_assert(err);
	if (psw_addr_s) {
		uint64_t psw_addr = hex_str_toull(psw_addr_s, err);
		if (*err)
			return -1;
		img->initial_psw.addr = psw_addr;
	}

	return 0;
}

static int pv_img_set_control_flags(PvImage *img, const char *pcf_s, const char *scf_s,
				    GError **err)
{
	g_assert(err);
	if (pcf_s) {
		uint64_t flags = hex_str_toull(pcf_s, err);
		if (*err)
			return -1;
		img->pcf = flags;
	}

	if (scf_s) {
		uint64_t flags = hex_str_toull(scf_s, err);
		if (*err)
			return -1;
		img->scf = flags;
	}

	return 0;
}

/* read in the keys or auto-generate them */
static int pv_img_set_keys(PvImage *img, const PvArgs *args, GError **err)
{
	g_autoptr(X509_STORE) store = NULL;
	g_assert(img->xts_cipher);
	g_assert(img->cust_comm_cipher);
	g_assert(img->gcm_cipher);
	g_assert(img->nid);

	img->xts_key = pv_img_get_key(img->xts_cipher, args->xts_key_path, err);
	if (!img->xts_key)
		return -1;

	img->cust_comm_key = pv_img_get_key(img->cust_comm_cipher, args->cust_comm_key_path, err);
	if (!img->cust_comm_key)
		return -1;

	img->cust_root_key = pv_img_get_key(img->gcm_cipher, args->cust_root_key_path, err);
	if (!img->cust_root_key)
		return -1;

	img->gcm_iv = pv_img_get_iv(img->gcm_cipher, args->gcm_iv_path, err);
	if (!img->gcm_iv)
		return -1;

	img->cust_pub_priv_key = pv_img_get_cust_pub_priv_key(img->nid, err);
	if (!img->cust_pub_priv_key)
		return -1;

	img->host_pub_keys = pv_img_get_host_keys(args->host_certs, store, img->nid, err);
	if (!img->host_pub_keys)
		return -1;

	return 0;
}

static void pv_img_add_host_slot(PvImage *img, PvHdrKeySlot *slot)
{
	img->key_slots = g_slist_append(img->key_slots, slot);
}

static void pv_hdr_key_slot_free(PvHdrKeySlot *slot)
{
	if (!slot)
		return;

	g_free(slot);
}
G_DEFINE_AUTOPTR_CLEANUP_FUNC(PvHdrKeySlot, pv_hdr_key_slot_free)

static PvHdrKeySlot *pv_hdr_key_slot_new(const EVP_CIPHER *gcm_cipher, const Buffer *cust_root_key,
					 EVP_PKEY *cust_key, EVP_PKEY *host_key, GError **err)
{
	g_autoptr(PvHdrKeySlot) ret = g_new0(PvHdrKeySlot, 1);
	g_autofree union ecdh_pub_key *pub = NULL;
	g_autoptr(Buffer) exchange_key = NULL;
	g_autoptr(Buffer) digest_key = NULL;
	Buffer pub_buf = { 0 };
	Buffer aad = { .data = NULL, .size = 0 };
	Buffer tag = { .data = ret->tag, .size = sizeof(ret->tag) };
	Buffer enc = { .data = ret->wrapped_key, .size = sizeof(ret->wrapped_key) };
	struct gcm_cipher_parms parms = { 0 };
	int64_t c_len = 0;

	pub = evp_pkey_to_ecdh_pub_key(host_key, err);
	if (!pub)
		return NULL;

	pub_buf.data = pub->data;
	pub_buf.size = sizeof(*pub);
	digest_key = sha256_buffer(&pub_buf, err);
	if (!digest_key)
		return NULL;

	g_assert(digest_key->size == sizeof(ret->digest_key));
	/* set digest_key field */
	memcpy(ret->digest_key, digest_key->data, sizeof(ret->digest_key));

	exchange_key = compute_exchange_key(cust_key, host_key, err);
	if (!exchange_key)
		return NULL;

	/* initialize cipher parameters */
	parms.cipher = gcm_cipher;
	g_assert(exchange_key->size <= INT_MAX);
	g_assert((int)exchange_key->size == EVP_CIPHER_key_length(parms.cipher));
	g_assert(exchange_key->size == sizeof(parms.key));
	memcpy(&parms.key, exchange_key->data, sizeof(parms.key));

	/* encrypt the customer root key that is used for the encryption
	 * of the PV header */
	c_len = gcm_encrypt_decrypt(cust_root_key, &aad, &parms, &enc, &tag, true, err);
	if (c_len < 0)
		return NULL;

	g_assert(c_len == (int64_t)cust_root_key->size);
	return g_steal_pointer(&ret);
}

static int pv_img_set_host_slots(PvImage *img, GError **err)
{
	for (GSList *iterator = img->host_pub_keys; iterator; iterator = iterator->next) {
		EVP_PKEY *host_key = iterator->data;
		g_assert(host_key);
		PvHdrKeySlot *slot = pv_hdr_key_slot_new(img->gcm_cipher, img->cust_root_key,
							 img->cust_pub_priv_key, host_key, err);
		if (!slot)
			return -1;

		pv_img_add_host_slot(img, slot);
	}

	return 0;
}

static int pv_img_set_comps_offset(PvImage *img, uint64_t offset, GError **err)
{
	return pv_img_comps_set_offset(img->comps, offset, err);
}

PvImage *pv_img_new(PvArgs *args, const gchar *stage3a_path, GError **err)
{
	g_autoptr(PvImage) ret = g_new0(PvImage, 1);

	g_assert(args->tmp_dir);
	g_assert(stage3a_path);

	ret->comps = pv_img_comps_new(EVP_sha512(), EVP_sha512(), EVP_sha512(), err);
	if (!ret->comps)
		return NULL;
	ret->cust_comm_cipher = EVP_aes_256_gcm();
	ret->gcm_cipher = EVP_aes_256_gcm();
	ret->initial_psw.addr = DEFAULT_INITIAL_PSW_ADDR;
	ret->initial_psw.mask = DEFAULT_INITIAL_PSW_MASK;
	ret->nid = NID_secp521r1;
	ret->tmp_dir = g_strdup(args->tmp_dir);
	ret->xts_cipher = EVP_aes_256_xts();

	/* set initial PSW that will be loaded by the stage3b */
	if (pv_img_set_psw_addr(ret, args->psw_addr, err) < 0)
		return NULL;

	/* set the control flags: PCF and SCF */
	if (pv_img_set_control_flags(ret, args->pcf, args->scf, err) < 0)
		return NULL;

	/* read in the keys */
	if (pv_img_set_keys(ret, args, err) < 0)
		return NULL;

	if (pv_img_set_host_slots(ret, err) < 0)
		return NULL;

	/* allocate enough memory for the stage3a args and load the
	 * stage3a template into memory and set the loader_psw */
	if (pv_img_load_and_set_stage3a(ret, stage3a_path, err) < 0)
		return NULL;

	uint64_t off = PAGE_ALIGN(ret->stage3a_psw.addr + ret->stage3a->size);

	/* shift right all components by the size of stage3a loader */
	if (pv_img_set_comps_offset(ret, off, err) < 0)
		return NULL;

	return g_steal_pointer(&ret);
}

void pv_img_free(PvImage *img)
{
	if (!img)
		return;

	g_slist_free_full(img->optional_items, (GDestroyNotify)pv_opt_item_free);
	g_slist_free_full(img->key_slots, (GDestroyNotify)pv_hdr_key_slot_free);
	g_slist_free_full(img->host_pub_keys, (GDestroyNotify)EVP_PKEY_free);
	EVP_PKEY_free(img->cust_pub_priv_key);
	buffer_clear(&img->stage3a);
	pv_img_comps_free(img->comps);
	g_free(img->tmp_dir);
	buffer_free(img->xts_key);
	buffer_free(img->cust_root_key);
	buffer_free(img->gcm_iv);
	buffer_free(img->cust_comm_key);
	g_free(img);
}

static int pv_img_prepare_and_add_component(PvImage *img, PvComponent **comp, GError **err)
{
	int rc;
	g_assert(comp);

	/* prepares the component: does the alignment and encryption
	 * if required */
	rc = pv_img_prepare_component(img, *comp, err);
	if (rc)
		return -1;

	/* calculates the memory layout and adds the component to its
	 * internal list */
	rc = pv_img_comps_add_component(img->comps, g_steal_pointer(comp), err);
	if (rc)
		return -1;

	return 0;
}

int pv_img_add_component(PvImage *img, const PvArg *arg, GError **err)
{
	int rc;
	g_autoptr(PvComponent) comp = pv_component_new_file(arg->type, arg->path, err);
	if (!comp)
		return -1;

	rc = pv_img_prepare_and_add_component(img, &comp, err);
	if (rc < 0)
		return -1;

	g_assert(!comp);
	return 0;
}

int pv_img_calc_pld_ald_tld_nep(const PvImage *img, Buffer **pld, Buffer **ald, Buffer **tld,
				uint64_t *nep, GError **err)
{
	int rc;
	rc = pv_img_comps_finalize(img->comps, pld, ald, tld, nep, err);
	if (rc)
		return -1;

	return 0;
}

static int pv_img_build_stage3b(PvImage *img, Buffer *stage3b, GError **err)
{
	g_autofree struct stage3b_args *args;

	args = pv_img_comps_get_stage3b_args(img->comps, &img->initial_psw);
	if (!args) {
		g_set_error(err, PV_ERROR, PV_ERROR_INTERNAL,
			    _("Cannot generate stage3b arguments"));
		return -1;
	}

	build_stage3b(stage3b, args);
	return 0;
}

int pv_img_add_stage3b_comp(PvImage *img, const gchar *path, GError **err)
{
	int rc;
	g_autoptr(Buffer) stage3b = NULL;
	g_autoptr(PvComponent) comp = NULL;

	stage3b = stage3b_getblob(path, err);
	if (!stage3b)
		return -1;

	/* set the stage3b data */
	rc = pv_img_build_stage3b(img, stage3b, err);
	if (rc)
		return -1;

	comp = pv_component_new_buf(PV_COMP_TYPE_STAGE3B, stage3b, err);
	if (!comp)
		return -1;

	rc = pv_img_prepare_and_add_component(img, &comp, err);
	if (rc)
		return -1;

	return 0;
}

static uint32_t pv_img_get_aad_size(const PvImage *img)
{
	uint32_t size = 0;
	uint32_t key_size;

	g_assert(sizeof(struct pv_hdr_head) <= UINT32_MAX);
	g_assert(sizeof(struct pv_hdr_key_slot) <= UINT32_MAX);

	g_assert_true(g_uint_checked_add(&size, size, (uint32_t)sizeof(struct pv_hdr_head)));
	g_assert_true(g_uint_checked_mul(&key_size, (uint32_t)sizeof(struct pv_hdr_key_slot),
					 g_slist_length(img->key_slots)));
	g_assert_true(g_uint_checked_add(&size, size, key_size));
	return size;
}

static uint32_t pv_img_get_opt_items_size(const PvImage *img)
{
	uint32_t ret = 0;

	g_assert(img);

	for (GSList *iterator = img->optional_items; iterator; iterator = iterator->next) {
		const struct pv_hdr_opt_item *item = iterator->data;

		g_assert(item);
		g_assert_true(g_uint_checked_add(&ret, ret, pv_opt_item_size(item)));
	}
	return ret;
}

uint32_t pv_img_get_enc_size(const PvImage *img)
{
	uint32_t ret = 0;

	g_assert(sizeof(struct pv_hdr_encrypted) <= UINT32_MAX);

	g_assert_true(g_uint_checked_add(&ret, ret, (uint32_t)sizeof(struct pv_hdr_encrypted)));
	g_assert_true(g_uint_checked_add(&ret, ret, pv_img_get_opt_items_size(img)));
	return ret;
}

static uint32_t pv_img_get_tag_size(const PvImage *img G_GNUC_UNUSED)
{
	g_assert(sizeof(((struct pv_hdr *)0)->tag) <= UINT32_MAX);

	return (uint32_t)sizeof(((struct pv_hdr *)0)->tag);
}

uint32_t pv_img_get_pv_hdr_size(const PvImage *img)
{
	uint32_t size = 0;
	g_assert_true(g_uint_checked_add(&size, size, pv_img_get_aad_size(img)));
	g_assert_true(g_uint_checked_add(&size, size, pv_img_get_enc_size(img)));
	g_assert_true(g_uint_checked_add(&size, size, pv_img_get_tag_size(img)));
	return size;
}

static size_t get_stage3a_data_size(const PvImage *img)
{
	size_t size = 0;
	size += PAGE_ALIGN(pv_ipib_get_size(pv_img_comps_length(img->comps)));
	size += PAGE_ALIGN(pv_img_get_pv_hdr_size(img));
	return size;
}

int pv_img_load_and_set_stage3a(PvImage *img, const gchar *path, GError **err)
{
	g_autoptr(Buffer) stage3a = NULL;
	size_t data_size = get_stage3a_data_size(img);
	gsize stage3a_size;

	stage3a = stage3a_getblob(path, &stage3a_size, data_size, err);
	if (!stage3a)
		return -1;

	img->stage3a_psw.addr = STAGE3A_INIT_ENTRY;
	img->stage3a_psw.mask = DEFAULT_INITIAL_PSW_MASK;

	/* set addresses and size */
	img->stage3a = g_steal_pointer(&stage3a);
	img->stage3a_size = stage3a_size;
	return 0;
}

/* Creates the PV IPIB and sets the stage3a arguments */
static int pv_img_build_stage3a(Buffer *stage3a, size_t stage3a_bin_size, GSList *comps,
				const Buffer *hdr, GError **err)
{
	g_autofree struct ipl_parameter_block *ipib = NULL;
	int rc;

	g_assert(stage3a);
	g_assert(hdr);

	ipib = pv_ipib_new(comps, hdr, err);
	if (!ipib)
		return -1;

	rc = build_stage3a(stage3a, stage3a_bin_size, hdr, ipib, err);
	if (rc < 0)
		return -1;

	g_info("%12s:\t0x%012lx (%12ld / %12ld Bytes)", "stage3a", STAGE3A_LOAD_ADDRESS,
	       stage3a->size, stage3a->size);
	return 0;
}

/* Creates the actual PV header (serialized and AES-GCM encrypted) */
static Buffer *pv_img_create_pv_hdr(PvImage *img, GError **err)
{
	g_autoptr(PvHdr) hdr = NULL;
	g_autoptr(Buffer) hdr_buf = NULL;

	hdr = pv_hdr_new(img, err);
	if (!hdr)
		return NULL;

	hdr_buf = pv_hdr_serialize(hdr, img, true, err);
	if (!hdr_buf)
		return NULL;

	return g_steal_pointer(&hdr_buf);
}

/* No changes to the components are allowed after calling this
 * function */
int pv_img_finalize(PvImage *pv, const gchar *stage3b_path, GError **err)
{
	int rc;
	g_autoptr(Buffer) hdr = NULL;

	/* load stage3b template into memory and add it to the list of
	 * components. This must be done before calling
	 * `pv_img_load_and_set_stage3a`. */
	rc = pv_img_add_stage3b_comp(pv, stage3b_path, err);
	if (rc < 0)
		return -1;

	/* create the PV header */
	hdr = pv_img_create_pv_hdr(pv, err);
	if (!hdr)
		return -1;

	/* generate stage3a. At this point in time the PV header and
	 * the stage3b must be generated and encrypted */
	rc = pv_img_build_stage3a(pv->stage3a, pv->stage3a_size, pv_img_comps_get_comps(pv->comps),
				  hdr, err);
	if (rc < 0)
		return -1;

	return 0;
}

static uint64_t convert_psw_to_short_psw(const struct psw_t *psw, GError **err)
{
	uint64_t ret;
	uint64_t psw_addr = psw->addr;
	uint64_t psw_mask = psw->mask;

	/* test if PSW mask can be converted */
	if (psw_mask & PSW_SHORT_ADDR_MASK) {
		g_set_error(err, PV_ERROR, PV_ERROR_INTERNAL,
			    _("Failed to convert PSW to short PSW"));
		return 0;
	}

	/* test for bit 12 */
	if (psw_mask & PSW_MASK_BIT_12) {
		g_set_error(err, PV_ERROR, PV_ERROR_INTERNAL,
			    _("Failed to convert PSW to short PSW"));
		return 0;
	}

	/* test if PSW addr can be converted  */
	if (psw_addr & ~PSW_SHORT_ADDR_MASK) {
		g_set_error(err, PV_ERROR, PV_ERROR_INTERNAL,
			    _("Failed to convert PSW to short PSW"));
		return 0;
	}

	ret = psw_mask;
	/* set bit 12 to 1 */
	ret |= PSW_MASK_BIT_12;
	ret |= psw_addr;
	return ret;
}

static int write_short_psw(FILE *f, struct psw_t *psw, GError **err)
{
	uint64_t short_psw, short_psw_be;

	g_assert(err);

	short_psw = convert_psw_to_short_psw(psw, err);
	if (*err)
		return -1;

	short_psw_be = GUINT64_TO_BE(short_psw);
	return file_write(f, &short_psw_be, 1, sizeof(short_psw_be), NULL, err);
}

int pv_img_write(PvImage *img, const char *path, GError **err)
{
	int ret = -1;
	FILE *f = file_open(path, "wb", err);

	if (!f)
		return -1;

	if (write_short_psw(f, &img->stage3a_psw, err) < 0)
		goto err;

	if (seek_and_write_buffer(f, img->stage3a, STAGE3A_LOAD_ADDRESS, err) < 0)
		goto err;

	/* list is sorted by component type => by address */
	for (GSList *iterator = pv_img_comps_get_comps(img->comps); iterator;
	     iterator = iterator->next) {
		int rc;
		const PvComponent *comp = iterator->data;

		rc = pv_component_write(comp, f, err);
		if (rc < 0)
			goto err;
	}

	ret = 0;
err:
	if (f)
		fclose(f);
	return ret;
}
