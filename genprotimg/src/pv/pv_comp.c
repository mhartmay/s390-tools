/*
 * PV component related definitions and functions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <glib/gtypes.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#include "common.h"
#include "utils/align.h"
#include "utils/file_utils.h"
#include "boot/s390.h"
#include "utils/buffer.h"
#include "utils/crypto.h"

#include "pv_comp.h"
#include "pv_error.h"

static void comp_file_free(CompFile *comp)
{
	if (!comp)
		return;

	g_free(comp->path);
	g_free(comp);
}
G_DEFINE_AUTOPTR_CLEANUP_FUNC(CompFile, comp_file_free)

static PvComponent *pv_component_new(PvComponentType type, size_t size, PvComponentDataType d_type,
				     void **data, GError **err)
{
	g_autoptr(PvComponent) ret = g_new0(PvComponent, 1);

	g_assert(type >= 0 && type < UINT16_MAX);

	ret->type = (int)type;
	ret->d_type = (int)d_type;
	ret->data = g_steal_pointer(data);
	ret->orig_size = size;

	if (generate_tweak(&ret->tweak, (uint16_t)type, err) < 0)
		return NULL;

	return g_steal_pointer(&ret);
}

PvComponent *pv_component_new_file(PvComponentType type, const char *path, GError **err)
{
	int rc;
	size_t size;
	g_autoptr(CompFile) file = g_new0(struct comp_file, 1);

	g_assert(path != NULL);

	rc = file_size(path, &size, err);
	if (rc < 0)
		return NULL;

	file->path = g_strdup(path);
	file->size = size;
	return pv_component_new(type, size, DATA_FILE, (void **)&file, err);
}

PvComponent *pv_component_new_buf(PvComponentType type, const Buffer *buf, GError **err)
{
	g_assert(buf);

	g_autoptr(Buffer) dup_buf = buffer_dup(buf, false);
	return pv_component_new(type, buf->size, DATA_BUFFER, (void **)&dup_buf, err);
}

void pv_component_free(PvComponent *component)
{
	if (!component)
		return;

	switch ((PvComponentDataType)component->d_type) {
	case DATA_BUFFER:
		buffer_clear(&component->buf);
		break;
	case DATA_FILE:
		comp_file_free(component->file);
		break;
	}

	g_free(component);
}

int pv_component_type(const PvComponent *component)
{
	return component->type;
}

const char *pv_component_name(const PvComponent *component)
{
	int type = pv_component_type(component);

	switch ((PvComponentType)type) {
	case PV_COMP_TYPE_KERNEL:
		return "kernel";
	case PV_COMP_TYPE_INITRD:
		return "ramdisk";
	case PV_COMP_TYPE_CMDLINE:
		return "parmline";
	case PV_COMP_TYPE_STAGE3B:
		return "stage3b";
	}

	g_abort();
}

uint64_t pv_component_size(const PvComponent *component)
{
	switch ((PvComponentDataType)component->d_type) {
	case DATA_BUFFER:
		return component->buf->size;
	case DATA_FILE:
		return component->file->size;
	}

	g_assert_not_reached();
}

uint64_t pv_component_get_src_addr(const PvComponent *component)
{
	return component->src_addr;
}

uint64_t pv_component_get_orig_size(const PvComponent *component)
{
	return component->orig_size;
}

uint64_t pv_component_get_tweak_prefix(const PvComponent *component)
{
	return GUINT64_FROM_BE(component->tweak.cmp_idx.data);
}

bool pv_component_is_stage3b(const PvComponent *component)
{
	return pv_component_type(component) == PV_COMP_TYPE_STAGE3B;
}

int pv_component_align_and_encrypt(PvComponent *component, const char *tmp_path, void *opaque,
				   GError **err)
{
	struct cipher_parms *parms = opaque;

	switch ((PvComponentDataType)component->d_type) {
	case DATA_BUFFER: {
		g_autoptr(Buffer) enc_buf = NULL;
		if (!(IS_PAGE_ALIGNED(pv_component_size(component)))) {
			g_autoptr(Buffer) new = NULL;
			/* create a page aligned copy */
			new = buffer_dup(component->buf, true);
			buffer_clear(&component->buf);
			component->buf = g_steal_pointer(&new);
		}
		enc_buf = encrypt_buf(parms, component->buf, err);
		if (!enc_buf)
			return -1;

		buffer_clear(&component->buf);
		component->buf = g_steal_pointer(&enc_buf);
		return 0;
	}
	case DATA_FILE: {
		size_t orig_size;
		size_t prep_size;
		gchar *path_in = component->file->path;
		const char *comp_name = pv_component_name(component);
		g_autofree char *path_out = NULL;

		g_assert(path_in);

		path_out = g_build_filename(tmp_path, comp_name, NULL);
		if (encrypt_file(parms, path_in, path_out, &orig_size, &prep_size, err) < 0)
			return -1;

		if (component->orig_size != orig_size) {
			g_set_error(err, G_FILE_ERROR, PV_ERROR_INTERNAL,
				    _("File has changed during the preparation '%s'"), path_out);
			return -1;
		}

		g_free(path_in);
		component->file->size = prep_size;
		component->file->path = g_steal_pointer(&path_out);
		return 0;
	}
	}

	g_assert_not_reached();
}

/* Page align the size of the component */
int pv_component_align(PvComponent *component, const char *tmp_path, void *opaque G_GNUC_UNUSED,
		       GError **err)
{
	int ret = -1;
	FILE *f_in = NULL, *f_out = NULL;
	g_autoptr(Buffer) buf = NULL;

	if (IS_PAGE_ALIGNED(pv_component_size(component)))
		return 0;

	switch (component->d_type) {
	case DATA_BUFFER: {
		buf = buffer_dup(component->buf, true);
		buffer_clear(&component->buf);
		component->buf = g_steal_pointer(&buf);
	} break;
	case DATA_FILE: {
		size_t size_out;
		gchar *path_in = component->file->path;
		const char *comp_name = pv_component_name(component);
		g_autofree gchar *path_out = g_build_filename(tmp_path, comp_name, NULL);

		f_in = file_open(path_in, "rb", err);
		if (!f_in)
			goto err;
		f_out = file_open(path_out, "wb", err);
		if (!f_out)
			goto err;

		if (pad_file_right(f_out, f_in, &size_out, PAGE_SIZE, err) < 0)
			goto err;

		g_free(path_in);
		component->file->path = g_steal_pointer(&path_out);
		component->file->size = size_out;
	} break;
	}

	ret = 0;
err:
	if (f_out)
		fclose(f_out);
	if (f_in)
		fclose(f_in);
	return ret;
}

/* Convert uint64_t address to byte array */
static void uint64_to_uint8_buf(uint8_t dest[8], uint64_t addr)
{
	uint8_t *p = (uint8_t *)&addr;

	for (int i = 0; i < 8; i++)
		dest[i] = p[i];
}

/* Handle empty components as well (needs one page) */
int64_t pv_component_update_ald(const PvComponent *comp, EVP_MD_CTX *ctx, GError **err)
{
	g_assert(comp);

	int64_t nep = 0;
	uint64_t addr = pv_component_get_src_addr(comp);
	uint64_t size = pv_component_size(comp);
	uint64_t cur = addr;

	do {
		uint8_t addr_buf[8];
		uint64_t cur_be = GUINT64_TO_BE(cur);
		uint64_to_uint8_buf(addr_buf, cur_be);

		if (EVP_DigestUpdate(ctx, addr_buf, sizeof(addr_buf)) != 1) {
			g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
				    _("EVP_DigestUpdate failed"));
			return -1;
		}

		cur += PAGE_SIZE;
		nep++;
	} while (cur < addr + size);

	return nep;
}

/* Handle empty components as well (needs one page) */
int64_t pv_component_update_pld(const PvComponent *comp, EVP_MD_CTX *ctx, GError **err)
{
	g_assert(comp);

	int64_t nep = 0;

	switch (comp->d_type) {
	case DATA_BUFFER: {
		Buffer *buf = comp->buf;
		unsigned long quot = buf->size / PAGE_SIZE;
		unsigned int remaind = buf->size % PAGE_SIZE;
		g_assert(quot <= INT64_MAX);

		/* case `buf->size == 0` */
		nep = quot ? (int64_t)quot : 1;

		if (EVP_DigestUpdate(ctx, buf->data, quot * PAGE_SIZE) != 1) {
			g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
				    _("EVP_DigestUpdate failed"));
			return -1;
		}

		if (remaind != 0) {
			uint8_t in_buf[PAGE_SIZE] = { 0 };
			memcpy(in_buf, buf->data + quot * PAGE_SIZE, remaind);

			if (EVP_DigestUpdate(ctx, in_buf, PAGE_SIZE) != 1) {
				g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
					    _("EVP_DigestUpdate failed"));
				return -1;
			}
			nep++;
		}
		break;
	}
	case DATA_FILE: {
		const char *in_path = comp->file->path;
		unsigned char in_buf[PAGE_SIZE];
		size_t num_bytes_read = 0;
		size_t num_bytes_read_total = 0;

		FILE *f_in = file_open(in_path, "rb", err);
		if (!f_in)
			return -1;

		do {
			memset(in_buf, 0, sizeof(in_buf));

			/* Read data in blocks. Update the digest
			 * context each read. */
			if (file_read(f_in, in_buf, sizeof(unsigned char), sizeof(in_buf),
				      &num_bytes_read, err) < 0) {
				fclose(f_in);
				return -1;
			}
			num_bytes_read_total += num_bytes_read;

			if (EVP_DigestUpdate(ctx, in_buf, sizeof(in_buf)) != 1) {
				g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
					    _("EVP_DigestUpdate failed"));
				fclose(f_in);
				return -1;
			}

			nep++;
		} while (num_bytes_read_total < pv_component_size(comp) && num_bytes_read != 0);

		if (num_bytes_read_total != pv_component_size(comp)) {
			g_set_error(err, G_FILE_ERROR, PV_ERROR_INTERNAL,
				    _("File '%s' has changed during the preparation"), in_path);
			fclose(f_in);
			return -1;
		}
		fclose(f_in);
	}
	}

	return nep;
}

/* Handle empty components as well (needs one page) */
int64_t pv_component_update_tld(const PvComponent *comp, EVP_MD_CTX *ctx, GError **err)
{
	int64_t nep = 0;
	uint64_t size = pv_component_size(comp);
	const union tweak *tweak = &comp->tweak;
	g_autoptr(BIGNUM) tweak_num = BN_bin2bn(tweak->data, sizeof(tweak->data), NULL);

	for (uint64_t cur = 0; cur < size || cur == 0; cur += PAGE_SIZE) {
		unsigned char tmp[sizeof(tweak->data)] = { 0 };

		g_assert(BN_num_bytes(tweak_num) >= 0);
		g_assert(sizeof(tmp) - (unsigned int)BN_num_bytes(tweak_num) > 0);

		if (BN_bn2binpad(tweak_num, tmp, sizeof(tmp)) < 0) {
			g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
				    "BN_bn2binpad failed");
		};

		if (EVP_DigestUpdate(ctx, tmp, sizeof(tmp)) != 1) {
			g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
				    _("EVP_DigestUpdate failed"));
			return -1;
		}

		/* set new tweak value */
		if (BN_add_word(tweak_num, PAGE_SIZE) != 1) {
			g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
				    "BN_add_word failed");
		}

		nep++;
	}

	return nep;
}

int pv_component_write(const PvComponent *component, FILE *f, GError **err)
{
	g_assert(component);

	switch (component->d_type) {
	case DATA_BUFFER: {
		Buffer *buf = component->buf;
		uint64_t offset = pv_component_get_src_addr(component);

		if (seek_and_write_buffer(f, buf, offset, err) < 0)
			return -1;

		return 0;
	}
	case DATA_FILE: {
		const CompFile *file = component->file;
		uint64_t offset = pv_component_get_src_addr(component);

		if (seek_and_write_file(f, file, offset, err) < 0)
			return -1;

		return 0;
	}
	}

	g_assert_not_reached();
}
