/*
 * General file utils
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <glib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include "glib/gstdio.h"

#include "pv/pv_error.h"

#include "align.h"
#include "buffer.h"
#include "common.h"
#include "file_utils.h"

FILE *file_open(const char *filename, const char *mode, GError **err)
{
	FILE *f = fopen(filename, mode);

	if (!f) {
		g_set_error(err, G_FILE_ERROR, (gint)g_file_error_from_errno(errno),
			    _("Failed to open file '%s': %s"), filename, g_strerror(errno));
		return NULL;
	}

	return f;
}

int file_size(const char *filename, gsize *size, GError **err)
{
	int rc;
	GStatBuf st_buf;

	rc = g_stat(filename, &st_buf);
	if (rc != 0) {
		g_set_error(err, G_FILE_ERROR, (gint)g_file_error_from_errno(errno),
			    _("Failed to stat file '%s': %s"), filename, g_strerror(errno));
		return -1;
	}

	if (!S_ISREG(st_buf.st_mode)) {
		g_set_error(err, G_FILE_ERROR, PV_ERROR_INTERNAL,
			    _("File '%s' is not a regular file"), filename);
		return -1;
	}

	if (st_buf.st_size < 0) {
		g_set_error(err, G_FILE_ERROR, PV_ERROR_INTERNAL,
			    _("Invalid file size for '%s': %zu"), filename, st_buf.st_size);
		return -1;
	}

	*size = (gsize)st_buf.st_size;
	return 0;
}

/* Returns 0 on success, otherwise -1. Stores the total number of
 * elements successfully read in @count_read */
int file_read(FILE *in, void *ptr, size_t size, size_t count, size_t *count_read, GError **err)
{
	size_t tmp_count_read;

	tmp_count_read = fread(ptr, size, count, in);
	if (count_read)
		*count_read = tmp_count_read;

	if (ferror(in)) {
		g_set_error(err, G_FILE_ERROR, 0, _("Failed to read file"));
		return -1;
	}

	return 0;
}

int file_write(FILE *out, const void *ptr, size_t size, size_t count, size_t *count_written,
	       GError **err)
{
	size_t tmp_count_written;

	tmp_count_written = fwrite(ptr, size, count, out);
	if (count_written)
		*count_written = tmp_count_written;
	if (tmp_count_written != count) {
		g_set_error(err, G_FILE_ERROR, (gint)g_file_error_from_errno(errno),
			    _("Failed to write: '%s'"), g_strerror(errno));
		return -1;
	}

	if (ferror(out)) {
		g_set_error(err, G_FILE_ERROR, 0, _("Failed to write file"));
		return -1;
	}

	return 0;
}

static int file_seek(FILE *f, uint64_t offset, GError **err)
{
	int rc;

	if (offset > LONG_MAX) {
		g_set_error(err, PV_ERROR, 0, _("Offset is too large"));
		return -1;
	}

	rc = fseek(f, (long)offset, SEEK_SET);
	if (rc != 0) {
		g_set_error(err, G_FILE_ERROR, (gint)g_file_error_from_errno(errno),
			    _("Failed to seek: '%s'"), g_strerror(errno));
		return -1;
	}

	return 0;
}

int seek_and_write_file(FILE *o, const CompFile *ifile, uint64_t offset, GError **err)
{
	int ret = -1;
	FILE *i = NULL;
	char buf[4096];
	size_t bytes_read, bytes_written;
	size_t total_bytes_read = 0;

	if (file_seek(o, offset, err) < 0)
		return -1;

	i = file_open(ifile->path, "rb", err);
	if (!i)
		return -1;

	do {
		if (file_read(i, buf, 1, sizeof(buf), &bytes_read, err) < 0)
			goto err;

		if (bytes_read == 0)
			break;
		total_bytes_read += bytes_read;

		if (file_write(o, buf, bytes_read, 1, &bytes_written, err) < 0)
			goto err;
	} while (bytes_written != 0);

	if (ifile->size != total_bytes_read) {
		g_set_error(err, PV_ERROR, PV_ERROR_INTERNAL,
			    _("File '%s' has changed during the preparation"), ifile->path);
		goto err;
	}

	ret = 0;
err:
	fclose(i);
	return ret;
}

int seek_and_write_buffer(FILE *o, const Buffer *buf, uint64_t offset, GError **err)
{
	if (file_seek(o, offset, err) < 0)
		return -1;

	if (buffer_write(buf, o, err) < 0)
		return -1;

	return 0;
}

/* Could be optimized... determine the length and remove unnecessary
 * memsets and adapt buffer sizes */
int pad_file_right(FILE *f_out, FILE *f_in, size_t *size_out, unsigned int padding, GError **err)
{
	unsigned char buf[padding];
	uint64_t size_in = 0;
	size_t num_bytes_read;
	size_t num_bytes_written;
	*size_out = 0;

	do {
		memset(buf, 0, sizeof(buf));
		/* Read in data in 4096 bytes blocks. Update the ciphering
		 * with each read. */
		if (file_read(f_in, buf, 1, sizeof(buf), &num_bytes_read, err) < 0)
			return -1;

		size_in += num_bytes_read;

		if (file_write(f_out, buf, 1, sizeof(buf), &num_bytes_written, err))
			return -1;

		*size_out += num_bytes_written;
	} while (num_bytes_read == padding);

	g_assert(num_bytes_written == ALIGN(num_bytes_read, padding));
	return 0;
}
