/*
 * General file utils
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PV_FILE_UTILS_H
#define PV_FILE_UTILS_H

#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <glib/gtypes.h>

#include "pv/pv_comp.h"

#include "buffer.h"

FILE *file_open(const char *filename, const char *mode, GError **err);
int file_size(const char *filename, gsize *size, GError **err);
int file_read(FILE *in, void *ptr, size_t size, size_t count, size_t *count_read, GError **err);
int file_write(FILE *out, const void *ptr, size_t size, size_t count, size_t *count_written,
	       GError **err);
int pad_file_right(FILE *f_out, FILE *f_in, size_t *size_out, unsigned int padding, GError **err);
int seek_and_write_buffer(FILE *out, const Buffer *buf, uint64_t offset, GError **err);
int seek_and_write_file(FILE *o, const CompFile *ifile, uint64_t offset, GError **err);

#endif
