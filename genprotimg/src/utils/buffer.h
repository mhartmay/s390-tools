/*
 * Buffer definition and functions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef BUFFER_H
#define BUFFER_H

#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <glib.h>

#include "common.h"

typedef struct Buffer {
	void *data;
	size_t size; /* in bytes */
} Buffer;

Buffer *buffer_alloc(size_t size);
void buffer_free(Buffer *buf);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(Buffer, buffer_free)
void buffer_clear(Buffer **buf);
int buffer_write(const Buffer *buf, FILE *file, GError **err);
Buffer *buffer_dup(const Buffer *buf, bool page_aligned);

#endif
