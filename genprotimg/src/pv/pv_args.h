/*
 * PV arguments related definitions and functions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PV_ARGS_H
#define PV_ARGS_H

#include <glib.h>

#include "pv_comp.h"

typedef struct pv_arg {
	PvComponentType type;
	gchar *path;
} PvArg;

PvArg *pv_arg_new(PvComponentType type, const char *path);
void pv_arg_free(PvArg *arg);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(PvArg, pv_arg_free);

int pv_arg_compare(gconstpointer arg_1, gconstpointer arg_2);
int pv_arg_has_type(gconstpointer arg, gconstpointer type);

typedef struct {
	int log_level;
	int no_cert_check;
	char *pcf;
	char *scf;
	char *psw_addr; /* PSW address which will be used for the start of
			 * the actual component (e.g. Linux kernel)
			 */
	char *cust_root_key_path;
	char *cust_comm_key_path;
	char *gcm_iv_path;
	char **host_certs;
	char *xts_key_path;
	GSList *comps;
	char *output_path;
	char *tmp_dir;
} PvArgs;

PvArgs *pv_args_new(void);
void pv_args_free(PvArgs *args);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(PvArgs, pv_args_free)

int pv_args_parse_options(PvArgs *args, gint *argc, gchar **argv[], GError **err);

#endif
