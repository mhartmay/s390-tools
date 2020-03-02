/*
 * genprotimg - build relocatable secure images
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <locale.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <glib/gtypes.h>

#include "common.h"
#include "pv/pv_image.h"
#include "pv/pv_args.h"

enum {	LOGLEVEL_CRITICAL = 0,
	LOGLEVEL_INFO = 1,
	LOGLEVEL_DEBUG = 2,
};

static gint debug_level;
static gchar *tmp_dir;

static void rmdir_recursive(gchar *dir_path, GError **err)
{
	const gchar *file = NULL;
	g_autoptr(GDir) d = NULL;

	if (!dir_path)
		return;

	d = g_dir_open(dir_path, 0, err);
	if (!d) {
		g_set_error(err, G_FILE_ERROR, (gint)g_file_error_from_errno(errno),
			    _("Failed to open directory '%s': %s"), dir_path, g_strerror(errno));
		return;
	}

	while ((file = g_dir_read_name(d)) != NULL) {
		g_autofree gchar *file_path = g_build_filename(dir_path, file, NULL);
		/* ignore error */
		(void)g_unlink(file_path);
	}

	if (g_rmdir(dir_path) != 0) {
		g_set_error(err, G_FILE_ERROR, (gint)g_file_error_from_errno(errno),
			    _("Failed to remove directory '%s': %s"), dir_path, g_strerror(errno));
		return;
	}
}

static void sig_term_handler(int signal G_GNUC_UNUSED)
{
	rmdir_recursive(tmp_dir, NULL);
	exit(EXIT_FAILURE);
}

static void log_handler_cb(const gchar *log_domain G_GNUC_UNUSED, GLogLevelFlags log_level,
			   const gchar *message, gpointer user_data G_GNUC_UNUSED)
{
	const gchar *prefix = "";

	/* filter out messages depending on debugging level */
	if ((log_level & G_LOG_LEVEL_DEBUG) && debug_level < LOGLEVEL_DEBUG)
		return;

	if ((log_level & G_LOG_LEVEL_INFO) && debug_level < LOGLEVEL_INFO)
		return;

	if (log_level & G_LOG_LEVEL_WARNING)
		prefix = "WARNING: ";

	if (log_level & G_LOG_LEVEL_ERROR)
		prefix = "ERROR: ";

	if (log_level & (G_LOG_LEVEL_WARNING | G_LOG_LEVEL_ERROR))
		g_printerr("%s%s\n", prefix, message);
	else
		g_print("%s%s\n", prefix, message);
}

static void setup_prgname(const gchar *name)
{
	g_set_prgname(name);
	g_set_application_name(_(name));
}

static void setup_handler(const gint *signals, const gsize signals_n)
{
	/* set up logging handler */
	g_log_set_handler(NULL, G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION,
			  log_handler_cb, NULL);

	/* set signal handler */
	for (gsize i = 0; i < signals_n; i++)
		signal(signals[i], sig_term_handler);
}

static void remove_signal_handler(const gint *signals, const gsize signals_n)
{
	for (gsize i = 0; i < signals_n; i++)
		signal(signals[i], SIG_DFL);
}

/* Main idea:
 * 1. prepare components: stage3b depends on: address of the
 *    components (tweaks: depends on component type + relative
 *    addresses)
 *    comp = prepare_component (encryption/size alignment) -> needs: keys
 *    + tweak
 * 2. add stub stage3a (so we can calculate the memory addresses)
 * 3. add other components(): calc src, dest, and hashes
 * 4. build and add stage3b: calculate the hashes
 * 5. update stage3a
 */
int main(int argc, char *argv[])
{
	int ret = EXIT_FAILURE;
	GError *err = NULL;
	gint signals[] = { SIGINT, SIGTERM };
	g_autoptr(PvArgs) pv_args = pv_args_new();
	g_autoptr(PvImage) img = NULL;

	setlocale(LC_CTYPE, "");
	setup_prgname(tool_name);
	setup_handler(signals, G_N_ELEMENTS(signals));

	if (pv_args_parse_options(pv_args, &argc, &argv, &err) < 0)
		goto error;

	/* create a temporary directory which will be used for the
	 * preparation of the user components */
	pv_args->tmp_dir = g_dir_make_tmp("genprotimg-XXXXXX", &err);

	/* set new log level */
	debug_level = pv_args->log_level;

	if (pv_args->no_cert_check)
		g_warning(_("Certificate check is disabled. Please be aware that"
			    " this is insecure."));

	/* allocate and initialize ``pv_img`` data structure */
	img = pv_img_new(pv_args, GENPROTIMG_STAGE3A_PATH, &err);
	if (!img)
		goto error;

	/* add user components */
	/* the args must be sorted by the component type => by guest address */
	for (GSList * iterator = pv_args->comps; iterator; iterator = iterator->next) {
		const PvArg *arg = iterator->data;

		if (pv_img_add_component(img, arg, &err) < 0)
			goto error;
	}

	if (pv_img_finalize(img, GENPROTIMG_STAGE3B_PATH, &err) < 0)
		goto error;

	if (pv_img_write(img, pv_args->output_path, &err) < 0)
		goto error;

	ret = EXIT_SUCCESS;

error:
	if (err) {
		fputs(err->message, stderr);
		fputc('\n', stderr);
		g_clear_error(&err);
	}
	rmdir_recursive(pv_args->tmp_dir, NULL);
	remove_signal_handler(signals, G_N_ELEMENTS(signals));
	exit(ret);
}
