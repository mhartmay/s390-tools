/*
 * PV arguments related definitions and functions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdlib.h>

#include <glib.h>
#include <glib/gprintf.h>

#include "common.h"
#include "pv_args.h"
#include "pv/pv_error.h"
#include "pv/pv_comp.h"

static gchar summary[] =
	"Essentially, this program called 'genprotimg' takes a kernel, key files,\n"
	"and optionally an initial ram filesystem, and optionally a file containing\n"
	"the kernel command line parameters and generates a single loadable image\n"
	"file. This created image file consists of a concatenation of a plain text\n"
	"boot loader, the encrypted components for kernel, initrd, and cmdline,\n"
	"and the integrity-protected PV header, containing metadata necessary for\n"
	"running the guest in PV mode.\n\n"
	"It's possible to use this image file as a kernel for zipl or for a direct\n"
	"kernel boot using QEMU.";

static int pv_args_set_defaults(PvArgs *args, GError **err G_GNUC_UNUSED)
{
	if (!args->psw_addr)
		args->psw_addr = g_strdup_printf("0x%lx", DEFAULT_INITIAL_PSW_ADDR);

	return 0;
}

static int pv_args_validate_options(PvArgs *args, GError **err)
{
	PvComponentType KERNEL = PV_COMP_TYPE_KERNEL;

	if (!args->output_path) {
		g_set_error(err, PV_ERROR, PR_ERROR_PARSE_MISSING_ARGUMENT,
			    "'--output' option is missing");
		return -1;
	}

	if (!g_slist_find_custom(args->comps, &KERNEL, pv_arg_has_type)) {
		g_set_error(err, PV_ERROR, PR_ERROR_PARSE_MISSING_ARGUMENT,
			    "'--image' option is missing");
		return -1;
	}

	if (!args->host_certs || g_strv_length(args->host_certs) == 0) {
		g_set_error(err, PV_ERROR, PR_ERROR_PARSE_MISSING_ARGUMENT,
			    "'--host-cert' option is missing");
		return -1;
	}

	if (!args->no_cert_check) {
		g_set_error(err, PV_ERROR, PR_ERROR_PARSE_MISSING_ARGUMENT,
			    "Please use the option '--no-cert-check' as the verification"
			    " support is not available yet.");
		return -1;
	}

	return 0;
}

static gboolean add_component(const gchar *option, const gchar *value, PvArgs *args, GError **err)
{
	int type = -1;
	PvArg *comp = NULL;

	if (g_str_equal(option, "-i") || g_str_equal(option, "--image"))
		type = PV_COMP_TYPE_KERNEL;
	if (g_str_equal(option, "-r") || g_str_equal(option, "--ramdisk"))
		type = PV_COMP_TYPE_INITRD;
	if (g_str_equal(option, "-p") || g_str_equal(option, "--parmfile"))
		type = PV_COMP_TYPE_CMDLINE;

	if (type < 0) {
		g_set_error(err, PV_ERROR, PV_ERROR_PARSE_SYNTAX, _("Invalid option '%s': "),
			    option);
		return FALSE;
	}

	if (g_slist_find_custom(args->comps, &type, pv_arg_has_type)) {
		g_set_error(err, PV_ERROR, PV_ERROR_PARSE_SYNTAX,
			    _("Multiple values for option '%s'"), option);
		return FALSE;
	}

	comp = pv_arg_new((PvComponentType)type, value);
	args->comps = g_slist_insert_sorted(args->comps, comp, pv_arg_compare);
	return TRUE;
}

static gboolean set_string_option(const gchar *option, const gchar *value, PvArgs *args,
				  GError **err)
{
	char **args_option = NULL;

	if (g_str_equal(option, "-o") || g_str_equal(option, "--output"))
		args_option = &args->output_path;
	if (g_str_equal(option, "--header-key"))
		args_option = &args->cust_root_key_path;
	if (g_str_equal(option, "--comp-key"))
		args_option = &args->xts_key_path;
	if (g_str_equal(option, "--x-comm-key"))
		args_option = &args->cust_comm_key_path;
	if (g_str_equal(option, "--x-pcf"))
		args_option = &args->pcf;
	if (g_str_equal(option, "--x-psw"))
		args_option = &args->psw_addr;
	if (g_str_equal(option, "--x-scf"))
		args_option = &args->scf;

	if (!args_option) {
		g_set_error(err, PV_ERROR, PV_ERROR_PARSE_SYNTAX, _("Invalid option '%s': "),
			    option);
		return FALSE;
	}

	if (*args_option) {
		g_set_error(err, PV_ERROR, PV_ERROR_PARSE_SYNTAX,
			    _("Multiple values for option '%s'"), option);
		return FALSE;
	}

	*args_option = g_strdup(value);
	return TRUE;
}

static gboolean set_verbose(const gchar *option G_GNUC_UNUSED, const gchar *value G_GNUC_UNUSED,
			    PvArgs *args, GError **err G_GNUC_UNUSED)
{
	args->log_level++;
	return TRUE;
}

#define INDENT "                                  "

int pv_args_parse_options(PvArgs *args, gint *argc, gchar **argv[], GError **err)
{
	gboolean print_version = FALSE;
	GOptionGroup *group, *x_group;
	g_autoptr(GOptionContext) context = NULL;
	g_autofree gchar *psw_desc = g_strdup_printf(
		_("Use the address ADDRESS to load from (optional, default: '0x%lx')\n" INDENT
		  "Must be a hexadecimal value"),
		DEFAULT_INITIAL_PSW_ADDR);
	GOptionEntry entries[] = {
		{ .long_name = "host-certificate",
		  .short_name = 'c',
		  .flags = G_OPTION_FLAG_NONE,
		  .arg = G_OPTION_ARG_FILENAME_ARRAY,
		  .arg_data = &args->host_certs,
		  .description =
			  _("Use FILE as a host certificate. At least one host certificate must be specified"),
		  .arg_description = _("FILE") },
		{ .long_name = "output",
		  .short_name = 'o',
		  .flags = G_OPTION_FLAG_FILENAME,
		  .arg = G_OPTION_ARG_CALLBACK,
		  .arg_data = set_string_option,
		  .description = _("Set FILE as the output file"),
		  .arg_description = _("FILE") },
		{ .long_name = "image",
		  .short_name = 'i',
		  .flags = G_OPTION_FLAG_FILENAME,
		  .arg = G_OPTION_ARG_CALLBACK,
		  .arg_data = add_component,
		  .description = _("Use FILE as the Linux kernel image"),
		  .arg_description = _("FILE") },
		{ .long_name = "ramdisk",
		  .short_name = 'r',
		  .flags = G_OPTION_FLAG_OPTIONAL_ARG | G_OPTION_FLAG_FILENAME,
		  .arg = G_OPTION_ARG_CALLBACK,
		  .arg_data = add_component,
		  .description = _("Use FILE as the initial ramdisk (optional)"),
		  .arg_description = _("FILE") },
		{ .long_name = "parmfile",
		  .short_name = 'p',
		  .flags = G_OPTION_FLAG_OPTIONAL_ARG | G_OPTION_FLAG_FILENAME,
		  .arg = G_OPTION_ARG_CALLBACK,
		  .arg_data = add_component,
		  .description = _("Use content of FILE as the kernel cmdline (optional)"),
		  .arg_description = _("FILE") },
		{ .long_name = "header-key",
		  .short_name = 0,
		  .flags = G_OPTION_FLAG_FILENAME,
		  .arg = G_OPTION_ARG_CALLBACK,
		  .arg_data = set_string_option,
		  .description = _(
			  "Use FILE as the AES 256-bit GCM customer root key (optional, default: auto generation)\n" INDENT
			  "This key protects the PV header (confidentiality and integrity)"),
		  .arg_description = _("FILE") },
		{ .long_name = "comp-key",
		  .short_name = 0,
		  .flags = G_OPTION_FLAG_FILENAME,
		  .arg = G_OPTION_ARG_CALLBACK,
		  .arg_data = set_string_option,
		  .description = _(
			  "Use FILE as the AES 256-bit XTS key (optional, default: auto generation)\n" INDENT
			  "This key is used for the component encryption"),
		  .arg_description = _("FILE") },
		{ .long_name = "no-cert-check",
		  .short_name = 0,
		  .flags = G_OPTION_FLAG_NONE,
		  .arg = G_OPTION_ARG_NONE,
		  .arg_data = &args->no_cert_check,
		  .description = _("Disable the certification check (optional)"),
		  .arg_description = NULL },
		{ .long_name = "verbose",
		  .short_name = 'V',
		  .flags = G_OPTION_FLAG_NO_ARG,
		  .arg = G_OPTION_ARG_CALLBACK,
		  .arg_data = set_verbose,
		  .description = _("Print memory layout (optional)"),
		  .arg_description = NULL },
		{ .long_name = "version",
		  .short_name = 'v',
		  .flags = G_OPTION_FLAG_NONE,
		  .arg = G_OPTION_ARG_NONE,
		  .arg_data = &print_version,
		  .description = _("Print version and exit (optional)"),
		  .arg_description = NULL },
		{ 0 },
	};

	GOptionEntry x_entries[] = {
		{ .long_name = "x-comm-key",
		  .short_name = 0,
		  .flags = G_OPTION_FLAG_FILENAME,
		  .arg = G_OPTION_ARG_CALLBACK,
		  .arg_data = set_string_option,
		  .description = _(
			  "Use FILE as the customer communication key (optional, default: auto generation)"),
		  .arg_description = _("FILE") },
		{ .long_name = "x-pcf",
		  .short_name = 0,
		  .flags = G_OPTION_FLAG_NONE,
		  .arg = G_OPTION_ARG_CALLBACK,
		  .arg_data = set_string_option,
		  .description =
			  _("Use VALUE as the plaintext control flags (optional, default: '0x0')\n" INDENT
			    "Must be a hexadecimal value"),
		  .arg_description = _("VALUE") },
		{ .long_name = "x-psw",
		  .short_name = 0,
		  .flags = G_OPTION_FLAG_NONE,
		  .arg = G_OPTION_ARG_CALLBACK,
		  .arg_data = set_string_option,
		  .description = psw_desc,
		  .arg_description = _("ADDRESS") },
		{ .long_name = "x-scf",
		  .short_name = 0,
		  .flags = G_OPTION_FLAG_NONE,
		  .arg = G_OPTION_ARG_CALLBACK,
		  .arg_data = set_string_option,
		  .description = _("Use VALUE as the secret control flags (optional, default: '0x0')\n" INDENT
				   "Must be a hexadecimal value"),
		  .arg_description = _("VALUE") },
		{ 0 },
	};

	context = g_option_context_new(_("- Create a Protected Virtualization Image"));
	g_option_context_set_summary(context, _(summary));
	group = g_option_group_new(GETTEXT_PACKAGE, _("Application Options:"),
				   _("Show help options"),
				   args, NULL);
	g_option_group_add_entries(group, entries);
	g_option_context_set_main_group(context, group);

	x_group = g_option_group_new("experimental",
				     _("Experimental options:"),
				     _("Show experimental options"),
				     args, NULL);
	g_option_group_add_entries(x_group, x_entries);
	g_option_context_add_group(context, x_group);
	if (!g_option_context_parse(context, argc, argv, err))
		return -1;

	if (print_version) {
		g_printf(_("%s version %s\n"), tool_name, RELEASE_STRING);
		g_printf("%s\n", copyright_notice);
		exit(EXIT_SUCCESS);
	}

	if (pv_args_set_defaults(args, err) < 0)
		return -1;

	return pv_args_validate_options(args, err);
}

PvArgs *pv_args_new(void)
{
	g_autoptr(PvArgs) args = g_new0(PvArgs, 1);

	return g_steal_pointer(&args);
}

void pv_args_free(PvArgs *args)
{
	if (!args)
		return;

	g_free(args->pcf);
	g_free(args->scf);
	g_free(args->psw_addr);
	g_free(args->cust_root_key_path);
	g_free(args->cust_comm_key_path);
	g_free(args->gcm_iv_path);
	g_strfreev(args->host_certs);
	g_free(args->xts_key_path);
	g_slist_free_full(args->comps, (GDestroyNotify)pv_arg_free);
	g_free(args->output_path);
	g_free(args->tmp_dir);
	g_free(args);
}

int pv_arg_compare(gconstpointer arg_1, gconstpointer arg_2)
{
	g_assert(arg_1);
	g_assert(arg_2);

	PvComponentType a = ((PvArg *)arg_1)->type;
	PvComponentType b = ((PvArg *)arg_2)->type;

	if (a < b)
		return -1;
	if (a == b)
		return 0;
	return 1;
}

int pv_arg_has_type(gconstpointer arg, gconstpointer type)
{
	const PvArg *c = arg;
	const PvComponentType *t = type;

	g_assert(arg);

	if (c->type == *t)
		return 0;
	if (c->type < *t)
		return -1;
	return 1;
}

void pv_arg_free(PvArg *arg)
{
	if (!arg)
		return;

	g_free(arg->path);
	g_free(arg);
}
PvArg *pv_arg_new(PvComponentType type, const char *path)
{
	g_autoptr(PvArg) ret = g_new0(struct pv_arg, 1);

	ret->type = type;
	ret->path = g_strdup(path);
	return g_steal_pointer(&ret);
}
