/* package.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
 */

#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdio.h>
#include <limits.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#include <openssl/pem.h>

#include "apk_defines.h"
#include "apk_archive.h"
#include "apk_package.h"
#include "apk_database.h"
#include "apk_state.h"

struct apk_package *apk_pkg_new(void)
{
	struct apk_package *pkg;

	pkg = calloc(1, sizeof(struct apk_package));
	if (pkg != NULL)
		list_init(&pkg->installed_pkgs_list);

	return pkg;
}

int apk_pkg_parse_name(apk_blob_t apkname,
		       apk_blob_t *name,
		       apk_blob_t *version)
{
	int i, dash = 0;

	if (APK_BLOB_IS_NULL(apkname))
		return -1;

	for (i = apkname.len - 2; i >= 0; i--) {
		if (apkname.ptr[i] != '-')
			continue;
		if (isdigit(apkname.ptr[i+1]))
			break;
		if (++dash >= 2)
			return -1;
	}
	if (name != NULL)
		*name = APK_BLOB_PTR_LEN(apkname.ptr, i);
	if (version != NULL)
		*version = APK_BLOB_PTR_PTR(&apkname.ptr[i+1],
					    &apkname.ptr[apkname.len-1]);

	return 0;
}

static apk_blob_t trim(apk_blob_t str)
{
	if (str.ptr == NULL || str.len < 1)
		return str;

	if (str.ptr[str.len-1] == '\n') {
		str.ptr[str.len-1] = 0;
		return APK_BLOB_PTR_LEN(str.ptr, str.len-1);
	}

	return str;
}

int apk_deps_add(struct apk_dependency_array **depends,
		 struct apk_dependency *dep)
{
	struct apk_dependency_array *deps = *depends;
	int i;

	if (deps != NULL) {
		for (i = 0; i < deps->num; i++) {
			if (deps->item[i].name == dep->name) {
				deps->item[i] = *dep;
				return 0;
			}
		}
	}

	*apk_dependency_array_add(depends) = *dep;
	return 0;
}

void apk_deps_del(struct apk_dependency_array **pdeps,
		  struct apk_name *name)
{
	struct apk_dependency_array *deps = *pdeps;
	int i;

	if (deps == NULL)
		return;

	for (i = 0; i < deps->num; i++) {
		if (deps->item[i].name != name)
			continue;

		deps->item[i] = deps->item[deps->num-1];
		*pdeps = apk_dependency_array_resize(deps, deps->num-1);
		break;
	}
}

struct parse_depend_ctx {
	struct apk_database *db;
	struct apk_dependency_array **depends;
};

int apk_dep_from_blob(struct apk_dependency *dep, struct apk_database *db,
		      apk_blob_t blob)
{
	struct apk_name *name;
	apk_blob_t bname, bop, bver = APK_BLOB_NULL;
	int mask = APK_VERSION_LESS | APK_VERSION_EQUAL | APK_VERSION_GREATER;

	/* [!]name[<,<=,=,>=,>]ver */
	if (blob.ptr[0] == '!') {
		mask = 0;
		blob.ptr++;
		blob.len--;
	}
	if (apk_blob_cspn(blob, "<>=", &bname, &bop)) {
		int i;

		if (mask == 0)
			return -EINVAL;
		if (!apk_blob_spn(bop, "<>=", &bop, &bver))
			return -EINVAL;
		mask = 0;
		for (i = 0; i < bop.len; i++) {
			switch (bop.ptr[i]) {
			case '<':
				mask |= APK_VERSION_LESS;
				break;
			case '>':
				mask |= APK_VERSION_GREATER;
				break;
			case '=':
				mask |= APK_VERSION_EQUAL;
				break;
			}
		}
		if ((mask & (APK_VERSION_LESS|APK_VERSION_GREATER))
		    == (APK_VERSION_LESS|APK_VERSION_GREATER))
			return -EINVAL;

		if (!apk_version_validate(bver))
			return -EINVAL;

		blob = bname;
	}

	name = apk_db_get_name(db, blob);
	if (name == NULL)
		return -ENOENT;

	*dep = (struct apk_dependency){
		.name = name,
		.version = APK_BLOB_IS_NULL(bver) ? NULL : apk_blob_cstr(bver),
		.result_mask = mask,
	};
	return 0;
}

void apk_dep_from_pkg(struct apk_dependency *dep, struct apk_database *db,
		      struct apk_package *pkg)
{
	*dep = (struct apk_dependency) {
		.name = pkg->name,
		.version = pkg->version,
		.result_mask = APK_VERSION_EQUAL,
	};
}

static int parse_depend(void *ctx, apk_blob_t blob)
{
	struct parse_depend_ctx *pctx = (struct parse_depend_ctx *) ctx;
	struct apk_dependency *dep, p;

	if (blob.len == 0)
		return 0;

	if (apk_dep_from_blob(&p, pctx->db, blob) < 0)
		return -1;

	dep = apk_dependency_array_add(pctx->depends);
	if (dep == NULL)
		return -1;
	*dep = p;

	return 0;
}

void apk_deps_parse(struct apk_database *db,
		    struct apk_dependency_array **depends,
		    apk_blob_t blob)
{
	struct parse_depend_ctx ctx = { db, depends };

	if (blob.len > 1 && blob.ptr[blob.len-1] == '\n')
		blob.len--;

	apk_blob_for_each_segment(blob, " ", parse_depend, &ctx);
}

int apk_deps_write(struct apk_dependency_array *deps, struct apk_ostream *os)
{
	int i, r, n = 0;

	if (deps == NULL)
		return 0;

	for (i = 0; i < deps->num; i++) {
		if (i) {
			if (os->write(os, " ", 1) != 1)
				return -1;
			n += 1;
		}

		if (deps->item[i].result_mask == APK_DEPMASK_CONFLICT) {
			if (os->write(os, "!", 1) != 1)
				return -1;
			n += 1;
		}

		r = apk_ostream_write_string(os, deps->item[i].name->name);
		if (r < 0)
			return r;
		n += r;

		if (deps->item[i].result_mask != APK_DEPMASK_CONFLICT &&
		    deps->item[i].result_mask != APK_DEPMASK_REQUIRE) {
			r = apk_ostream_write_string(os, apk_version_op_string(deps->item[i].result_mask));
			if (r < 0)
				return r;
			n += r;

			r = apk_ostream_write_string(os, deps->item[i].version);
			if (r < 0)
				return r;
			n += r;
		}
	}

	return n;
}

const char *apk_script_types[] = {
	[APK_SCRIPT_PRE_INSTALL]	= "pre-install",
	[APK_SCRIPT_POST_INSTALL]	= "post-install",
	[APK_SCRIPT_PRE_DEINSTALL]	= "pre-deinstall",
	[APK_SCRIPT_POST_DEINSTALL]	= "post-deinstall",
	[APK_SCRIPT_PRE_UPGRADE]	= "pre-upgrade",
	[APK_SCRIPT_POST_UPGRADE]	= "post-upgrade",
};

int apk_script_type(const char *name)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(apk_script_types); i++)
		if (apk_script_types[i] &&
		    strcmp(apk_script_types[i], name) == 0)
			return i;

	return APK_SCRIPT_INVALID;
}

void apk_sign_ctx_init(struct apk_sign_ctx *ctx, int action,
		       struct apk_checksum *identity)
{
	memset(ctx, 0, sizeof(struct apk_sign_ctx));
	ctx->action = action;
	switch (action) {
	case APK_SIGN_NONE:
		ctx->md = EVP_md_null();
		ctx->control_started = 1;
		ctx->data_started = 1;
		break;
	case APK_SIGN_VERIFY:
		ctx->md = EVP_md_null();
		break;
	case APK_SIGN_VERIFY_IDENTITY:
		if (identity->type == APK_CHECKSUM_MD5) {
			ctx->md = EVP_md5();
			ctx->control_started = 1;
			ctx->data_started = 1;
		} else {
			ctx->md = EVP_sha1();
		}
		memcpy(&ctx->identity, identity, sizeof(ctx->identity));
		break;
	case APK_SIGN_GENERATE_V1:
		ctx->md = EVP_md5();
		ctx->control_started = 1;
		ctx->data_started = 1;
		break;
	case APK_SIGN_GENERATE:
	case APK_SIGN_VERIFY_AND_GENERATE:
	default:
		action = APK_SIGN_GENERATE;
		ctx->md = EVP_sha1();
		break;
	}
	EVP_MD_CTX_init(&ctx->mdctx);
	EVP_DigestInit_ex(&ctx->mdctx, ctx->md, NULL);
}


void apk_sign_ctx_free(struct apk_sign_ctx *ctx)
{
	if (ctx->signature.data.ptr != NULL)
		free(ctx->signature.data.ptr);
	if (ctx->signature.pkey != NULL)
		EVP_PKEY_free(ctx->signature.pkey);
}

int apk_sign_ctx_process_file(struct apk_sign_ctx *ctx,
			      const struct apk_file_info *fi,
			      struct apk_istream *is)
{
	if (ctx->data_started)
		return 1;

	if (fi->name[0] != '.' || strchr(fi->name, '/') != NULL) {
		ctx->data_started = 1;
		ctx->control_started = 1;
		return 1;
	}

	if (ctx->control_started)
		return 1;

	if (strncmp(fi->name, ".SIGN.", 6) != 0) {
		ctx->control_started = 1;
		return 1;
	}

	/* A signature file */
	ctx->num_signatures++;

	/* Found already a trusted key */
	if (ctx->action != APK_SIGN_VERIFY ||
	    ctx->signature.pkey != NULL)
		return 0;

	if (strncmp(&fi->name[6], "RSA.", 4) == 0 ||
	    strncmp(&fi->name[6], "DSA.", 4) == 0) {
		char file[256];
	        BIO *bio = BIO_new(BIO_s_file());
		snprintf(file, sizeof(file), "/etc/apk/keys/%s", &fi->name[10]);
		if (BIO_read_filename(bio, file) > 0)
			ctx->signature.pkey =
				PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
		if (ctx->signature.pkey != NULL) {
			if (fi->name[6] == 'R')
				ctx->md = EVP_sha1();
			else
				ctx->md = EVP_dss1();
		}
		BIO_free(bio);
	} else
		return 0;

	if (ctx->signature.pkey != NULL)
		ctx->signature.data = apk_blob_from_istream(is, fi->size);

	return 0;
}

static int read_datahash(void *ctx, apk_blob_t line)
{
	struct apk_sign_ctx *sctx = (struct apk_sign_ctx *) ctx;
	apk_blob_t l, r;

	if (line.ptr == NULL || line.len < 1 || line.ptr[0] == '#')
		return 0;

	if (!apk_blob_split(line, APK_BLOB_STR(" = "), &l, &r))
		return 0;

	if (sctx->data_started == 0 &&
	    apk_blob_compare(APK_BLOB_STR("datahash"), l) == 0) {
		sctx->has_data_checksum = 1;
		sctx->md = EVP_sha256();
		apk_blob_pull_hexdump(
			&r, APK_BLOB_PTR_LEN(sctx->data_checksum,
					     EVP_MD_size(sctx->md)));
	}

	return 0;
}

int apk_sign_ctx_verify_tar(void *sctx, const struct apk_file_info *fi,
			    struct apk_istream *is)
{
	struct apk_sign_ctx *ctx = (struct apk_sign_ctx *) sctx;

	if (apk_sign_ctx_process_file(ctx, fi, is) == 0)
		return 0;

	if (strcmp(fi->name, ".PKGINFO") == 0) {
		apk_blob_t blob = apk_blob_from_istream(is, fi->size);
		apk_blob_for_each_segment(blob, "\n", read_datahash, ctx);
		free(blob.ptr);
	}

	return 0;
}

int apk_sign_ctx_mpart_cb(void *ctx, int part, apk_blob_t data)
{
	struct apk_sign_ctx *sctx = (struct apk_sign_ctx *) ctx;
	unsigned char calculated[EVP_MAX_MD_SIZE];
	int r, end_of_control;

	if ((part == APK_MPART_DATA) ||
	    (part == APK_MPART_BOUNDARY && sctx->data_started))
		goto update_digest;

	/* Still in signature blocks? */
	if (!sctx->control_started)
		goto reset_digest;

	/* Grab state and mark all remaining block as data */
	end_of_control = (sctx->data_started == 0);
	sctx->data_started = 1;

	/* End of control-block and control does not have data checksum? */
	if (sctx->has_data_checksum == 0 && end_of_control)
		goto update_digest;

	/* Drool in the remaining of the digest block now, we will finish
	 * it on all cases */
	EVP_DigestUpdate(&sctx->mdctx, data.ptr, data.len);

	/* End of control-block and checking control hash/signature or
	 * end of data-block and checking its hash/signature */
	if (sctx->has_data_checksum && !end_of_control) {
		/* End of control-block and check it's hash */
		EVP_DigestFinal_ex(&sctx->mdctx, calculated, NULL);
		if (EVP_MD_CTX_size(&sctx->mdctx) == 0 ||
		    memcmp(calculated, sctx->data_checksum,
		           EVP_MD_CTX_size(&sctx->mdctx)) != 0)
			return -EKEYREJECTED;
		sctx->data_verified = 1;
		if (!(apk_flags & APK_ALLOW_UNTRUSTED) &&
		    !sctx->control_verified)
			return -ENOKEY;
		return 0;
	}

	switch (sctx->action) {
	case APK_SIGN_VERIFY:
	case APK_SIGN_VERIFY_AND_GENERATE:
		if (sctx->signature.pkey == NULL) {
			if (apk_flags & APK_ALLOW_UNTRUSTED)
				break;
			return -ENOKEY;
		}

		r = EVP_VerifyFinal(&sctx->mdctx,
			(unsigned char *) sctx->signature.data.ptr,
			sctx->signature.data.len,
			sctx->signature.pkey);
		if (r != 1)
			return -EKEYREJECTED;
		sctx->control_verified = 1;
		if (!sctx->has_data_checksum && part == APK_MPART_END)
			sctx->data_verified = 1;
		break;
	case APK_SIGN_VERIFY_IDENTITY:
		/* Reset digest for hashing data */
		EVP_DigestFinal_ex(&sctx->mdctx, calculated, NULL);
		if (memcmp(calculated, sctx->identity.data,
			   sctx->identity.type) != 0)
			return -EKEYREJECTED;
		sctx->control_verified = 1;
		if (!sctx->has_data_checksum && part == APK_MPART_END)
			sctx->data_verified = 1;
		break;
	case APK_SIGN_GENERATE:
	case APK_SIGN_GENERATE_V1:
		/* Package identity is the checksum */
		sctx->identity.type = EVP_MD_CTX_size(&sctx->mdctx);
		EVP_DigestFinal_ex(&sctx->mdctx, sctx->identity.data, NULL);
		if (sctx->action == APK_SIGN_GENERATE &&
		    sctx->has_data_checksum)
			return -ECANCELED;
		break;
	}
	if (sctx->action == APK_SIGN_VERIFY_AND_GENERATE) {
		sctx->identity.type = EVP_MD_CTX_size(&sctx->mdctx);
		EVP_DigestFinal_ex(&sctx->mdctx, sctx->identity.data, NULL);
	}

reset_digest:
	EVP_DigestInit_ex(&sctx->mdctx, sctx->md, NULL);
	EVP_MD_CTX_set_flags(&sctx->mdctx, EVP_MD_CTX_FLAG_ONESHOT);
	return 0;

update_digest:
	EVP_MD_CTX_clear_flags(&sctx->mdctx, EVP_MD_CTX_FLAG_ONESHOT);
	EVP_DigestUpdate(&sctx->mdctx, data.ptr, data.len);
	return 0;
}

struct read_info_ctx {
	struct apk_database *db;
	struct apk_package *pkg;
	struct apk_sign_ctx *sctx;
	int version;
};

int apk_pkg_add_info(struct apk_database *db, struct apk_package *pkg,
		     char field, apk_blob_t value)
{
	switch (field) {
	case 'P':
		pkg->name = apk_db_get_name(db, value);
		break;
	case 'V':
		pkg->version = apk_blob_cstr(value);
		break;
	case 'T':
		pkg->description = apk_blob_cstr(value);
		break;
	case 'U':
		pkg->url = apk_blob_cstr(value);
		break;
	case 'L':
		pkg->license = apk_blob_cstr(value);
		break;
	case 'D':
		apk_deps_parse(db, &pkg->depends, value);
		break;
	case 'C':
		apk_blob_pull_csum(&value, &pkg->csum);
		break;
	case 'S':
		pkg->size = apk_blob_pull_uint(&value, 10);
		break;
	case 'I':
		pkg->installed_size = apk_blob_pull_uint(&value, 10);
		break;
	default:
		return -1;
	}
	if (APK_BLOB_IS_NULL(value))
		return -1;
	return 0;
}

static int read_info_line(void *ctx, apk_blob_t line)
{
	static struct {
		const char *str;
		char field;
	} fields[] = {
		{ "pkgname", 'P' },
		{ "pkgver",  'V' },
		{ "pkgdesc", 'T' },
		{ "url",     'U' },
		{ "size",    'I' },
		{ "license", 'L' },
		{ "depend",  'D' },
	};
	struct read_info_ctx *ri = (struct read_info_ctx *) ctx;
	apk_blob_t l, r;
	int i;

	if (line.ptr == NULL || line.len < 1 || line.ptr[0] == '#')
		return 0;

	if (!apk_blob_split(line, APK_BLOB_STR(" = "), &l, &r))
		return 0;

	for (i = 0; i < ARRAY_SIZE(fields); i++) {
		if (apk_blob_compare(APK_BLOB_STR(fields[i].str), l) == 0) {
			apk_pkg_add_info(ri->db, ri->pkg, fields[i].field, r);
			return 0;
		}
	}

	if (ri->sctx->data_started == 0 &&
	    apk_blob_compare(APK_BLOB_STR("datahash"), l) == 0) {
		ri->sctx->has_data_checksum = 1;
		ri->sctx->md = EVP_sha256();
		apk_blob_pull_hexdump(
			&r, APK_BLOB_PTR_LEN(ri->sctx->data_checksum,
					     EVP_MD_size(ri->sctx->md)));
	}

	return 0;
}

static int read_info_entry(void *ctx, const struct apk_file_info *ae,
			   struct apk_istream *is)
{
	static struct {
		const char *str;
		char field;
	} fields[] = {
		{ "DESC",	'T' },
		{ "WWW",	'U' },
		{ "LICENSE",	'L' },
		{ "DEPEND", 	'D' },
	};
	struct read_info_ctx *ri = (struct read_info_ctx *) ctx;
	struct apk_database *db = ri->db;
	struct apk_package *pkg = ri->pkg;
	apk_blob_t name, version;
	char *slash;
	int i;

	/* Meta info and scripts */
	if (apk_sign_ctx_process_file(ri->sctx, ae, is) == 0)
		return 0;

	if (ae->name[0] == '.') {
		/* APK 2.0 format */
		if (strcmp(ae->name, ".PKGINFO") == 0) {
			apk_blob_t blob = apk_blob_from_istream(is, ae->size);
			apk_blob_for_each_segment(blob, "\n", read_info_line, ctx);
			free(blob.ptr);
			ri->version = 2;
		} else if (strcmp(ae->name, ".INSTALL") == 0) {
			apk_warning("Package '%s-%s' contains deprecated .INSTALL",
				    pkg->name->name, pkg->version);
		}
		return 0;
	}

	if (strncmp(ae->name, "var/db/apk/", 11) == 0) {
		/* APK 1.0 format */
		ri->version = 1;
		if (!S_ISREG(ae->mode))
			return 0;

		slash = strchr(&ae->name[11], '/');
		if (slash == NULL)
			return 0;

		if (apk_pkg_parse_name(APK_BLOB_PTR_PTR(&ae->name[11], slash-1),
				       &name, &version) < 0)
			return -1;

		if (pkg->name == NULL)
			pkg->name = apk_db_get_name(db, name);
		if (pkg->version == NULL)
			pkg->version = apk_blob_cstr(version);

		for (i = 0; i < ARRAY_SIZE(fields); i++) {
			if (strcmp(fields[i].str, slash+1) == 0) {
				apk_blob_t blob = apk_blob_from_istream(is, ae->size);
				apk_pkg_add_info(ri->db, ri->pkg, fields[i].field,
						 trim(blob));
				free(blob.ptr);
				break;
			}
		}
	} else if (ri->version < 2) {
		/* Version 1.x packages do not contain installed size
		 * in metadata, so we calculate it here */
		pkg->installed_size += apk_calc_installed_size(ae->size);
	}

	return 0;
}

int apk_pkg_read(struct apk_database *db, const char *file,
	         struct apk_sign_ctx *sctx, struct apk_package **pkg)
{
	struct read_info_ctx ctx;
	struct apk_file_info fi;
	struct apk_bstream *bs;
	struct apk_istream *tar;
	char realfile[PATH_MAX];
	int r;

	if (realpath(file, realfile) < 0)
		return -errno;
	r = apk_file_get_info(realfile, APK_CHECKSUM_NONE, &fi);
	if (r != 0)
		return r;

	memset(&ctx, 0, sizeof(ctx));
	ctx.sctx = sctx;
	ctx.pkg = apk_pkg_new();
	r = -ENOMEM;
	if (ctx.pkg == NULL)
		goto err;
	bs = apk_bstream_from_file(realfile);
	if (bs == NULL)
		goto err;

	ctx.db = db;
	ctx.pkg->size = fi.size;

	tar = apk_bstream_gunzip_mpart(bs, apk_sign_ctx_mpart_cb, sctx);
	r = apk_tar_parse(tar, read_info_entry, &ctx);
	tar->close(tar);
	if (r < 0 && r != -ECANCELED)
		goto err;
	if (ctx.pkg->name == NULL) {
		r = -ENOMSG;
		goto err;
	}
	if (sctx->action != APK_SIGN_VERIFY)
		ctx.pkg->csum = sctx->identity;
	ctx.pkg->filename = strdup(realfile);

	ctx.pkg = apk_db_pkg_add(db, ctx.pkg);
	if (pkg != NULL)
		*pkg = ctx.pkg;
	return 0;
err:
	apk_pkg_free(ctx.pkg);
	return r;
}

void apk_pkg_free(struct apk_package *pkg)
{
	struct apk_script *script;
	struct hlist_node *c, *n;

	if (pkg == NULL)
		return;

	hlist_for_each_entry_safe(script, c, n, &pkg->scripts, script_list)
		free(script);

	if (pkg->depends)
		free(pkg->depends);
	if (pkg->version)
		free(pkg->version);
	if (pkg->url)
		free(pkg->url);
	if (pkg->description)
		free(pkg->description);
	if (pkg->license)
		free(pkg->license);
	free(pkg);
}

int apk_pkg_get_state(struct apk_package *pkg)
{
	if (list_hashed(&pkg->installed_pkgs_list))
		return APK_PKG_INSTALLED;
	return APK_PKG_NOT_INSTALLED;
}

void apk_pkg_set_state(struct apk_database *db, struct apk_package *pkg, int state)
{
	switch (state) {
	case APK_PKG_INSTALLED:
		if (!list_hashed(&pkg->installed_pkgs_list)) {
			db->installed.stats.packages++;
			list_add_tail(&pkg->installed_pkgs_list,
				      &db->installed.packages);
		}
		break;
	case APK_PKG_NOT_INSTALLED:
		if (list_hashed(&pkg->installed_pkgs_list)) {
			db->installed.stats.packages--;
			list_del(&pkg->installed_pkgs_list);
		}
		break;
	}
}

int apk_pkg_add_script(struct apk_package *pkg, struct apk_istream *is,
		       unsigned int type, unsigned int size)
{
	struct apk_script *script;
	int r;

	script = malloc(sizeof(struct apk_script) + size);
	script->type = type;
	script->size = size;
	r = is->read(is, script->script, size);
	if (r < 0) {
		free(script);
		return r;
	}

	hlist_add_head(&script->script_list, &pkg->scripts);
	return r;
}

int apk_pkg_run_script(struct apk_package *pkg, int root_fd,
		       unsigned int type)
{
	static const char * const environment[] = {
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		NULL
	};
	struct apk_script *script;
	struct hlist_node *c;
	int fd, status;
	pid_t pid;
	char fn[1024];

	fchdir(root_fd);
	hlist_for_each_entry(script, c, &pkg->scripts, script_list) {
		if (script->type != type)
			continue;

		snprintf(fn, sizeof(fn),
			"tmp/%s-%s.%s",
			pkg->name->name, pkg->version,
			apk_script_types[type]);
		fd = creat(fn, 0777);
		if (fd < 0)
			return fd;
		write(fd, script->script, script->size);
		close(fd);

		apk_message("Executing %s", &fn[4]);

		pid = fork();
		if (pid == -1)
			return -1;
		if (pid == 0) {
			if (chroot(".") < 0) {
				apk_error("chroot: %s", strerror(errno));
			} else {
				execle(fn, apk_script_types[type],
				       pkg->version, "", NULL, environment);
			}
			exit(1);
		}
		waitpid(pid, &status, 0);
		unlink(fn);
		if (WIFEXITED(status))
			return WEXITSTATUS(status);
		return -1;
	}

	return 0;
}

static int parse_index_line(void *ctx, apk_blob_t line)
{
	struct read_info_ctx *ri = (struct read_info_ctx *) ctx;

	if (line.len < 3 || line.ptr[1] != ':')
		return 0;

	apk_pkg_add_info(ri->db, ri->pkg, line.ptr[0], APK_BLOB_PTR_LEN(line.ptr+2, line.len-2));
	return 0;
}

struct apk_package *apk_pkg_parse_index_entry(struct apk_database *db, apk_blob_t blob)
{
	struct read_info_ctx ctx;

	ctx.pkg = apk_pkg_new();
	if (ctx.pkg == NULL)
		return NULL;

	ctx.db = db;
	ctx.version = 0;

	apk_blob_for_each_segment(blob, "\n", parse_index_line, &ctx);

	if (ctx.pkg->name == NULL) {
		apk_pkg_free(ctx.pkg);
		apk_error("Failed to parse index entry: %.*s",
			  blob.len, blob.ptr);
		ctx.pkg = NULL;
	}

	return ctx.pkg;
}

int apk_pkg_write_index_entry(struct apk_package *info,
			      struct apk_ostream *os)
{
	char buf[512];
	apk_blob_t bbuf = APK_BLOB_BUF(buf);
	int r;

	apk_blob_push_blob(&bbuf, APK_BLOB_STR("C:"));
	apk_blob_push_csum(&bbuf, &info->csum);
	apk_blob_push_blob(&bbuf, APK_BLOB_STR("\nP:"));
	apk_blob_push_blob(&bbuf, APK_BLOB_STR(info->name->name));
	apk_blob_push_blob(&bbuf, APK_BLOB_STR("\nV:"));
	apk_blob_push_blob(&bbuf, APK_BLOB_STR(info->version));
	apk_blob_push_blob(&bbuf, APK_BLOB_STR("\nS:"));
	apk_blob_push_uint(&bbuf, info->size, 10);
	apk_blob_push_blob(&bbuf, APK_BLOB_STR("\nI:"));
	apk_blob_push_uint(&bbuf, info->installed_size, 10);
	apk_blob_push_blob(&bbuf, APK_BLOB_STR("\nT:"));
	apk_blob_push_blob(&bbuf, APK_BLOB_STR(info->description));
	apk_blob_push_blob(&bbuf, APK_BLOB_STR("\nU:"));
	apk_blob_push_blob(&bbuf, APK_BLOB_STR(info->url));
	apk_blob_push_blob(&bbuf, APK_BLOB_STR("\nL:"));
	apk_blob_push_blob(&bbuf, APK_BLOB_STR(info->license));
	apk_blob_push_blob(&bbuf, APK_BLOB_STR("\n"));

	if (APK_BLOB_IS_NULL(bbuf))
		return -1;

	if (os->write(os, buf, bbuf.ptr - buf) != bbuf.ptr - buf)
		return -1;

	if (info->depends != NULL) {
		if (os->write(os, "D:", 2) != 2)
			return -1;
		r = apk_deps_write(info->depends, os);
		if (r < 0)
			return r;
		if (os->write(os, "\n", 1) != 1)
			return -1;
	}

	return 0;
}

int apk_pkg_version_compare(struct apk_package *a, struct apk_package *b)
{
	return apk_version_compare(a->version, b->version);
}
