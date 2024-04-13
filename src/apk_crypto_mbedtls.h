/* apk_crypto_openssl.h - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef APK_CRYPTO_MBEDTLS_H
#define APK_CRYPTO_MBEDTLS_H

#include <mbedtls/md.h>
#include <mbedtls/pk.h>

struct apk_pkey {
	uint8_t id[16];
	mbedtls_pk_context *key;
};

struct apk_digest_ctx {
	mbedtls_md_context_t *mdctx;
	struct apk_pkey *sigver_key;
	uint8_t alg;
};

#endif
