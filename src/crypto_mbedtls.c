#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/random.h>

#include <mbedtls/platform.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <psa/crypto.h>

#include "apk_crypto.h"

static inline const mbedtls_md_type_t apk_digest_alg_to_mbedtls_type(uint8_t alg) {
	switch (alg) {
	case APK_DIGEST_NONE:	return MBEDTLS_MD_NONE;
	case APK_DIGEST_MD5:	return MBEDTLS_MD_MD5;
	case APK_DIGEST_SHA1:	return MBEDTLS_MD_SHA1;
	case APK_DIGEST_SHA256_160:
	case APK_DIGEST_SHA256:	return MBEDTLS_MD_SHA256;
	case APK_DIGEST_SHA512:	return MBEDTLS_MD_SHA512;
	default:
		assert(alg);
		return MBEDTLS_MD_NONE;
	}
}

static inline const mbedtls_md_info_t *apk_digest_alg_to_mdinfo(uint8_t alg) {
	return mbedtls_md_info_from_type(
		apk_digest_alg_to_mbedtls_type(alg)
	);
}

int apk_digest_calc(struct apk_digest *d, uint8_t alg, const void *ptr, size_t sz)
{
	//unsigned int md_sz = sizeof d->data;
	if (mbedtls_md(apk_digest_alg_to_mdinfo(alg), ptr, sz, d->data))
		return -APKE_CRYPTO_ERROR;

	apk_digest_set(d, alg);
	return 0;
}

int apk_digest_ctx_init(struct apk_digest_ctx *dctx, uint8_t alg)
{
	dctx->alg = alg;
	dctx->mdctx = malloc(sizeof(mbedtls_md_context_t));

	if (!dctx->mdctx) return -ENOMEM;

	mbedtls_md_init(dctx->mdctx);
	if (mbedtls_md_setup(dctx->mdctx, apk_digest_alg_to_mdinfo(alg), 0) ||
		mbedtls_md_starts(dctx->mdctx))
		return -APKE_CRYPTO_ERROR;

	return 0;
}

int apk_digest_ctx_reset(struct apk_digest_ctx *dctx, uint8_t alg)
{
	mbedtls_md_free(dctx->mdctx);

	if (mbedtls_md_setup(dctx->mdctx, apk_digest_alg_to_mdinfo(alg), 0) ||
		mbedtls_md_starts(dctx->mdctx))
		return -APKE_CRYPTO_ERROR;
	
	dctx->alg = alg;
	return 0;
}

void apk_digest_ctx_free(struct apk_digest_ctx *dctx)
{
	free(dctx->mdctx);
	dctx->mdctx = 0;
}

int apk_digest_ctx_update(struct apk_digest_ctx *dctx, const void *ptr, size_t sz)
{
	return mbedtls_md_update(dctx->mdctx, ptr, sz) == 0 ? 0 : -APKE_CRYPTO_ERROR;
}

int apk_digest_ctx_final(struct apk_digest_ctx *dctx, struct apk_digest *d)
{
	//unsigned int mdlen = sizeof d->data;
	// TODO: do we need to check if buffer is big enough?
	if (mbedtls_md_finish(dctx->mdctx, d->data)) {
		apk_digest_reset(d);
		return -APKE_CRYPTO_ERROR;
	}
	d->alg = dctx->alg;
	d->len = apk_digest_alg_len(d->alg);
	return 0;
}

// Entropy function from ustream-ssl to avoid using the bloated mbedtls stuff
// with mbedtls_entropy_context and mbedtls_ctr_drbg_context. 
static int _apk_random(void *ctx, unsigned char *out, size_t len)
{
#ifdef linux
	if (getrandom(out, len, 0) != (ssize_t) len)
		return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
#else
	static FILE *f;

	if (!f)
		f = fopen("/dev/urandom", "r");
	if (fread(out, len, 1, f) != 1)
		return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
#endif

	return 0;
}

int mbedtls_pk_load_file_fd(int fd, unsigned char **buf, size_t *n)
{
    FILE *f;
    long size;

    //PK_VALIDATE_RET(fd != 0);
    //PK_VALIDATE_RET(buf != NULL);
    //PK_VALIDATE_RET(n != NULL);

    if ((f = fdopen(fd, "rb")) == NULL) {
        return MBEDTLS_ERR_PK_FILE_IO_ERROR;
    }

    fseek(f, 0, SEEK_END);
    if ((size = ftell(f)) == -1) {
        fclose(f);
        return MBEDTLS_ERR_PK_FILE_IO_ERROR;
    }
    fseek(f, 0, SEEK_SET);

    *n = (size_t) size;

    if (*n + 1 == 0 ||
        (*buf = mbedtls_calloc(1, *n + 1)) == NULL) {
        fclose(f);
        return MBEDTLS_ERR_PK_ALLOC_FAILED;
    }

    if (fread(*buf, 1, *n, f) != *n) {
        fclose(f);

        mbedtls_platform_zeroize(*buf, *n);
        mbedtls_free(*buf);

        return MBEDTLS_ERR_PK_FILE_IO_ERROR;
    }

    fclose(f);

    (*buf)[*n] = '\0';

    if (strstr((const char *) *buf, "-----BEGIN ") != NULL) {
        ++*n;
    }

    return 0;
}

static int apk_pkey_init(struct apk_pkey *pkey, mbedtls_pk_context *key)
{
	unsigned char dig[APK_DIGEST_MAX_LENGTH], *pub = NULL;
	unsigned char *c;
	//unsigned int dlen = sizeof dig;
	int len, publen, r = -APKE_CRYPTO_ERROR;

	// Assume byte len is always * 2 + NULL terminated
	publen = mbedtls_pk_get_len(key) * 2 + 1;
	pub = malloc(publen);
	if (!pub)
		return -ENOMEM;
	c = pub + publen;

	if ((len = mbedtls_pk_write_pubkey(&c, pub, key)) < 0) return -APKE_CRYPTO_ERROR;
	if (!mbedtls_md(apk_digest_alg_to_mdinfo(APK_DIGEST_SHA512), pub, len, dig)) {
		memcpy(pkey->id, dig, sizeof pkey->id);
		r = 0;
	}

	free(pub);
	pkey->key = key;

	return r;
}

void apk_pkey_free(struct apk_pkey *pkey)
{
	mbedtls_pk_free(pkey->key);
}

int apk_pkey_load(struct apk_pkey *pkey, int dirfd, const char *fn)
{
	mbedtls_pk_context *key;
	unsigned char *buf;
	size_t blen;
	int ret, fd;

	fd = openat(dirfd, fn, O_RDONLY|O_CLOEXEC);
	if (fd < 0)
		return -errno;

	key = malloc(sizeof *key);
	if (!key)
		return -ENOMEM;
	
	mbedtls_pk_init(key);
	if (mbedtls_pk_load_file_fd(fd, &buf, &blen))
		return -APKE_CRYPTO_ERROR;

	if ((ret = mbedtls_pk_parse_public_key(key, buf, blen)) != 0) {
#if (MBEDTLS_VERSION_NUMBER >= 0x03000000)
		ret = mbedtls_pk_parse_key(key, buf, blen, NULL, 0, _apk_random, NULL);
#else
		ret = mbedtls_pk_parse_key(key, buf, blen, NULL, 0);
#endif
	}
	mbedtls_platform_zeroize(buf, blen);
	mbedtls_free(buf);
	if (ret != 0)
		return -APKE_CRYPTO_KEY_FORMAT;

	return apk_pkey_init(pkey, key);
}

int apk_sign_start(struct apk_digest_ctx *dctx, uint8_t alg, struct apk_pkey *pkey)
{
	if (apk_digest_ctx_reset(dctx, alg))
		return -APKE_CRYPTO_ERROR;

	dctx->sigver_key = pkey;

	return 0;
}

int apk_sign(struct apk_digest_ctx *dctx, void *sig, size_t *len)
{
	struct apk_digest dig;
	int r = 0;

	if (apk_digest_ctx_final(dctx, &dig))
		return -APKE_SIGNATURE_GEN_FAILURE;
#if (MBEDTLS_VERSION_NUMBER >= 0x03000000)	
	if (mbedtls_pk_sign(dctx->sigver_key->key, apk_digest_alg_to_mbedtls_type(dctx->alg),
						&dig.data, dig.len, sig, sizeof *sig, len, _apk_random, NULL))
#else
	if (mbedtls_pk_sign(dctx->sigver_key->key, apk_digest_alg_to_mbedtls_type(dctx->alg),
						&dig.data, dig.len, sig, len, _apk_random, NULL))
#endif
		r = -APKE_SIGNATURE_GEN_FAILURE;


	dctx->sigver_key = NULL;
	return r;
}

int apk_verify_start(struct apk_digest_ctx *dctx, uint8_t alg, struct apk_pkey *pkey)
{
	if (apk_digest_ctx_reset(dctx, alg))
		return -APKE_CRYPTO_ERROR;

	dctx->sigver_key = pkey;

	return 0;
}

int apk_verify(struct apk_digest_ctx *dctx, void *sig, size_t len)
{
	struct apk_digest dig;
	int r = 0;

	if (apk_digest_ctx_final(dctx, &dig))
		return -APKE_SIGNATURE_GEN_FAILURE;

	if (mbedtls_pk_verify(dctx->sigver_key->key, apk_digest_alg_to_mbedtls_type(dctx->alg), &dig.data, dig.len, sig, len))
		r = -APKE_SIGNATURE_INVALID;

	dctx->sigver_key = NULL;
	return r;
}

static void apk_crypto_cleanup(void)
{
#ifdef MBEDTLS_PSA_CRYPTO_C
	mbedtls_psa_crypto_free();
#endif
}

void apk_crypto_init(void)
{
	atexit(apk_crypto_cleanup);
	
#ifdef MBEDTLS_PSA_CRYPTO_C
	psa_crypto_init();
#endif
}
