/*
 * General cryptography helper functions and definitions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PV_CRYPTO_H
#define PV_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <glib.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ecdh.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

#include "include/pv_crypto_defs.h"
#include "common.h"

#include "buffer.h"

#define AES_256_GCM_IV_SIZE  12
#define AES_256_GCM_KEY_SIZE 32
#define AES_256_GCM_TAG_SIZE 16

#define AES_256_XTS_TWEAK_SIZE 16
#define AES_256_XTS_KEY_SIZE   64

typedef GSList HostKeyList;

/* Register auto cleanup functions */
G_DEFINE_AUTOPTR_CLEANUP_FUNC(BIGNUM, BN_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(BIO, BIO_free_all)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(BN_CTX, BN_CTX_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(EC_GROUP, EC_GROUP_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(EC_KEY, EC_KEY_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(EC_POINT, EC_POINT_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_CIPHER_CTX, EVP_CIPHER_CTX_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_MD_CTX, EVP_MD_CTX_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_PKEY, EVP_PKEY_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_PKEY_CTX, EVP_PKEY_CTX_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(X509, X509_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(X509_LOOKUP, X509_LOOKUP_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(X509_STORE, X509_STORE_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(X509_STORE_CTX, X509_STORE_CTX_free)

union cmp_index {
	struct {
		uint16_t idx;
		unsigned char rand[6];
	} __attribute__((packed));
	uint64_t data;
};

/* The tweak is always stored as big endian */
union tweak {
	struct {
		union cmp_index cmp_idx;
		uint64_t page_idx; /* page index */
	} __attribute__((packed));
	uint8_t data[16];
};

struct cipher_parms {
	const EVP_CIPHER *cipher;
	unsigned char key[AES_256_XTS_KEY_SIZE];
	union tweak tweak;
	unsigned int padding;
};

struct gcm_cipher_parms {
	const EVP_CIPHER *cipher;
	uint8_t key[AES_256_GCM_KEY_SIZE];
	uint8_t iv[AES_256_GCM_IV_SIZE];
};

EVP_PKEY *read_ec_pubkey_cert(X509_STORE *store, int nid, const char *path, GError **err);
Buffer *compute_exchange_key(EVP_PKEY *cust, EVP_PKEY *host, GError **err);
Buffer *generate_aes_key(unsigned int size, GError **err);
EVP_PKEY *generate_ec_key(int nid, GError **err);
int generate_tweak(union tweak *tweak, uint16_t i, GError **err);
union ecdh_pub_key *evp_pkey_to_ecdh_pub_key(EVP_PKEY *key, GError **err);
EVP_MD_CTX *digest_ctx_new(const EVP_MD *md, GError **err);
Buffer *digest_ctx_finalize(EVP_MD_CTX *ctx, GError **err);
Buffer *sha256_buffer(const Buffer *buf, GError **err);
int64_t gcm_encrypt_decrypt(const Buffer *in, const Buffer *aad, struct gcm_cipher_parms *parms,
			    Buffer *out, Buffer *tag, bool encrypt, GError **err);
int encrypt_file(const struct cipher_parms *parms, const char *in_path, const char *path_out,
		 size_t *in_size, size_t *out_size, GError **err);
Buffer *encrypt_buf(const struct cipher_parms *parms, const Buffer *in, GError **err);
Buffer *decrypt_buf(const struct cipher_parms *parms, const Buffer *in, GError **err);

#endif
