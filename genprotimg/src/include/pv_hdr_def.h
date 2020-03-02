/*
 * PV header definitions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PV_HDR_DEF_H
#define PV_HDR_DEF_H

#include <openssl/sha.h>

#include "boot/s390.h"
#include "utils/crypto.h"
#include "pv_crypto_defs.h"

#define PV_MAGIC_VALUE 0x49424d5365634578ULL
#define PV_VERSION_1 0x00000100

/* UV doesn't decrypt during unpack operation */
#define PV_CONTROL_FLAG_NO_DECRYPTION 0x10000000UL

typedef struct pv_hdr_key_slot {
	uint8_t digest_key[SHA256_DIGEST_LENGTH];
	uint8_t wrapped_key[32];
	uint8_t tag[AES_256_GCM_TAG_SIZE];
} __attribute__((packed)) PvHdrKeySlot;

typedef struct pv_hdr_opt_item {
	uint32_t otype;
	uint8_t ibk[32];
	uint8_t data[];
} __attribute__((packed)) PvHdrOptItem;

/* integrity protected data (by GCM tag), but non-encrypted */
struct pv_hdr_head {
	uint64_t magic;
	uint32_t version;
	uint32_t phs;
	uint8_t iv[AES_256_GCM_IV_SIZE];
	uint32_t res1;
	uint64_t nks;
	uint64_t sea;
	uint64_t nep;
	uint64_t pcf;
	union ecdh_pub_key cust_pub_key;
	uint8_t pld[SHA512_DIGEST_LENGTH];
	uint8_t ald[SHA512_DIGEST_LENGTH];
	uint8_t tld[SHA512_DIGEST_LENGTH];
} __attribute__((packed));

/* Must not have any padding */
struct pv_hdr_encrypted {
	uint8_t cust_comm_key[32];
	uint8_t img_enc_key_1[AES_256_XTS_KEY_SIZE / 2];
	uint8_t img_enc_key_2[AES_256_XTS_KEY_SIZE / 2];
	struct psw_t psw;
	uint64_t scf;
	uint32_t noi;
	uint32_t res2;
};
STATIC_ASSERT(sizeof(struct pv_hdr_encrypted) == 32 + 32 + 32 + sizeof(struct psw_t)
	      + 8 + 4 + 4);

typedef struct pv_hdr {
	struct pv_hdr_head head;
	struct pv_hdr_key_slot *slots;
	struct pv_hdr_encrypted *encrypted;
	struct pv_hdr_opt_item **optional_items;
	uint8_t tag[AES_256_GCM_TAG_SIZE];
} PvHdr;

#endif
