/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"
#include "sha256.h"

#define X509_FINGERPRINT_SIZE SHA256_DIGEST_SIZE

#if HAVE_OPENSSL
#  include <openssl/bio.h>
#  include <openssl/bn.h>
#  include <openssl/crypto.h>
#  include <openssl/err.h>
#  include <openssl/evp.h>
#  include <openssl/opensslv.h>
#  include <openssl/pkcs7.h>
#  include <openssl/ssl.h>
#  include <openssl/x509v3.h>
#  ifndef OPENSSL_VERSION_MAJOR
/* OPENSSL_VERSION_MAJOR macro was added in OpenSSL 3. Thus, if it doesn't exist,  we must be before OpenSSL 3. */
#    define OPENSSL_VERSION_MAJOR 1
#  endif
#  if OPENSSL_VERSION_MAJOR >= 3
#    include <openssl/core_names.h>
#    include <openssl/param_build.h>
#  endif

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_MACRO(void*, OPENSSL_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(X509_NAME*, X509_NAME_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EVP_PKEY_CTX*, EVP_PKEY_CTX_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EVP_CIPHER_CTX*, EVP_CIPHER_CTX_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EC_POINT*, EC_POINT_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EC_GROUP*, EC_GROUP_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(BIGNUM*, BN_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(BN_CTX*, BN_CTX_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(ECDSA_SIG*, ECDSA_SIG_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(PKCS7*, PKCS7_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(SSL*, SSL_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(BIO*, BIO_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EVP_MD_CTX*, EVP_MD_CTX_free, NULL);
#if OPENSSL_VERSION_MAJOR >= 3
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(OSSL_PARAM*, OSSL_PARAM_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(OSSL_PARAM_BLD*, OSSL_PARAM_BLD_free, NULL);
#else
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EC_KEY*, EC_KEY_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(RSA*, RSA_free, NULL);
#endif

static inline void sk_X509_free_allp(STACK_OF(X509) **sk) {
        if (!sk || !*sk)
                return;

        sk_X509_pop_free(*sk, X509_free);
}

int openssl_pkey_from_pem(const void *pem, size_t pem_size, EVP_PKEY **ret);

int openssl_hash(const EVP_MD *alg, const void *msg, size_t msg_len, uint8_t *ret_hash, size_t *ret_hash_len);

int rsa_encrypt_bytes(EVP_PKEY *pkey, const void *decrypted_key, size_t decrypted_key_size, void **ret_encrypt_key, size_t *ret_encrypt_key_size);

int rsa_pkey_to_suitable_key_size(EVP_PKEY *pkey, size_t *ret_suitable_key_size);

int rsa_pkey_new(size_t bits, EVP_PKEY **ret);

int rsa_pkey_from_n_e(const void *n, size_t n_size, const void *e, size_t e_size, EVP_PKEY **ret);

int rsa_pkey_to_n_e(const EVP_PKEY *pkey, void **ret_n, size_t *ret_n_size, void **ret_e, size_t *ret_e_size);

int ecc_pkey_from_curve_x_y(int curve_id, const void *x, size_t x_size, const void *y, size_t y_size, EVP_PKEY **ret);

int ecc_pkey_to_curve_x_y(const EVP_PKEY *pkey, int *ret_curve_id, void **ret_x, size_t *ret_x_size, void **ret_y, size_t *ret_y_size);

int ecc_pkey_new(int curve_id, EVP_PKEY **ret);

int pubkey_fingerprint(EVP_PKEY *pk, const EVP_MD *md, void **ret, size_t *ret_size);

#else

typedef struct X509 X509;
typedef struct EVP_PKEY EVP_PKEY;

static inline void *X509_free(X509 *p) {
        assert(p == NULL);
        return NULL;
}

static inline void *EVP_PKEY_free(EVP_PKEY *p) {
        assert(p == NULL);
        return NULL;
}

#endif

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(X509*, X509_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EVP_PKEY*, EVP_PKEY_free, NULL);

int x509_fingerprint(X509 *cert, uint8_t buffer[static X509_FINGERPRINT_SIZE]);

#if PREFER_OPENSSL
/* The openssl definition */
typedef const EVP_MD* hash_md_t;
typedef const EVP_MD* hash_algorithm_t;
typedef int elliptic_curve_t;
typedef EVP_MD_CTX* hash_context_t;
#  define OPENSSL_OR_GCRYPT(a, b) (a)

#elif HAVE_GCRYPT

#  include <gcrypt.h>

/* The gcrypt definition */
typedef int hash_md_t;
typedef const char* hash_algorithm_t;
typedef const char* elliptic_curve_t;
typedef gcry_md_hd_t hash_context_t;
#  define OPENSSL_OR_GCRYPT(a, b) (b)
#endif

#if PREFER_OPENSSL
int string_hashsum(const char *s, size_t len, hash_algorithm_t md_algorithm, char **ret);

static inline int string_hashsum_sha224(const char *s, size_t len, char **ret) {
        return string_hashsum(s, len, EVP_sha224(), ret);
}

static inline int string_hashsum_sha256(const char *s, size_t len, char **ret) {
        return string_hashsum(s, len, EVP_sha256(), ret);
}
#endif
