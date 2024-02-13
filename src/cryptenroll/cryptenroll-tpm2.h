/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "cryptsetup-util.h"
#include "log.h"
#include "tpm2-util.h"

#if HAVE_TPM2
int enroll_tpm2(struct crypt_device *cd, const void *volume_key, size_t volume_key_size, const char *device, uint32_t seal_key_handle, Tpm2PCRValue *hash_pcrs, size_t n_hash_pcrs, const char *pubkey_path, uint32_t pubkey_pcr_mask, const char *signature_path, bool use_pin);
#else
static inline int enroll_tpm2(struct crypt_device *cd, const void *volume_key, size_t volume_key_size, const char *device, uint32_t seal_key_handle, Tpm2PCRValue *hash_pcrs, size_t n_hash_pcrs, const char *pubkey_path, uint32_t pubkey_pcr_mask, const char *signature_path, bool use_pin) {
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "TPM2 key enrollment not supported.");
}
#endif
