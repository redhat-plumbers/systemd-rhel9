/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if HAVE_BLKID
#  include <blkid.h>

#  include "macro.h"

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(blkid_probe, blkid_free_probe, NULL);

/* Define symbolic names for blkid_do_safeprobe() return values, since blkid only uses literal numbers. We
 * prefix these symbolic definitions with underscores, to not invade libblkid's namespace needlessly. */
enum {
        _BLKID_SAFEPROBE_FOUND     =  0,
        _BLKID_SAFEPROBE_NOT_FOUND =  1,
        _BLKID_SAFEPROBE_AMBIGUOUS = -2,
        _BLKID_SAFEPROBE_ERROR     = -1,
};

#endif
