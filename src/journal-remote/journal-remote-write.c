/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "journal-remote.h"

static int do_rotate(JournaldFile **f, MMapCache *m, bool compress, bool seal) {
        int r = journald_file_rotate(f, m, compress, UINT64_MAX, seal, NULL);
        if (r < 0) {
                if (*f)
                        log_error_errno(r, "Failed to rotate %s: %m", (*f)->file->path);
                else
                        log_error_errno(r, "Failed to create rotated journal: %m");
        }

        return r;
}

Writer* writer_new(RemoteServer *server) {
        Writer *w;

        w = new0(Writer, 1);
        if (!w)
                return NULL;

        memset(&w->metrics, 0xFF, sizeof(w->metrics));

        w->mmap = mmap_cache_new();
        if (!w->mmap)
                return mfree(w);

        w->n_ref = 1;
        w->server = server;

        return w;
}

static Writer* writer_free(Writer *w) {
        if (!w)
                return NULL;

        if (w->journal) {
                log_debug("Closing journal file %s.", w->journal->file->path);
                journald_file_close(w->journal);
        }

        if (w->server && w->hashmap_key)
                hashmap_remove(w->server->writers, w->hashmap_key);

        free(w->hashmap_key);

        if (w->mmap)
                mmap_cache_unref(w->mmap);

        return mfree(w);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(Writer, writer, writer_free);

int writer_write(Writer *w,
                 struct iovec_wrapper *iovw,
                 dual_timestamp *ts,
                 sd_id128_t *boot_id,
                 bool compress,
                 bool seal) {
        int r;

        assert(w);
        assert(iovw);
        assert(iovw->count > 0);

        if (journal_file_rotate_suggested(w->journal->file, 0, LOG_DEBUG)) {
                log_info("%s: Journal header limits reached or header out-of-date, rotating",
                         w->journal->file->path);
                r = do_rotate(&w->journal, w->mmap, compress, seal);
                if (r < 0)
                        return r;
        }

        r = journal_file_append_entry(w->journal->file, ts, boot_id,
                                      iovw->iovec, iovw->count,
                                      &w->seqnum, NULL, NULL);
        if (r >= 0) {
                if (w->server)
                        w->server->event_count += 1;
                return 0;
        } else if (r == -EBADMSG)
                return r;

        log_debug_errno(r, "%s: Write failed, rotating: %m", w->journal->file->path);
        r = do_rotate(&w->journal, w->mmap, compress, seal);
        if (r < 0)
                return r;
        else
                log_debug("%s: Successfully rotated journal", w->journal->file->path);

        log_debug("Retrying write.");
        r = journal_file_append_entry(w->journal->file, ts, boot_id,
                                      iovw->iovec, iovw->count,
                                      &w->seqnum, NULL, NULL);
        if (r < 0)
                return r;

        if (w->server)
                w->server->event_count += 1;
        return 0;
}
