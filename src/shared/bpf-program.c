/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bpf-program.h"
#include "fd-util.h"
#include "memory-util.h"
#include "missing_syscall.h"
#include "path-util.h"
#include "string-table.h"

static const char *const bpf_cgroup_attach_type_table[__MAX_BPF_ATTACH_TYPE] = {
        [BPF_CGROUP_INET_INGRESS] =     "ingress",
        [BPF_CGROUP_INET_EGRESS] =      "egress",
        [BPF_CGROUP_INET_SOCK_CREATE] = "sock_create",
        [BPF_CGROUP_SOCK_OPS] =         "sock_ops",
        [BPF_CGROUP_DEVICE] =           "device",
        [BPF_CGROUP_INET4_BIND] =       "bind4",
        [BPF_CGROUP_INET6_BIND] =       "bind6",
        [BPF_CGROUP_INET4_CONNECT] =    "connect4",
        [BPF_CGROUP_INET6_CONNECT] =    "connect6",
        [BPF_CGROUP_INET4_POST_BIND] =  "post_bind4",
        [BPF_CGROUP_INET6_POST_BIND] =  "post_bind6",
        [BPF_CGROUP_UDP4_SENDMSG] =     "sendmsg4",
        [BPF_CGROUP_UDP6_SENDMSG] =     "sendmsg6",
        [BPF_CGROUP_SYSCTL] =           "sysctl",
        [BPF_CGROUP_UDP4_RECVMSG] =     "recvmsg4",
        [BPF_CGROUP_UDP6_RECVMSG] =     "recvmsg6",
        [BPF_CGROUP_GETSOCKOPT] =       "getsockopt",
        [BPF_CGROUP_SETSOCKOPT] =       "setsockopt",
};

DEFINE_STRING_TABLE_LOOKUP(bpf_cgroup_attach_type, int);

 /* struct bpf_prog_info info must be initialized since its value is both input and output
  * for BPF_OBJ_GET_INFO_BY_FD syscall. */
static int bpf_program_get_info_by_fd(int prog_fd, struct bpf_prog_info *info, uint32_t info_len) {
        union bpf_attr attr;

        /* Explicitly memset to zero since some compilers may produce non-zero-initialized padding when
         * structured initialization is used.
         * Refer to https://github.com/systemd/systemd/issues/18164
         */
        zero(attr);
        attr.info.bpf_fd = prog_fd;
        attr.info.info_len = info_len;
        attr.info.info = PTR_TO_UINT64(info);

        if (bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) < 0)
                return -errno;

        return 0;
}

int bpf_program_new(uint32_t prog_type, BPFProgram **ret) {
        _cleanup_(bpf_program_unrefp) BPFProgram *p = NULL;

        p = new0(BPFProgram, 1);
        if (!p)
                return -ENOMEM;

        p->n_ref = 1;
        p->prog_type = prog_type;
        p->kernel_fd = -1;

        *ret = TAKE_PTR(p);

        return 0;
}

int bpf_program_new_from_bpffs_path(const char *path, BPFProgram **ret) {
        _cleanup_(bpf_program_unrefp) BPFProgram *p = NULL;
        struct bpf_prog_info info = {};
        int r;

        assert(path);
        assert(ret);

        p = new(BPFProgram, 1);
        if (!p)
                return -ENOMEM;

        *p = (BPFProgram) {
                .prog_type = BPF_PROG_TYPE_UNSPEC,
                .n_ref = 1,
                .kernel_fd = -1,
        };

        r = bpf_program_load_from_bpf_fs(p, path);
        if (r < 0)
                return r;

        r = bpf_program_get_info_by_fd(p->kernel_fd, &info, sizeof(info));
        if (r < 0)
                return r;

        p->prog_type = info.type;
        *ret = TAKE_PTR(p);

        return 0;
}

static BPFProgram *bpf_program_free(BPFProgram *p) {
        assert(p);

        /* Unfortunately, the kernel currently doesn't implicitly detach BPF programs from their cgroups when the last
         * fd to the BPF program is closed. This has nasty side-effects since this means that abnormally terminated
         * programs that attached one of their BPF programs to a cgroup will leave this programs pinned for good with
         * zero chance of recovery, until the cgroup is removed. This is particularly problematic if the cgroup in
         * question is the root cgroup (or any other cgroup belonging to a service that cannot be restarted during
         * operation, such as dbus), as the memory for the BPF program can only be reclaimed through a reboot. To
         * counter this, we track closely to which cgroup a program was attached to and will detach it on our own
         * whenever we close the BPF fd. */
        (void) bpf_program_cgroup_detach(p);

        safe_close(p->kernel_fd);
        free(p->instructions);
        free(p->attached_path);

        return mfree(p);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(BPFProgram, bpf_program, bpf_program_free);

int bpf_program_add_instructions(BPFProgram *p, const struct bpf_insn *instructions, size_t count) {

        assert(p);

        if (p->kernel_fd >= 0) /* don't allow modification after we uploaded things to the kernel */
                return -EBUSY;

        if (!GREEDY_REALLOC(p->instructions, p->allocated, p->n_instructions + count))
                return -ENOMEM;

        memcpy(p->instructions + p->n_instructions, instructions, sizeof(struct bpf_insn) * count);
        p->n_instructions += count;

        return 0;
}

int bpf_program_load_kernel(BPFProgram *p, char *log_buf, size_t log_size) {
        union bpf_attr attr;

        assert(p);

        if (p->kernel_fd >= 0) { /* make this idempotent */
                memzero(log_buf, log_size);
                return 0;
        }

        // FIXME: Clang doesn't 0-pad with structured initialization, causing
        // the kernel to reject the bpf_attr as invalid. See:
        // https://github.com/torvalds/linux/blob/v5.9/kernel/bpf/syscall.c#L65
        // Ideally it should behave like GCC, so that we can remove these workarounds.
        zero(attr);
        attr.prog_type = p->prog_type;
        attr.insns = PTR_TO_UINT64(p->instructions);
        attr.insn_cnt = p->n_instructions;
        attr.license = PTR_TO_UINT64("GPL");
        attr.log_buf = PTR_TO_UINT64(log_buf);
        attr.log_level = !!log_buf;
        attr.log_size = log_size;

        p->kernel_fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
        if (p->kernel_fd < 0)
                return -errno;

        return 0;
}

int bpf_program_load_from_bpf_fs(BPFProgram *p, const char *path) {
        union bpf_attr attr;

        assert(p);

        if (p->kernel_fd >= 0) /* don't overwrite an assembled or loaded program */
                return -EBUSY;

        zero(attr);
        attr.pathname = PTR_TO_UINT64(path);

        p->kernel_fd = bpf(BPF_OBJ_GET, &attr, sizeof(attr));
        if (p->kernel_fd < 0)
                return -errno;

        return 0;
}

int bpf_program_cgroup_attach(BPFProgram *p, int type, const char *path, uint32_t flags) {
        _cleanup_free_ char *copy = NULL;
        _cleanup_close_ int fd = -1;
        union bpf_attr attr;
        int r;

        assert(p);
        assert(type >= 0);
        assert(path);

        if (!IN_SET(flags, 0, BPF_F_ALLOW_OVERRIDE, BPF_F_ALLOW_MULTI))
                return -EINVAL;

        /* We need to track which cgroup the program is attached to, and we can only track one attachment, hence let's
        * refuse this early. */
        if (p->attached_path) {
                if (!path_equal(p->attached_path, path))
                        return -EBUSY;
                if (p->attached_type != type)
                        return -EBUSY;
                if (p->attached_flags != flags)
                        return -EBUSY;

                /* Here's a shortcut: if we previously attached this program already, then we don't have to do so
                 * again. Well, with one exception: if we are in BPF_F_ALLOW_OVERRIDE mode then someone else might have
                 * replaced our program since the last time, hence let's reattach it again, just to be safe. In flags
                 * == 0 mode this is not an issue since nobody else can replace our program in that case, and in flags
                 * == BPF_F_ALLOW_MULTI mode any other's program would be installed in addition to ours hence ours
                 * would remain in effect. */
                if (flags != BPF_F_ALLOW_OVERRIDE)
                        return 0;
        }

        /* Ensure we have a kernel object for this. */
        r = bpf_program_load_kernel(p, NULL, 0);
        if (r < 0)
                return r;

        copy = strdup(path);
        if (!copy)
                return -ENOMEM;

        fd = open(path, O_DIRECTORY|O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        zero(attr);
        attr.attach_type = type;
        attr.target_fd = fd;
        attr.attach_bpf_fd = p->kernel_fd;
        attr.attach_flags = flags;

        if (bpf(BPF_PROG_ATTACH, &attr, sizeof(attr)) < 0)
                return -errno;

        free_and_replace(p->attached_path, copy);
        p->attached_type = type;
        p->attached_flags = flags;

        return 0;
}

int bpf_program_cgroup_detach(BPFProgram *p) {
        _cleanup_close_ int fd = -1;

        assert(p);

        if (!p->attached_path)
                return -EUNATCH;

        fd = open(p->attached_path, O_DIRECTORY|O_RDONLY|O_CLOEXEC);
        if (fd < 0) {
                if (errno != ENOENT)
                        return -errno;

                /* If the cgroup does not exist anymore, then we don't have to explicitly detach, it got detached
                 * implicitly by the removal, hence don't complain */

        } else {
                union bpf_attr attr;

                zero(attr);
                attr.attach_type = p->attached_type;
                attr.target_fd = fd;
                attr.attach_bpf_fd = p->kernel_fd;

                if (bpf(BPF_PROG_DETACH, &attr, sizeof(attr)) < 0)
                        return -errno;
        }

        p->attached_path = mfree(p->attached_path);

        return 0;
}

int bpf_map_new(enum bpf_map_type type, size_t key_size, size_t value_size, size_t max_entries, uint32_t flags) {
        union bpf_attr attr;
        int fd;

        zero(attr);
        attr.map_type = type;
        attr.key_size = key_size;
        attr.value_size = value_size;
        attr.max_entries = max_entries;
        attr.map_flags = flags;

        fd = bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
        if (fd < 0)
                return -errno;

        return fd;
}

int bpf_map_update_element(int fd, const void *key, void *value) {
        union bpf_attr attr;

        zero(attr);
        attr.map_fd = fd;
        attr.key = PTR_TO_UINT64(key);
        attr.value = PTR_TO_UINT64(value);

        if (bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr)) < 0)
                return -errno;

        return 0;
}

int bpf_map_lookup_element(int fd, const void *key, void *value) {
        union bpf_attr attr;

        zero(attr);
        attr.map_fd = fd;
        attr.key = PTR_TO_UINT64(key);
        attr.value = PTR_TO_UINT64(value);

        if (bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr)) < 0)
                return -errno;

        return 0;
}

int bpf_program_pin(int prog_fd, const char *bpffs_path) {
        union bpf_attr attr;

        zero(attr);
        attr.pathname = PTR_TO_UINT64((void *) bpffs_path);
        attr.bpf_fd = prog_fd;

        if (bpf(BPF_OBJ_PIN, &attr, sizeof(attr)) < 0)
                return -errno;

        return 0;
}

int bpf_program_get_id_by_fd(int prog_fd, uint32_t *ret_id) {
        struct bpf_prog_info info = {};
        int r;

        assert(ret_id);

        r = bpf_program_get_info_by_fd(prog_fd, &info, sizeof(info));
        if (r < 0)
                return r;

        *ret_id = info.id;

        return 0;
};
