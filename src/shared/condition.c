/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "apparmor-util.h"
#include "architecture.h"
#include "audit-util.h"
#include "blockdev-util.h"
#include "cap-list.h"
#include "cgroup-util.h"
#include "condition.h"
#include "cpu-set-util.h"
#include "efi-loader.h"
#include "env-file.h"
#include "env-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "glob-util.h"
#include "hostname-util.h"
#include "ima-util.h"
#include "limits-util.h"
#include "list.h"
#include "macro.h"
#include "mountpoint-util.h"
#include "os-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "selinux-util.h"
#include "smack-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "tomoyo-util.h"
#include "user-record.h"
#include "user-util.h"
#include "util.h"
#include "virt.h"

Condition* condition_new(ConditionType type, const char *parameter, bool trigger, bool negate) {
        Condition *c;

        assert(type >= 0);
        assert(type < _CONDITION_TYPE_MAX);
        assert(parameter);

        c = new(Condition, 1);
        if (!c)
                return NULL;

        *c = (Condition) {
                .type = type,
                .trigger = trigger,
                .negate = negate,
        };

        if (parameter) {
                c->parameter = strdup(parameter);
                if (!c->parameter)
                        return mfree(c);
        }

        return c;
}

Condition* condition_free(Condition *c) {
        assert(c);

        free(c->parameter);
        return mfree(c);
}

Condition* condition_free_list_type(Condition *head, ConditionType type) {
        Condition *c, *n;

        LIST_FOREACH_SAFE(conditions, c, n, head)
                if (type < 0 || c->type == type) {
                        LIST_REMOVE(conditions, head, c);
                        condition_free(c);
                }

        assert(type >= 0 || !head);
        return head;
}

static int condition_test_kernel_command_line(Condition *c, char **env) {
        _cleanup_free_ char *line = NULL;
        const char *p;
        bool equal;
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_KERNEL_COMMAND_LINE);

        r = proc_cmdline(&line);
        if (r < 0)
                return r;

        equal = strchr(c->parameter, '=');

        for (p = line;;) {
                _cleanup_free_ char *word = NULL;
                bool found;

                r = extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE|EXTRACT_RELAX);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (equal)
                        found = streq(word, c->parameter);
                else {
                        const char *f;

                        f = startswith(word, c->parameter);
                        found = f && IN_SET(*f, 0, '=');
                }

                if (found)
                        return true;
        }

        return false;
}

typedef enum {
        /* Listed in order of checking. Note that some comparators are prefixes of others, hence the longest
         * should be listed first. */
        ORDER_LOWER_OR_EQUAL,
        ORDER_GREATER_OR_EQUAL,
        ORDER_LOWER,
        ORDER_GREATER,
        ORDER_EQUAL,
        ORDER_UNEQUAL,
        _ORDER_MAX,
        _ORDER_INVALID = -EINVAL,
} OrderOperator;

static OrderOperator parse_order(const char **s) {

        static const char *const prefix[_ORDER_MAX] = {
                [ORDER_LOWER_OR_EQUAL] = "<=",
                [ORDER_GREATER_OR_EQUAL] = ">=",
                [ORDER_LOWER] = "<",
                [ORDER_GREATER] = ">",
                [ORDER_EQUAL] = "=",
                [ORDER_UNEQUAL] = "!=",
        };

        OrderOperator i;

        for (i = 0; i < _ORDER_MAX; i++) {
                const char *e;

                e = startswith(*s, prefix[i]);
                if (e) {
                        *s = e;
                        return i;
                }
        }

        return _ORDER_INVALID;
}

static bool test_order(int k, OrderOperator p) {

        switch (p) {

        case ORDER_LOWER:
                return k < 0;

        case ORDER_LOWER_OR_EQUAL:
                return k <= 0;

        case ORDER_EQUAL:
                return k == 0;

        case ORDER_UNEQUAL:
                return k != 0;

        case ORDER_GREATER_OR_EQUAL:
                return k >= 0;

        case ORDER_GREATER:
                return k > 0;

        default:
                assert_not_reached("unknown order");

        }
}

static int condition_test_kernel_version(Condition *c, char **env) {
        OrderOperator order;
        struct utsname u;
        const char *p;
        bool first = true;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_KERNEL_VERSION);

        assert_se(uname(&u) >= 0);

        p = c->parameter;

        for (;;) {
                _cleanup_free_ char *word = NULL;
                const char *s;
                int r;

                r = extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE);
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse condition string \"%s\": %m", p);
                if (r == 0)
                        break;

                s = strstrip(word);
                order = parse_order(&s);
                if (order >= 0) {
                        s += strspn(s, WHITESPACE);
                        if (isempty(s)) {
                                if (first) {
                                        /* For backwards compatibility, allow whitespace between the operator and
                                         * value, without quoting, but only in the first expression. */
                                        word = mfree(word);
                                        r = extract_first_word(&p, &word, NULL, 0);
                                        if (r < 0)
                                                return log_debug_errno(r, "Failed to parse condition string \"%s\": %m", p);
                                        if (r == 0)
                                                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Unexpected end of expression: %s", p);
                                        s = word;
                                } else
                                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Unexpected end of expression: %s", p);
                        }

                        r = test_order(strverscmp_improved(u.release, s), order);
                } else
                        /* No prefix? Then treat as glob string */
                        r = fnmatch(s, u.release, 0) == 0;

                if (r == 0)
                        return false;

                first = false;
        }

        return true;
}

static int condition_test_osrelease(Condition *c, char **env) {
        const char *parameter = c->parameter;
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_OS_RELEASE);

        for (;;) {
                _cleanup_free_ char *key = NULL, *condition = NULL, *actual_value = NULL;
                OrderOperator order;
                const char *word;
                bool matches;

                r = extract_first_word(&parameter, &condition, NULL, EXTRACT_UNQUOTE);
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse parameter: %m");
                if (r == 0)
                        break;

                /* parse_order() needs the string to start with the comparators */
                word = condition;
                r = extract_first_word(&word, &key, "!<=>", EXTRACT_RETAIN_SEPARATORS);
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse parameter: %m");
                /* The os-release spec mandates env-var-like key names */
                if (r == 0 || isempty(word) || !env_name_is_valid(key))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                        "Failed to parse parameter, key/value format expected: %m");

                /* Do not allow whitespace after the separator, as that's not a valid os-release format */
                order = parse_order(&word);
                if (order < 0 || isempty(word) || strchr(WHITESPACE, *word) != NULL)
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                        "Failed to parse parameter, key/value format expected: %m");

                r = parse_os_release(NULL, key, &actual_value);
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse os-release: %m");

                /* Might not be comparing versions, so do exact string matching */
                if (order == ORDER_EQUAL)
                        matches = streq_ptr(actual_value, word);
                else if (order == ORDER_UNEQUAL)
                        matches = !streq_ptr(actual_value, word);
                else
                        matches = test_order(strverscmp_improved(actual_value, word), order);

                if (!matches)
                        return false;
        }

        return true;
}

static int condition_test_memory(Condition *c, char **env) {
        OrderOperator order;
        uint64_t m, k;
        const char *p;
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_MEMORY);

        m = physical_memory();

        p = c->parameter;
        order = parse_order(&p);
        if (order < 0)
                order = ORDER_GREATER_OR_EQUAL; /* default to >= check, if nothing is specified. */

        r = safe_atou64(p, &k);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse size: %m");

        return test_order(CMP(m, k), order);
}

static int condition_test_cpus(Condition *c, char **env) {
        OrderOperator order;
        const char *p;
        unsigned k;
        int r, n;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_CPUS);

        n = cpus_in_affinity_mask();
        if (n < 0)
                return log_debug_errno(n, "Failed to determine CPUs in affinity mask: %m");

        p = c->parameter;
        order = parse_order(&p);
        if (order < 0)
                order = ORDER_GREATER_OR_EQUAL; /* default to >= check, if nothing is specified. */

        r = safe_atou(p, &k);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse number of CPUs: %m");

        return test_order(CMP((unsigned) n, k), order);
}

static int condition_test_user(Condition *c, char **env) {
        uid_t id;
        int r;
        _cleanup_free_ char *username = NULL;
        const char *u;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_USER);

        r = parse_uid(c->parameter, &id);
        if (r >= 0)
                return id == getuid() || id == geteuid();

        if (streq("@system", c->parameter))
                return uid_is_system(getuid()) || uid_is_system(geteuid());

        username = getusername_malloc();
        if (!username)
                return -ENOMEM;

        if (streq(username, c->parameter))
                return 1;

        if (getpid_cached() == 1)
                return streq(c->parameter, "root");

        u = c->parameter;
        r = get_user_creds(&u, &id, NULL, NULL, NULL, USER_CREDS_ALLOW_MISSING);
        if (r < 0)
                return 0;

        return id == getuid() || id == geteuid();
}

static int condition_test_control_group_controller(Condition *c, char **env) {
        int r;
        CGroupMask system_mask, wanted_mask = 0;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_CONTROL_GROUP_CONTROLLER);

        if (streq(c->parameter, "v2"))
                return cg_all_unified();
        if (streq(c->parameter, "v1")) {
                r = cg_all_unified();
                if (r < 0)
                        return r;
                return !r;
        }

        r = cg_mask_supported(&system_mask);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine supported controllers: %m");

        r = cg_mask_from_string(c->parameter, &wanted_mask);
        if (r < 0 || wanted_mask <= 0) {
                /* This won't catch the case that we have an unknown controller
                 * mixed in with valid ones -- these are only assessed on the
                 * validity of the valid controllers found. */
                log_debug("Failed to parse cgroup string: %s", c->parameter);
                return 1;
        }

        return FLAGS_SET(system_mask, wanted_mask);
}

static int condition_test_group(Condition *c, char **env) {
        gid_t id;
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_GROUP);

        r = parse_gid(c->parameter, &id);
        if (r >= 0)
                return in_gid(id);

        /* Avoid any NSS lookups if we are PID1 */
        if (getpid_cached() == 1)
                return streq(c->parameter, "root");

        return in_group(c->parameter) > 0;
}

static int condition_test_virtualization(Condition *c, char **env) {
        int b, v;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_VIRTUALIZATION);

        if (streq(c->parameter, "private-users"))
                return running_in_userns();

        v = detect_virtualization();
        if (v < 0)
                return v;

        /* First, compare with yes/no */
        b = parse_boolean(c->parameter);
        if (b >= 0)
                return b == !!v;

        /* Then, compare categorization */
        if (streq(c->parameter, "vm"))
                return VIRTUALIZATION_IS_VM(v);

        if (streq(c->parameter, "container"))
                return VIRTUALIZATION_IS_CONTAINER(v);

        /* Finally compare id */
        return v != VIRTUALIZATION_NONE && streq(c->parameter, virtualization_to_string(v));
}

static int condition_test_architecture(Condition *c, char **env) {
        int a, b;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_ARCHITECTURE);

        a = uname_architecture();
        if (a < 0)
                return a;

        if (streq(c->parameter, "native"))
                b = native_architecture();
        else {
                b = architecture_from_string(c->parameter);
                if (b < 0) /* unknown architecture? Then it's definitely not ours */
                        return false;
        }

        return a == b;
}

#define DTCOMPAT_FILE "/sys/firmware/devicetree/base/compatible"
static int condition_test_firmware_devicetree_compatible(const char *dtcarg) {
        int r;
        _cleanup_free_ char *dtcompat = NULL;
        _cleanup_strv_free_ char **dtcompatlist = NULL;
        size_t size;

        r = read_full_virtual_file(DTCOMPAT_FILE, &dtcompat, &size);
        if (r < 0) {
                /* if the path doesn't exist it is incompatible */
                if (r != -ENOENT)
                        log_debug_errno(r, "Failed to open() '%s', assuming machine is incompatible: %m", DTCOMPAT_FILE);
                return false;
        }

        /* Not sure this can happen, but play safe. */
        if (size == 0) {
                log_debug("%s has zero length, assuming machine is incompatible", DTCOMPAT_FILE);
                return false;
        }

        /*
         * /sys/firmware/devicetree/base/compatible consists of one or more
         * strings, each ending in '\0'. So the last character in dtcompat must
         * be a '\0'.
         */
        if (dtcompat[size - 1] != '\0') {
                log_debug("%s is in an unknown format, assuming machine is incompatible", DTCOMPAT_FILE);
                return false;
        }

        dtcompatlist = strv_parse_nulstr(dtcompat, size);
        if (!dtcompatlist)
                return -ENOMEM;

        return strv_contains(dtcompatlist, dtcarg);
}

static int condition_test_firmware(Condition *c, char **env) {
        sd_char *dtc;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_FIRMWARE);

        if (streq(c->parameter, "device-tree")) {
                if (access("/sys/firmware/device-tree/", F_OK) < 0) {
                        if (errno != ENOENT)
                                log_debug_errno(errno, "Unexpected error when checking for /sys/firmware/device-tree/: %m");
                        return false;
                } else
                        return true;
        } else if ((dtc = startswith(c->parameter, "device-tree-compatible("))) {
                _cleanup_free_ char *dtcarg = NULL;
                char *end;

                end = strchr(dtc, ')');
                if (!end || *(end + 1) != '\0') {
                        log_debug("Malformed Firmware condition \"%s\"", c->parameter);
                        return false;
                }

                dtcarg = strndup(dtc, end - dtc);
                if (!dtcarg)
                        return -ENOMEM;

                return condition_test_firmware_devicetree_compatible(dtcarg);
        } else if (streq(c->parameter, "uefi"))
                return is_efi_boot();
        else {
                log_debug("Unsupported Firmware condition \"%s\"", c->parameter);
                return false;
        }
}

static int condition_test_host(Condition *c, char **env) {
        _cleanup_free_ char *h = NULL;
        sd_id128_t x, y;
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_HOST);

        if (sd_id128_from_string(c->parameter, &x) >= 0) {

                r = sd_id128_get_machine(&y);
                if (r < 0)
                        return r;

                return sd_id128_equal(x, y);
        }

        h = gethostname_malloc();
        if (!h)
                return -ENOMEM;

        return fnmatch(c->parameter, h, FNM_CASEFOLD) == 0;
}

static int condition_test_ac_power(Condition *c, char **env) {
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_AC_POWER);

        r = parse_boolean(c->parameter);
        if (r < 0)
                return r;

        return (on_ac_power() != 0) == !!r;
}

static int has_tpm2(void) {
        int r;

        /* Checks whether the system has at least one TPM2 resource manager device, i.e. at least one "tpmrm"
         * class device */

        r = dir_is_empty("/sys/class/tpmrm");
        if (r == 0)
                return true; /* nice! we have a device */

        /* Hmm, so Linux doesn't know of the TPM2 device (or we couldn't check for it), most likely because
         * the driver wasn't loaded yet. Let's see if the firmware knows about a TPM2 device, in this
         * case. This way we can answer the TPM2 question already during early boot (where we most likely
         * need it) */
        if (efi_has_tpm2())
                return true;

        /* OK, this didn't work either, in this case propagate the original errors */
        if (r == -ENOENT)
                return false;
        if (r < 0)
                return log_debug_errno(r, "Failed to determine whether system has TPM2 support: %m");

        return !r;
}

static int condition_test_security(Condition *c, char **env) {
        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_SECURITY);

        if (streq(c->parameter, "selinux"))
                return mac_selinux_use();
        if (streq(c->parameter, "smack"))
                return mac_smack_use();
        if (streq(c->parameter, "apparmor"))
                return mac_apparmor_use();
        if (streq(c->parameter, "audit"))
                return use_audit();
        if (streq(c->parameter, "ima"))
                return use_ima();
        if (streq(c->parameter, "tomoyo"))
                return mac_tomoyo_use();
        if (streq(c->parameter, "uefi-secureboot"))
                return is_efi_secure_boot();
        if (streq(c->parameter, "tpm2"))
                return has_tpm2();

        return false;
}

static int condition_test_capability(Condition *c, char **env) {
        unsigned long long capabilities = (unsigned long long) -1;
        _cleanup_fclose_ FILE *f = NULL;
        int value, r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_CAPABILITY);

        /* If it's an invalid capability, we don't have it */
        value = capability_from_name(c->parameter);
        if (value < 0)
                return -EINVAL;

        /* If it's a valid capability we default to assume
         * that we have it */

        f = fopen("/proc/self/status", "re");
        if (!f)
                return -errno;

        for (;;) {
                _cleanup_free_ char *line = NULL;
                const char *p;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                p = startswith(line, "CapBnd:");
                if (p) {
                        if (sscanf(line+7, "%llx", &capabilities) != 1)
                                return -EIO;

                        break;
                }
        }

        return !!(capabilities & (1ULL << value));
}

static int condition_test_needs_update(Condition *c, char **env) {
        struct stat usr, other;
        const char *p;
        bool b;
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_NEEDS_UPDATE);

        r = proc_cmdline_get_bool("systemd.condition-needs-update", &b);
        if (r < 0)
                log_debug_errno(r, "Failed to parse systemd.condition-needs-update= kernel command line argument, ignoring: %m");
        if (r > 0)
                return b;

        if (in_initrd()) {
                log_debug("We are in an initrd, not doing any updates.");
                return false;
        }

        if (!path_is_absolute(c->parameter)) {
                log_debug("Specified condition parameter '%s' is not absolute, assuming an update is needed.", c->parameter);
                return true;
        }

        /* If the file system is read-only we shouldn't suggest an update */
        r = path_is_read_only_fs(c->parameter);
        if (r < 0)
                log_debug_errno(r, "Failed to determine if '%s' is read-only, ignoring: %m", c->parameter);
        if (r > 0)
                return false;

        /* Any other failure means we should allow the condition to be true, so that we rather invoke too
         * many update tools than too few. */

        p = strjoina(c->parameter, "/.updated");
        if (lstat(p, &other) < 0) {
                if (errno != ENOENT)
                        log_debug_errno(errno, "Failed to stat() '%s', assuming an update is needed: %m", p);
                return true;
        }

        if (lstat("/usr/", &usr) < 0) {
                log_debug_errno(errno, "Failed to stat() /usr/, assuming an update is needed: %m");
                return true;
        }

        /*
         * First, compare seconds as they are always accurate...
         */
        if (usr.st_mtim.tv_sec != other.st_mtim.tv_sec)
                return usr.st_mtim.tv_sec > other.st_mtim.tv_sec;

        /*
         * ...then compare nanoseconds.
         *
         * A false positive is only possible when /usr's nanoseconds > 0
         * (otherwise /usr cannot be strictly newer than the target file)
         * AND the target file's nanoseconds == 0
         * (otherwise the filesystem supports nsec timestamps, see stat(2)).
         */
        if (usr.st_mtim.tv_nsec == 0 || other.st_mtim.tv_nsec > 0)
                return usr.st_mtim.tv_nsec > other.st_mtim.tv_nsec;

        _cleanup_free_ char *timestamp_str = NULL;
        r = parse_env_file(NULL, p, "TIMESTAMP_NSEC", &timestamp_str);
        if (r < 0) {
                log_debug_errno(r, "Failed to parse timestamp file '%s', using mtime: %m", p);
                return true;
        } else if (r == 0) {
                log_debug("No data in timestamp file '%s', using mtime.", p);
                return true;
        }

        uint64_t timestamp;
        r = safe_atou64(timestamp_str, &timestamp);
        if (r < 0) {
                log_debug_errno(r, "Failed to parse timestamp value '%s' in file '%s', using mtime: %m", timestamp_str, p);
                return true;
        }

        return timespec_load_nsec(&usr.st_mtim) > timestamp;
}

static int condition_test_first_boot(Condition *c, char **env) {
        int r, q;
        bool b;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_FIRST_BOOT);

        r = proc_cmdline_get_bool("systemd.condition-first-boot", &b);
        if (r < 0)
                log_debug_errno(r, "Failed to parse systemd.condition-first-boot= kernel command line argument, ignoring: %m");
        if (r > 0)
                return b == !!r;

        r = parse_boolean(c->parameter);
        if (r < 0)
                return r;

        q = access("/run/systemd/first-boot", F_OK);
        if (q < 0 && errno != ENOENT)
                log_debug_errno(errno, "Failed to check if /run/systemd/first-boot exists, ignoring: %m");

        return (q >= 0) == !!r;
}

static int condition_test_environment(Condition *c, char **env) {
        bool equal;
        char **i;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_ENVIRONMENT);

        equal = strchr(c->parameter, '=');

        STRV_FOREACH(i, env) {
                bool found;

                if (equal)
                        found = streq(c->parameter, *i);
                else {
                        const char *f;

                        f = startswith(*i, c->parameter);
                        found = f && IN_SET(*f, 0, '=');
                }

                if (found)
                        return true;
        }

        return false;
}

static int condition_test_path_exists(Condition *c, char **env) {
        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_PATH_EXISTS);

        return access(c->parameter, F_OK) >= 0;
}

static int condition_test_path_exists_glob(Condition *c, char **env) {
        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_PATH_EXISTS_GLOB);

        return glob_exists(c->parameter) > 0;
}

static int condition_test_path_is_directory(Condition *c, char **env) {
        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_PATH_IS_DIRECTORY);

        return is_dir(c->parameter, true) > 0;
}

static int condition_test_path_is_symbolic_link(Condition *c, char **env) {
        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_PATH_IS_SYMBOLIC_LINK);

        return is_symlink(c->parameter) > 0;
}

static int condition_test_path_is_mount_point(Condition *c, char **env) {
        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_PATH_IS_MOUNT_POINT);

        return path_is_mount_point(c->parameter, NULL, AT_SYMLINK_FOLLOW) > 0;
}

static int condition_test_path_is_read_write(Condition *c, char **env) {
        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_PATH_IS_READ_WRITE);

        return path_is_read_only_fs(c->parameter) <= 0;
}

static int condition_test_cpufeature(Condition *c, char **env) {
        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_CPU_FEATURE);

        return has_cpu_with_flag(ascii_strlower(c->parameter));
}

static int condition_test_path_is_encrypted(Condition *c, char **env) {
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_PATH_IS_ENCRYPTED);

        r = path_is_encrypted(c->parameter);
        if (r < 0 && r != -ENOENT)
                log_debug_errno(r, "Failed to determine if '%s' is encrypted: %m", c->parameter);

        return r > 0;
}

static int condition_test_directory_not_empty(Condition *c, char **env) {
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_DIRECTORY_NOT_EMPTY);

        r = dir_is_empty(c->parameter);
        return r <= 0 && r != -ENOENT;
}

static int condition_test_file_not_empty(Condition *c, char **env) {
        struct stat st;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_FILE_NOT_EMPTY);

        return (stat(c->parameter, &st) >= 0 &&
                S_ISREG(st.st_mode) &&
                st.st_size > 0);
}

static int condition_test_file_is_executable(Condition *c, char **env) {
        struct stat st;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_FILE_IS_EXECUTABLE);

        return (stat(c->parameter, &st) >= 0 &&
                S_ISREG(st.st_mode) &&
                (st.st_mode & 0111));
}

int condition_test(Condition *c, char **env) {

        static int (*const condition_tests[_CONDITION_TYPE_MAX])(Condition *c, char **env) = {
                [CONDITION_PATH_EXISTS]              = condition_test_path_exists,
                [CONDITION_PATH_EXISTS_GLOB]         = condition_test_path_exists_glob,
                [CONDITION_PATH_IS_DIRECTORY]        = condition_test_path_is_directory,
                [CONDITION_PATH_IS_SYMBOLIC_LINK]    = condition_test_path_is_symbolic_link,
                [CONDITION_PATH_IS_MOUNT_POINT]      = condition_test_path_is_mount_point,
                [CONDITION_PATH_IS_READ_WRITE]       = condition_test_path_is_read_write,
                [CONDITION_PATH_IS_ENCRYPTED]        = condition_test_path_is_encrypted,
                [CONDITION_DIRECTORY_NOT_EMPTY]      = condition_test_directory_not_empty,
                [CONDITION_FILE_NOT_EMPTY]           = condition_test_file_not_empty,
                [CONDITION_FILE_IS_EXECUTABLE]       = condition_test_file_is_executable,
                [CONDITION_KERNEL_COMMAND_LINE]      = condition_test_kernel_command_line,
                [CONDITION_KERNEL_VERSION]           = condition_test_kernel_version,
                [CONDITION_VIRTUALIZATION]           = condition_test_virtualization,
                [CONDITION_SECURITY]                 = condition_test_security,
                [CONDITION_CAPABILITY]               = condition_test_capability,
                [CONDITION_HOST]                     = condition_test_host,
                [CONDITION_AC_POWER]                 = condition_test_ac_power,
                [CONDITION_ARCHITECTURE]             = condition_test_architecture,
                [CONDITION_FIRMWARE]                 = condition_test_firmware,
                [CONDITION_NEEDS_UPDATE]             = condition_test_needs_update,
                [CONDITION_FIRST_BOOT]               = condition_test_first_boot,
                [CONDITION_USER]                     = condition_test_user,
                [CONDITION_GROUP]                    = condition_test_group,
                [CONDITION_CONTROL_GROUP_CONTROLLER] = condition_test_control_group_controller,
                [CONDITION_CPUS]                     = condition_test_cpus,
                [CONDITION_MEMORY]                   = condition_test_memory,
                [CONDITION_ENVIRONMENT]              = condition_test_environment,
                [CONDITION_CPU_FEATURE]              = condition_test_cpufeature,
                [CONDITION_OS_RELEASE]               = condition_test_osrelease,
        };

        int r, b;

        assert(c);
        assert(c->type >= 0);
        assert(c->type < _CONDITION_TYPE_MAX);

        r = condition_tests[c->type](c, env);
        if (r < 0) {
                c->result = CONDITION_ERROR;
                return r;
        }

        b = (r > 0) == !c->negate;
        c->result = b ? CONDITION_SUCCEEDED : CONDITION_FAILED;
        return b;
}

bool condition_test_list(
                Condition *first,
                char **env,
                condition_to_string_t to_string,
                condition_test_logger_t logger,
                void *userdata) {

        Condition *c;
        int triggered = -1;

        assert(!!logger == !!to_string);

        /* If the condition list is empty, then it is true */
        if (!first)
                return true;

        /* Otherwise, if all of the non-trigger conditions apply and
         * if any of the trigger conditions apply (unless there are
         * none) we return true */
        LIST_FOREACH(conditions, c, first) {
                int r;

                r = condition_test(c, env);

                if (logger) {
                        if (r < 0)
                                logger(userdata, LOG_WARNING, r, PROJECT_FILE, __LINE__, __func__,
                                       "Couldn't determine result for %s=%s%s%s, assuming failed: %m",
                                       to_string(c->type),
                                       c->trigger ? "|" : "",
                                       c->negate ? "!" : "",
                                       c->parameter);
                        else
                                logger(userdata, LOG_DEBUG, 0, PROJECT_FILE, __LINE__, __func__,
                                       "%s=%s%s%s %s.",
                                       to_string(c->type),
                                       c->trigger ? "|" : "",
                                       c->negate ? "!" : "",
                                       c->parameter,
                                       condition_result_to_string(c->result));
                }

                if (!c->trigger && r <= 0)
                        return false;

                if (c->trigger && triggered <= 0)
                        triggered = r > 0;
        }

        return triggered != 0;
}

void condition_dump(Condition *c, FILE *f, const char *prefix, condition_to_string_t to_string) {
        assert(c);
        assert(f);
        assert(to_string);

        prefix = strempty(prefix);

        fprintf(f,
                "%s\t%s: %s%s%s %s\n",
                prefix,
                to_string(c->type),
                c->trigger ? "|" : "",
                c->negate ? "!" : "",
                c->parameter,
                condition_result_to_string(c->result));
}

void condition_dump_list(Condition *first, FILE *f, const char *prefix, condition_to_string_t to_string) {
        Condition *c;

        LIST_FOREACH(conditions, c, first)
                condition_dump(c, f, prefix, to_string);
}

static const char* const condition_type_table[_CONDITION_TYPE_MAX] = {
        [CONDITION_ARCHITECTURE] = "ConditionArchitecture",
        [CONDITION_FIRMWARE] = "ConditionFirmware",
        [CONDITION_VIRTUALIZATION] = "ConditionVirtualization",
        [CONDITION_HOST] = "ConditionHost",
        [CONDITION_KERNEL_COMMAND_LINE] = "ConditionKernelCommandLine",
        [CONDITION_KERNEL_VERSION] = "ConditionKernelVersion",
        [CONDITION_SECURITY] = "ConditionSecurity",
        [CONDITION_CAPABILITY] = "ConditionCapability",
        [CONDITION_AC_POWER] = "ConditionACPower",
        [CONDITION_NEEDS_UPDATE] = "ConditionNeedsUpdate",
        [CONDITION_FIRST_BOOT] = "ConditionFirstBoot",
        [CONDITION_PATH_EXISTS] = "ConditionPathExists",
        [CONDITION_PATH_EXISTS_GLOB] = "ConditionPathExistsGlob",
        [CONDITION_PATH_IS_DIRECTORY] = "ConditionPathIsDirectory",
        [CONDITION_PATH_IS_SYMBOLIC_LINK] = "ConditionPathIsSymbolicLink",
        [CONDITION_PATH_IS_MOUNT_POINT] = "ConditionPathIsMountPoint",
        [CONDITION_PATH_IS_READ_WRITE] = "ConditionPathIsReadWrite",
        [CONDITION_PATH_IS_ENCRYPTED] = "ConditionPathIsEncrypted",
        [CONDITION_DIRECTORY_NOT_EMPTY] = "ConditionDirectoryNotEmpty",
        [CONDITION_FILE_NOT_EMPTY] = "ConditionFileNotEmpty",
        [CONDITION_FILE_IS_EXECUTABLE] = "ConditionFileIsExecutable",
        [CONDITION_USER] = "ConditionUser",
        [CONDITION_GROUP] = "ConditionGroup",
        [CONDITION_CONTROL_GROUP_CONTROLLER] = "ConditionControlGroupController",
        [CONDITION_CPUS] = "ConditionCPUs",
        [CONDITION_MEMORY] = "ConditionMemory",
        [CONDITION_ENVIRONMENT] = "ConditionEnvironment",
        [CONDITION_CPU_FEATURE] = "ConditionCPUFeature",
        [CONDITION_OS_RELEASE] = "ConditionOSRelease",
};

DEFINE_STRING_TABLE_LOOKUP(condition_type, ConditionType);

static const char* const assert_type_table[_CONDITION_TYPE_MAX] = {
        [CONDITION_ARCHITECTURE] = "AssertArchitecture",
        [CONDITION_FIRMWARE] = "AssertFirmware",
        [CONDITION_VIRTUALIZATION] = "AssertVirtualization",
        [CONDITION_HOST] = "AssertHost",
        [CONDITION_KERNEL_COMMAND_LINE] = "AssertKernelCommandLine",
        [CONDITION_KERNEL_VERSION] = "AssertKernelVersion",
        [CONDITION_SECURITY] = "AssertSecurity",
        [CONDITION_CAPABILITY] = "AssertCapability",
        [CONDITION_AC_POWER] = "AssertACPower",
        [CONDITION_NEEDS_UPDATE] = "AssertNeedsUpdate",
        [CONDITION_FIRST_BOOT] = "AssertFirstBoot",
        [CONDITION_PATH_EXISTS] = "AssertPathExists",
        [CONDITION_PATH_EXISTS_GLOB] = "AssertPathExistsGlob",
        [CONDITION_PATH_IS_DIRECTORY] = "AssertPathIsDirectory",
        [CONDITION_PATH_IS_SYMBOLIC_LINK] = "AssertPathIsSymbolicLink",
        [CONDITION_PATH_IS_MOUNT_POINT] = "AssertPathIsMountPoint",
        [CONDITION_PATH_IS_READ_WRITE] = "AssertPathIsReadWrite",
        [CONDITION_PATH_IS_ENCRYPTED] = "AssertPathIsEncrypted",
        [CONDITION_DIRECTORY_NOT_EMPTY] = "AssertDirectoryNotEmpty",
        [CONDITION_FILE_NOT_EMPTY] = "AssertFileNotEmpty",
        [CONDITION_FILE_IS_EXECUTABLE] = "AssertFileIsExecutable",
        [CONDITION_USER] = "AssertUser",
        [CONDITION_GROUP] = "AssertGroup",
        [CONDITION_CONTROL_GROUP_CONTROLLER] = "AssertControlGroupController",
        [CONDITION_CPUS] = "AssertCPUs",
        [CONDITION_MEMORY] = "AssertMemory",
        [CONDITION_ENVIRONMENT] = "AssertEnvironment",
        [CONDITION_CPU_FEATURE] = "AssertCPUFeature",
        [CONDITION_OS_RELEASE] = "AssertOSRelease",
};

DEFINE_STRING_TABLE_LOOKUP(assert_type, ConditionType);

static const char* const condition_result_table[_CONDITION_RESULT_MAX] = {
        [CONDITION_UNTESTED] = "untested",
        [CONDITION_SUCCEEDED] = "succeeded",
        [CONDITION_FAILED] = "failed",
        [CONDITION_ERROR] = "error",
};

DEFINE_STRING_TABLE_LOOKUP(condition_result, ConditionResult);
