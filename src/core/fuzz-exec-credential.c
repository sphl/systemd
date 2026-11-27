/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Fuzz target for the credential acquisition done for LoadCredential=/LoadCredentialEncrypted=/
 * ImportCredential=/SetCredential=/SetCredentialEncrypted= before a service is started:
 * acquire_credentials() → load_credential(), load_credential_glob(), load_cred_recurse_dir_cb(),
 * maybe_decrypt_and_write_credential() → decrypt_credential_and_warn(), plus the credential helpers in
 * src/shared/ that read credentials passed in from further up: read_credential_with_decryption(),
 * machine_credential_set(), machine_credential_load(). Credential sources may be written by less
 * privileged parties (e.g. a container manager passing credentials in, or a user's files referenced by
 * LoadCredential=), encrypted credentials are parsed before being authenticated.
 *
 * All credential sources are regular files created from the input in a temporary directory: the source
 * paths are always built below that directory, from sanitized names, so the READ_FULL_FILE_CONNECT_SOCKET
 * logic never finds a socket to connect to. Decryption never uses the host's secret or TPM:
 * $SYSTEMD_CREDENTIAL_SECRET and $SYSTEMD_TPM2_DEVICE point into the temporary directory. Nothing is
 * mounted: exec_setup_credentials() sets up the credentials in a plain directory below the temporary
 * directory, as it does without the privileges to mount a file system for them (see forbid_mounts()).
 *
 * Input: byte 0 bit 0 selects the service's user (the fuzzer's own user or UID 1000), then up to 32
 * records of [type] [name length] [name] [data length, 2 bytes LE] [data]. */

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "alloc-util.h"
#include "cgroup.h"
#include "creds-util.h"
#include "exec-credential.h"
#include "execute.h"
#include "fileio.h"
#include "fuzz.h"
#include "fuzz-network.h"
#include "iovec-util.h"
#include "machine-credential.h"
#include "mkdir.h"
#include "path-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "unaligned.h"

#define MAX_RECORDS 32

typedef enum RecordType {
        RECORD_SOURCE_FILE,          /* a file below the source directory */
        RECORD_SOURCE_SUBDIR_FILE,   /* a file in a subdirectory of the source directory */
        RECORD_RECEIVED_FILE,        /* a credential passed to us */
        RECORD_RECEIVED_ENCRYPTED,   /* an encrypted credential passed to us */
        RECORD_LOAD_PATH,            /* LoadCredential=ID:/path/in/source/dir */
        RECORD_LOAD_DIR,             /* LoadCredential=ID:/source/dir */
        RECORD_LOAD_NAME,            /* LoadCredential=ID:name-of-received-credential */
        RECORD_SET,                  /* SetCredential=ID:data */
        RECORD_IMPORT,               /* ImportCredential=GLOB:RENAME */
        RECORD_MACHINE_SET,          /* --set-credential=ID:DATA */
        RECORD_MACHINE_LOAD,         /* --load-credential=ID:NAME */
        RECORD_READ_WITH_DECRYPTION, /* read_credential_with_decryption(NAME) */
        _RECORD_TYPE_MAX,
} RecordType;

/* Bit 7 of the record type is a flag: LoadCredentialEncrypted=/SetCredentialEncrypted=, the subdirectory
 * for RECORD_LOAD_DIR, a path for RECORD_MACHINE_LOAD, the size for RECORD_READ_WITH_DECRYPTION */
#define RECORD_FLAG 0x80

/* exec_setup_credentials() mounts a file system for the credentials if it can, and uses a plain directory
 * otherwise. A fuzzer must not mount anything, hence make fsopen() fail as it does without privileges. It is
 * one of the newer system calls, which have the same number on all architectures. */
static void forbid_mounts(void) {
        static bool installed = false;
        struct sock_filter filter[] = {
                BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
                BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fsopen, 0, 1),
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        struct sock_fprog prog = {
                .len = ELEMENTSOF(filter),
                .filter = filter,
        };

        if (installed)
                return;

        ASSERT_OK_ERRNO(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
        ASSERT_OK_ERRNO(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0));

        installed = true;
}

/* Turns arbitrary bytes into something usable as a file name: no '/', no "." or "..". */
static char* sanitize_name(const uint8_t *p, size_t n, bool allow_glob) {
        char *s;
        size_t k = 0;

        s = new(char, n + 2);
        if (!s)
                return NULL;

        if (n == 0 || p[0] == '.')
                s[k++] = 'c';

        for (size_t i = 0; i < n; i++) {
                char c = p[i];

                if (ascii_isalpha(c) || ascii_isdigit(c) || IN_SET(c, '.', '_', '-', '@') ||
                    (allow_glob && IN_SET(c, '*', '?', '[', ']')))
                        s[k++] = c;
                else
                        s[k++] = '_';
        }

        s[k] = 0;
        return s;
}

static int write_file(const char *dir, const char *name, const uint8_t *data, size_t size) {
        _cleanup_free_ char *p = path_join(dir, name);
        if (!p)
                return -ENOMEM;

        return write_data_file_atomic_at(AT_FDCWD, p, &IOVEC_MAKE(data, size), WRITE_DATA_FILE_MKDIR_0755);
}

static void apply_record(
                RecordType type,
                bool flag,
                const char *name,
                const uint8_t *value,
                size_t value_size,
                ExecContext *ec,
                MachineCredentialContext *mc,
                const char *source,
                const char *subdir,
                const char *received,
                const char *received_encrypted) {

        _cleanup_free_ char *id = NULL;

        /* Credential IDs are derived from the names, with a prefix to keep them apart */
        id = ASSERT_NOT_NULL(strjoin("id-", name));

        /* Validated like config_parse_load_credential() and config_parse_set_credential() do */
        if (IN_SET(type, RECORD_LOAD_PATH, RECORD_LOAD_DIR, RECORD_LOAD_NAME, RECORD_SET) &&
            !credential_name_valid(id))
                return;

        switch (type) {

        case RECORD_SOURCE_FILE:
                (void) write_file(source, name, value, value_size);
                break;

        case RECORD_SOURCE_SUBDIR_FILE:
                (void) write_file(subdir, name, value, value_size);
                break;

        case RECORD_RECEIVED_FILE:
                (void) write_file(received, name, value, value_size);
                break;

        case RECORD_RECEIVED_ENCRYPTED:
                (void) write_file(received_encrypted, name, value, value_size);
                break;

        case RECORD_LOAD_PATH: {
                _cleanup_free_ char *p = ASSERT_NOT_NULL(path_join(source, name));

                (void) exec_context_put_load_credential(ec, id, p, /* encrypted= */ flag);
                break;
        }

        case RECORD_LOAD_DIR:
                (void) exec_context_put_load_credential(
                                ec, id, flag ? subdir : source, /* encrypted= */ false);
                break;

        case RECORD_LOAD_NAME:
                (void) exec_context_put_load_credential(ec, id, name, /* encrypted= */ flag);
                break;

        case RECORD_SET:
                /* Takes ownership of the data */
                (void) exec_context_put_set_credential(
                                ec, id, ASSERT_NOT_NULL(memdup_suffix0(value, value_size)), value_size,
                                /* encrypted= */ flag);
                break;

        case RECORD_IMPORT: {
                _cleanup_free_ char *rename = NULL;

                if (value_size > 0)
                        rename = ASSERT_NOT_NULL(sanitize_name(value, value_size, /* allow_glob= */ false));

                /* Validated like config_parse_import_credential() and the D-Bus setter do, which
                 * load_credential_glob() relies on (only a trailing '*' is allowed) */
                if (!credential_glob_valid(name) || (rename && !credential_name_valid(rename)))
                        break;

                (void) exec_context_put_import_credential(ec, name, rename);
                break;
        }

        case RECORD_MACHINE_SET: {
                _cleanup_free_ char *s = ASSERT_NOT_NULL(memdup_suffix0(value, value_size));

                (void) machine_credential_set(mc, s);
                break;
        }

        case RECORD_MACHINE_LOAD: {
                _cleanup_free_ char *s = NULL;

                /* Either the name of a received credential, or a path below the source directory */
                if (flag)
                        s = ASSERT_NOT_NULL(strjoin(id, ":", source, "/", name));
                else
                        s = ASSERT_NOT_NULL(strjoin(id, ":", name));

                (void) machine_credential_load(mc, s);
                break;
        }

        case RECORD_READ_WITH_DECRYPTION: {
                _cleanup_(erase_and_freep) void *buf = NULL;
                size_t sz;

                /* Unprivileged callers ask systemd-creds via Varlink instead */
                if (geteuid() == 0)
                        (void) read_credential_with_decryption(name, &buf, flag ? &sz : NULL);
                break;
        }

        default:
                assert_not_reached();
        }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(exec_context_done) ExecContext ec = {};
        _cleanup_(cgroup_context_done) CGroupContext cc = {};
        _cleanup_(machine_credential_context_done) MachineCredentialContext mc = {};
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_free_ char *source = NULL, *subdir = NULL, *received = NULL, *received_encrypted = NULL,
                *secret = NULL, *tpm = NULL, *runtime_prefix = NULL;
        uid_t uid;

        if (outside_size_range(size, 1, 256 * 1024))
                return 0;

        fuzz_forbid_network();
        forbid_mounts();
        fuzz_setup_logging();

        ASSERT_OK(mkdtemp_malloc("/tmp/fuzz-exec-credential-XXXXXX", &tmp));
        source = ASSERT_NOT_NULL(path_join(tmp, "source"));
        subdir = ASSERT_NOT_NULL(path_join(tmp, "source/sub"));
        received = ASSERT_NOT_NULL(path_join(tmp, "received"));
        received_encrypted = ASSERT_NOT_NULL(path_join(tmp, "received.encrypted"));
        secret = ASSERT_NOT_NULL(path_join(tmp, "credential.secret"));
        tpm = ASSERT_NOT_NULL(path_join(tmp, "no-tpm"));
        runtime_prefix = ASSERT_NOT_NULL(path_join(tmp, "run"));
        /* /run/systemd/ always exists, exec_setup_credentials() creates its workspace below it */
        ASSERT_OK(mkdir_p(strjoina(runtime_prefix, "/systemd"), 0755));

        /* Never use the host's credential secret, TPM or passed credentials */
        ASSERT_OK_ERRNO(setenv("CREDENTIALS_DIRECTORY", received, /* overwrite= */ true));
        ASSERT_OK_ERRNO(setenv("ENCRYPTED_CREDENTIALS_DIRECTORY", received_encrypted,
                               /* overwrite= */ true));
        ASSERT_OK_ERRNO(setenv("SYSTEMD_CREDENTIAL_SECRET", secret, /* overwrite= */ true));
        ASSERT_OK_ERRNO(setenv("SYSTEMD_TPM2_DEVICE", strjoina("device:", tpm), /* overwrite= */ true));

        exec_context_init(&ec);
        cgroup_context_init(&cc);

        /* Also cover the ACL/ownership logic for services with their own user */
        uid = FLAGS_SET(data[0], 1) ? 1000 : getuid();
        data++;
        size--;

        for (unsigned n = 0; n < MAX_RECORDS && size >= 4; n++) {
                _cleanup_free_ char *name = NULL;
                const uint8_t *name_data, *value;
                size_t name_size, value_size;
                RecordType type;
                bool flag;

                type = (data[0] & ~RECORD_FLAG) % _RECORD_TYPE_MAX;
                flag = FLAGS_SET(data[0], RECORD_FLAG);
                name_size = MIN((size_t) data[1], size - 2);
                name_data = data + 2;
                size -= 2 + name_size;
                if (size < 2)
                        break;

                value_size = MIN((size_t) unaligned_read_le16(name_data + name_size), size - 2);
                value = name_data + name_size + 2;
                data = value + value_size;
                size -= 2 + value_size;

                name = ASSERT_NOT_NULL(sanitize_name(name_data, name_size,
                                                     /* allow_glob= */ type == RECORD_IMPORT));

                apply_record(type, flag, name, value, value_size, &ec, &mc,
                             source, subdir, received, received_encrypted);
        }

        char *prefix[_EXEC_DIRECTORY_TYPE_MAX] = {
                [EXEC_DIRECTORY_RUNTIME] = runtime_prefix,
        };
        ExecParameters params = {
                .runtime_scope = RUNTIME_SCOPE_SYSTEM,
                .flags = EXEC_SETUP_CREDENTIALS_FRESH,
                .unit_id = (char*) "fuzz-credential.service",
                .prefix = prefix,
                .received_credentials_directory = received,
                .received_encrypted_credentials_directory = received_encrypted,
        };

        (void) exec_setup_credentials(&ec, &cc, &params, uid, getgid());

        return 0;
}
