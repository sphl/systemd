/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Fuzz target for the server side of an sd-bus connection, i.e. what every sd-bus service that accepts
 * direct connections (PID 1's private bus, systemd-stdio-bridge) exposes to its peers: the SASL
 * authentication (bus_socket_auth_verify_server() with EXTERNAL/ANONYMOUS/DATA/NEGOTIATE_UNIX_FD/BEGIN),
 * the socket reader (bus_socket_read_message(), bus_socket_make_message(), bus_process_cmsg() for passed
 * fds and credentials), message parsing, and the dispatch of incoming method calls through bus-objects.c:
 * method lookup and signature checks, property Get/Set/GetAll, Introspect, GetManagedObjects, fallback
 * vtables, node enumerators, object managers, filters and matches.
 *
 * The bus is started as server on one end of an AF_UNIX socketpair. The input is what the client writes
 * into the other end, in chunks that may carry file descriptors (SCM_RIGHTS) and explicit
 * SCM_CREDENTIALS. The server's replies are read and discarded.
 *
 * Input:
 *   byte 0: server settings: bit 0 allow anonymous authentication, bit 1 accept fds, bit 2 negotiate
 *           credentials, bit 3 trusted connection, bit 4 the client shuts its end down after the last chunk
 *   then up to 64 chunks: [length, 2 bytes LE] [ancillary data flags] [data], where the flags are bits 0-1
 *           the number of fds to pass, bit 2 send explicit SCM_CREDENTIALS */

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-id128.h"

#include "bus-internal.h"
#include "fd-util.h"
#include "fs-util.h"
#include "fuzz.h"
#include "fuzz-network.h"
#include "iovec-util.h"
#include "memfd-util.h"
#include "memstream-util.h"
#include "path-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "unaligned.h"

#define MAX_ITERATIONS 2048
#define MAX_CHUNKS 64
#define MAX_FDS 4

typedef struct Context {
        uint8_t y;
        int b;
        int16_t n;
        uint16_t q;
        int32_t i;
        uint32_t u;
        int64_t x;
        uint64_t t;
        double d;
        char *s;
        char *o;
        char *g;
        char **as;
        sd_bus_message *stash[3]; /* values of the "Variant", "Dict" and "Complex" properties */
        unsigned calls;
} Context;

static void context_done(Context *c) {
        free(c->s);
        free(c->o);
        free(c->g);
        strv_free(c->as);
        FOREACH_ELEMENT(m, c->stash)
                sd_bus_message_unref(*m);
}

/* Dumps the message like busctl monitor does, into memory */
static void dump_message(sd_bus_message *m) {
        _cleanup_(memstream_done) MemStream ms = {};
        FILE *f = memstream_init(&ms);

        if (!f)
                return;

        (void) sd_bus_message_dump(m, f, SD_BUS_MESSAGE_DUMP_WITH_HEADER);
        (void) sd_bus_message_rewind(m, /* complete= */ true);
}

static int method_echo(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int r;

        /* Copies whatever arguments we got into the reply: sd_bus_message_copy() walks the whole body. */
        r = sd_bus_message_new_method_return(m, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_copy(reply, m, /* all= */ true);
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

static int method_skip(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        int r;

        /* Skips over the arguments, then reads them again by type */
        r = sd_bus_message_skip(m, /* types= */ NULL);
        if (r < 0)
                return r;

        r = sd_bus_message_rewind(m, /* complete= */ true);
        if (r < 0)
                return r;

        dump_message(m);

        return sd_bus_reply_method_return(m, "u", UINT32_C(0));
}

/* Reads an "a{sv}" dictionary entry by entry, as daemons parse their options */
static int read_options(sd_bus_message *m) {
        int r;

        r = sd_bus_message_enter_container(m, 'a', "{sv}");
        if (r < 0)
                return r;
        while ((r = sd_bus_message_enter_container(m, 'e', "sv")) > 0) {
                const char *k, *contents;
                char type;

                r = sd_bus_message_read(m, "s", &k);
                if (r < 0)
                        return r;
                r = sd_bus_message_peek_type(m, &type, &contents);
                if (r < 0)
                        return r;
                r = sd_bus_message_skip(m, "v");
                if (r < 0)
                        return r;
                r = sd_bus_message_exit_container(m);
                if (r < 0)
                        return r;
        }
        if (r < 0)
                return r;

        return sd_bus_message_exit_container(m);
}

static int method_typed(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        _cleanup_strv_free_ char **l = NULL;
        const char *s;
        int r;

        /* "sa{sv}as": a typical systemd-style call */
        r = sd_bus_message_read(m, "s", &s);
        if (r < 0)
                return r;

        r = read_options(m);
        if (r < 0)
                return r;

        r = sd_bus_message_read_strv(m, &l);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(m, "su", s, (uint32_t) strv_length(l));
}

static int method_read(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        const char *s, *o, *g;
        uint8_t y;
        int b, h;
        int16_t n;
        uint16_t q;
        int32_t i;
        uint32_t u;
        int64_t x;
        uint64_t t;
        double d;
        int r;

        /* All basic types in one sd_bus_message_read(), as daemons read their arguments */
        r = sd_bus_message_read(m, "ybnqiuxtdsogh", &y, &b, &n, &q, &i, &u, &x, &t, &d, &s, &o, &g, &h);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(m, "u", u);
}

static int method_read_arrays(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        _cleanup_strv_free_ char **l = NULL;
        int r;

        /* Arrays of fixed-size types are read in place (sd_bus_message_read_array()) */
        FOREACH_STRING(type, "y", "n", "q", "i", "u", "x", "t", "d") {
                const void *p;
                size_t sz;

                r = sd_bus_message_read_array(m, type[0], &p, &sz);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_read_strv(m, &l);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(m, "u", (uint32_t) strv_length(l));
}

static int method_read_struct_array(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        const char *s1, *s2;
        uint32_t u1, u2;
        int r;

        /* sd_bus_message_read() with an element count for the array, then a dictionary */
        r = sd_bus_message_read(m, "a(su)", 2, &s1, &u1, &s2, &u2);
        if (r < 0)
                return r;

        r = read_options(m);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(m, "u", u1 + u2);
}

static int method_fds(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        int fd, r;

        r = sd_bus_message_read(m, "h", &fd);
        if (r < 0)
                return r;

        /* Send it straight back */
        return sd_bus_reply_method_return(m, "h", fd);
}

static int method_error(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        const char *name, *message;
        int r;

        r = sd_bus_message_read(m, "ss", &name, &message);
        if (r < 0)
                return r;

        if (!error_name_is_valid(name))
                return sd_bus_reply_method_errnof(m, EINVAL, "Invalid error name: %s", name);

        return sd_bus_reply_method_errorf(m, name, "%s", message);
}

static int method_emit(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        sd_bus *bus = sd_bus_message_get_bus(m);
        uint32_t what;
        int r;

        r = sd_bus_message_read(m, "u", &what);
        if (r < 0)
                return r;

        switch (what % 7) {
        case 0:
                r = sd_bus_emit_properties_changed(bus, "/org/example/fuzz", "org.example.Fuzz",
                                                   "String", "Byte", "Strv", NULL);
                break;
        case 1:
                r = sd_bus_emit_properties_changed_strv(bus, "/org/example/fuzz/fallback/x",
                                                        "org.example.Fallback", /* names= */ NULL);
                break;
        case 2:
                r = sd_bus_emit_interfaces_added(bus, "/org/example/fuzz", "org.example.Fuzz", NULL);
                break;
        case 3:
                r = sd_bus_emit_interfaces_removed(bus, "/org/example/fuzz/fallback/y",
                                                   "org.example.Fallback", NULL);
                break;
        case 4:
                r = sd_bus_emit_object_added(bus, "/org/example/fuzz/fallback/z");
                break;
        case 5:
                r = sd_bus_emit_object_removed(bus, "/org/example/fuzz");
                break;
        default:
                r = sd_bus_emit_signal(bus, "/org/example/fuzz", "org.example.Fuzz", "Signal",
                                       "su", "hello", what);
        }
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(m, /* types= */ NULL);
}

static int method_creds(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        uid_t uid = UID_INVALID;
        int r;

        r = sd_bus_query_sender_creds(m,
                                      SD_BUS_CREDS_PID|SD_BUS_CREDS_EUID|SD_BUS_CREDS_UID|SD_BUS_CREDS_GID|
                                      SD_BUS_CREDS_SUPPLEMENTARY_GIDS|SD_BUS_CREDS_SELINUX_CONTEXT|
                                      SD_BUS_CREDS_UNIQUE_NAME,
                                      &creds);
        if (r < 0)
                return r;
        (void) sd_bus_creds_get_euid(creds, &uid);

        r = sd_bus_query_sender_privilege(m, /* capability= */ -1);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(m, "ub", (uint32_t) uid, r > 0);
}

static int property_get_stash(sd_bus *bus, const char *path, const char *interface, const char *property,
                              sd_bus_message *reply, void *userdata, sd_bus_error *reterr_error) {
        sd_bus_message **stash = ASSERT_PTR(userdata);
        int r;

        if (!*stash) {
                if (streq(property, "Variant"))
                        return sd_bus_message_append(reply, "v", "s", "");
                return sd_bus_message_append(reply, streq(property, "Dict") ? "a{sv}" : "a(sa(iv)ay)", 0);
        }

        r = sd_bus_message_rewind(*stash, /* complete= */ true);
        if (r < 0)
                return r;

        return sd_bus_message_copy(reply, *stash, /* all= */ false);
}

static int property_set_stash(sd_bus *bus, const char *path, const char *interface, const char *property,
                              sd_bus_message *value, void *userdata, sd_bus_error *reterr_error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *copy = NULL;
        sd_bus_message **stash = ASSERT_PTR(userdata);
        int r;

        /* The value is kept in a sealed message of its own, which property_get_stash() copies from */
        r = sd_bus_message_new_signal(bus, &copy, "/org/example/fuzz", "org.example.Fuzz", "Stash");
        if (r < 0)
                return r;

        r = sd_bus_message_copy(copy, value, /* all= */ false);
        if (r < 0)
                return r;

        r = sd_bus_message_seal(copy, /* cookie= */ 1, /* timeout_usec= */ 0);
        if (r < 0)
                return r;

        sd_bus_message_unref(*stash);
        *stash = TAKE_PTR(copy);
        return 1;
}

static int property_get_fail(sd_bus *bus, const char *path, const char *interface, const char *property,
                             sd_bus_message *reply, void *userdata, sd_bus_error *reterr_error) {
        Context *c = ASSERT_PTR(userdata);

        /* Fails once the Boolean property was set, which makes GetAll() and GetManagedObjects() fail too */
        if (c->b)
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_ACCESS_DENIED, "Nope.");

        return sd_bus_message_append(reply, "s", "fine");
}

static int property_get_fallback(sd_bus *bus, const char *path, const char *interface, const char *property,
                                 sd_bus_message *reply, void *userdata, sd_bus_error *reterr_error) {
        return sd_bus_message_append(reply, "s", path);
}

static const sd_bus_vtable fuzz_vtable[] = {
        SD_BUS_VTABLE_START(0),
        /* Method signatures are checked strictly, so these take variants, which can carry anything */
        SD_BUS_METHOD("Echo", "av", "av", method_echo, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("EchoComplex", "a(sa(iv)ay)a{sv}", "a(sa(iv)ay)a{sv}", method_echo,
                      SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Skip", "v", "u", method_skip, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SkipMany", "yvvvt", "u", method_skip, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("Typed",
                                SD_BUS_ARGS("s", name, "a{sv}", options, "as", list),
                                SD_BUS_RESULT("s", name, "u", n),
                                method_typed,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Fds", "h", "h", method_fds, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Read", "ybnqiuxtdsogh", "u", method_read, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ReadArrays", "ayanaqaiauaxatadas", "u", method_read_arrays,
                      SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ReadStructArray", "a(su)a{sv}", "u", method_read_struct_array,
                      SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Error", "ss", NULL, method_error,
                      SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_METHOD_NO_REPLY),
        SD_BUS_METHOD("Emit", "u", NULL, method_emit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Creds", NULL, "ub", method_creds, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Privileged", "av", "av", method_echo, 0),
        SD_BUS_METHOD("Deprecated", "s", "s", method_echo,
                      SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_DEPRECATED),
        SD_BUS_METHOD("Hidden", "ay", "ay", method_echo, SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_HIDDEN),
        SD_BUS_METHOD("NoArgs", NULL, NULL, method_echo, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_SIGNAL("Signal", "su", 0),
        SD_BUS_SIGNAL_WITH_ARGS("Stash", SD_BUS_ARGS("v", value), 0),
        SD_BUS_WRITABLE_PROPERTY("Byte", "y", NULL, NULL, offsetof(Context, y),
                                 SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_WRITABLE_PROPERTY("Boolean", "b", NULL, NULL, offsetof(Context, b),
                                 SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        SD_BUS_WRITABLE_PROPERTY("Int16", "n", NULL, NULL, offsetof(Context, n),
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_WRITABLE_PROPERTY("UInt16", "q", NULL, NULL, offsetof(Context, q),
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_WRITABLE_PROPERTY("Int32", "i", NULL, NULL, offsetof(Context, i),
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_WRITABLE_PROPERTY("UInt32", "u", NULL, NULL, offsetof(Context, u),
                                 0),
        SD_BUS_WRITABLE_PROPERTY("Int64", "x", NULL, NULL, offsetof(Context, x),
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_WRITABLE_PROPERTY("UInt64", "t", NULL, NULL, offsetof(Context, t),
                                 SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_PROPERTY_EXPLICIT),
        SD_BUS_WRITABLE_PROPERTY("Double", "d", NULL, NULL, offsetof(Context, d),
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_WRITABLE_PROPERTY("String", "s", NULL, NULL, offsetof(Context, s),
                                 SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_WRITABLE_PROPERTY("ObjectPath", "o", NULL, NULL, offsetof(Context, o),
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_WRITABLE_PROPERTY("Signature", "g", NULL, NULL, offsetof(Context, g),
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_PROPERTY("Strv", "as", NULL, offsetof(Context, as), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_WRITABLE_PROPERTY("Variant", "v", property_get_stash, property_set_stash,
                                 offsetof(Context, stash[0]),
                                 SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_WRITABLE_PROPERTY("Dict", "a{sv}", property_get_stash, property_set_stash,
                                 offsetof(Context, stash[1]),
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_WRITABLE_PROPERTY("Complex", "a(sa(iv)ay)", property_get_stash, property_set_stash,
                                 offsetof(Context, stash[2]),
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_PROPERTY("Const", "s", NULL, offsetof(Context, s), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Failing", "s", property_get_fail, 0, SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        SD_BUS_VTABLE_END
};

static const sd_bus_vtable fallback_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("Echo", "av", "av", method_echo, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_PROPERTY("Path", "s", property_get_fallback, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Path2", "s", property_get_fallback, 0, SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        SD_BUS_VTABLE_END
};

static const sd_bus_vtable sensitive_vtable[] = {
        SD_BUS_VTABLE_START(SD_BUS_VTABLE_SENSITIVE),
        SD_BUS_METHOD("Echo", "s", "s", method_echo, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_PROPERTY("Secret", "s", property_get_fallback, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_VTABLE_END
};

static int fallback_find(
                sd_bus *bus,
                const char *path,
                const char *interface,
                void *userdata,
                void **found,
                sd_bus_error *reterr_error) {

        /* Only some children exist */
        if (!path_startswith(path, "/org/example/fuzz/fallback/") || endswith(path, "/missing"))
                return 0;

        *found = userdata;
        return 1;
}

static int enumerator(
                sd_bus *bus,
                const char *path,
                void *userdata,
                char ***nodes,
                sd_bus_error *reterr_error) {

        if (object_path_startswith("/org/example/fuzz/fallback", path)) {
                *nodes = strv_new("/org/example/fuzz/fallback/x",
                                  "/org/example/fuzz/fallback/y",
                                  "/org/example/fuzz/fallback/missing");
                if (!*nodes)
                        return -ENOMEM;
        }
        return 1;
}

static int object_callback(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        /* Handles everything sent to the object, unless a vtable handles it first */
        if (!sd_bus_message_is_method_call(m, /* interface= */ NULL, "Raw"))
                return 0;

        return method_echo(m, userdata, reterr_error);
}

static int filter(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        Context *c = ASSERT_PTR(userdata);

        c->calls++;
        return 0;
}

static int match_callback(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        dump_message(m);
        return 0;
}

static void drain(int fd) {
        char buf[4096];

        while (recv(fd, buf, sizeof(buf), MSG_DONTWAIT) > 0)
                ;
}

static void send_chunk(int fd, const uint8_t *data, size_t size, uint8_t flags) {
        int fds[MAX_FDS];
        size_t n_fds = 0;

        /* bits 0-1: number of fds, bit 2: explicit SCM_CREDENTIALS */
        for (size_t i = 0; i < (flags & 3U); i++) {
                int k = (i % 2 == 0) ? xopenat(AT_FDCWD, "/dev/null", O_RDWR) : memfd_new("fuzz-bus");
                if (k >= 0)
                        fds[n_fds++] = k;
        }

        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int) * MAX_FDS)) control = {};
        struct iovec iov = IOVEC_MAKE((void*) data, size);
        struct msghdr mh = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&mh);
        size_t controllen = 0;

        if (flags & 4) {
                controllen += CMSG_SPACE(sizeof(struct ucred));
                cmsg->cmsg_level = SOL_SOCKET;
                cmsg->cmsg_type = SCM_CREDENTIALS;
                cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
                *CMSG_TYPED_DATA(cmsg, struct ucred) = (struct ucred) {
                        .pid = getpid(),
                        .uid = getuid(),
                        .gid = getgid(),
                };
                cmsg = CMSG_NXTHDR(&mh, cmsg);
        }

        if (n_fds > 0) {
                controllen += CMSG_SPACE(sizeof(int) * n_fds);
                cmsg->cmsg_level = SOL_SOCKET;
                cmsg->cmsg_type = SCM_RIGHTS;
                cmsg->cmsg_len = CMSG_LEN(sizeof(int) * n_fds);
                memcpy(CMSG_TYPED_DATA(cmsg, int), fds, sizeof(int) * n_fds);
        }

        mh.msg_controllen = controllen;
        if (controllen == 0)
                mh.msg_control = NULL;

        (void) sendmsg(fd, &mh, MSG_DONTWAIT|MSG_NOSIGNAL);
        close_many(fds, n_fds);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(context_done) Context c = {}; /* must outlive the bus, whose callbacks reference it */
        _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        sd_id128_t id = SD_ID128_MAKE(fd,dd,a5,b3,c4,4f,4f,2b,9b,5e,cc,e7,21,19,31,9d);
        bool closed = false;
        uint8_t flags;

        if (outside_size_range(size, 1, 64 * 1024))
                return 0;

        fuzz_forbid_network();
        fuzz_setup_logging();

        flags = data[0];
        data++;
        size--;

        /* The automatic getters need valid initial values */
        c.s = ASSERT_NOT_NULL(strdup("initial"));
        c.o = ASSERT_NOT_NULL(strdup("/"));
        c.g = ASSERT_NOT_NULL(strdup(""));
        c.as = ASSERT_NOT_NULL(strv_new("a", "b"));

        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0, pair));

        ASSERT_OK(sd_bus_new(&bus));
        ASSERT_OK(sd_bus_set_fd(bus, pair[0], pair[0]));
        TAKE_FD(pair[0]);
        ASSERT_OK(sd_bus_set_server(bus, /* b= */ true, id));
        ASSERT_OK(sd_bus_set_anonymous(bus, FLAGS_SET(flags, 1 << 0)));
        ASSERT_OK(sd_bus_negotiate_fds(bus, FLAGS_SET(flags, 1 << 1)));
        ASSERT_OK(sd_bus_negotiate_creds(bus, FLAGS_SET(flags, 1 << 2),
                                         SD_BUS_CREDS_PID|SD_BUS_CREDS_UID|SD_BUS_CREDS_EUID|
                                         SD_BUS_CREDS_GID));
        ASSERT_OK(sd_bus_set_trusted(bus, FLAGS_SET(flags, 1 << 3)));

        ASSERT_OK(sd_bus_add_object_vtable(bus, /* ret_slot= */ NULL, "/org/example/fuzz",
                                           "org.example.Fuzz", fuzz_vtable, &c));
        ASSERT_OK(sd_bus_add_object_vtable(bus, /* ret_slot= */ NULL, "/org/example/fuzz",
                                           "org.example.Sensitive", sensitive_vtable, &c));
        ASSERT_OK(sd_bus_add_fallback_vtable(bus, /* ret_slot= */ NULL, "/org/example/fuzz/fallback",
                                             "org.example.Fallback", fallback_vtable, fallback_find, &c));
        ASSERT_OK(sd_bus_add_node_enumerator(bus, /* ret_slot= */ NULL, "/org/example/fuzz/fallback",
                                             enumerator, &c));
        ASSERT_OK(sd_bus_add_object_manager(bus, /* ret_slot= */ NULL, "/org/example"));
        ASSERT_OK(sd_bus_add_object_manager(bus, /* ret_slot= */ NULL, "/org/example/fuzz/fallback"));
        ASSERT_OK(sd_bus_add_object(bus, /* ret_slot= */ NULL, "/org/example/fuzz", object_callback, &c));
        ASSERT_OK(sd_bus_add_fallback(bus, /* ret_slot= */ NULL, "/org/example/raw", object_callback, &c));
        ASSERT_OK(sd_bus_add_filter(bus, /* ret_slot= */ NULL, filter, &c));
        ASSERT_OK(sd_bus_add_match(bus, /* ret_slot= */ NULL,
                                   "type='signal',interface='org.example.Fuzz',arg0='hello'",
                                   match_callback, &c));
        ASSERT_OK(sd_bus_add_match(bus, /* ret_slot= */ NULL,
                                   "type='method_call',path_namespace='/org/example',arg0path='/foo/'",
                                   match_callback, &c));

        ASSERT_OK(sd_bus_start(bus));

        for (unsigned i = 0, n_chunks = 0; i < MAX_ITERATIONS; i++) {
                bool more = true;
                int r;

                if (size >= 3 && n_chunks < MAX_CHUNKS) {
                        size_t len = MIN((size_t) unaligned_read_le16(data), size - 3);

                        send_chunk(pair[1], data + 3, len, data[2]);
                        data += 3 + len;
                        size -= 3 + len;
                        n_chunks++;
                } else if (FLAGS_SET(flags, 1 << 4) && !closed) {
                        (void) shutdown(pair[1], SHUT_WR);
                        closed = true;
                } else
                        more = false;

                /* As services do: sd-bus itself replies to method calls that nobody handled */
                r = sd_bus_process(bus, /* ret= */ NULL);
                drain(pair[1]);
                if (r < 0)
                        break;
                if (r == 0 && !more)
                        break;
        }

        return 0;
}
