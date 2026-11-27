/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* An in-memory fake of the UEFI firmware for the sd-boot/sd-stub fuzzers, see efi-fuzz.h. This is regular
 * userspace code, linked against sd-boot code that is built in EFI mode. All protocol functions use the EFI
 * calling convention. */

#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "efi-fuzz.h"
#include "fuzz.h"
#include "fuzz-network.h"
#include "proto/block-io.h"
#include "proto/device-path.h"
#include "proto/disk-io.h"
#include "proto/dt-fixup.h" /* IWYU pragma: keep */
#include "proto/edid-discovered.h"
#include "proto/graphics-output.h"
#include "proto/load-file.h"
#include "proto/loaded-image.h"
#include "proto/rng.h"
#include "proto/simple-text-io.h"
#include "proto/tcg.h"
#include "smbios.h"
#include "vmm.h"

/* Provided by the sanitizer runtimes, if one is linked in */
void __sanitizer_print_stack_trace(void) __attribute__((weak));

/* Replaces sd-boot's beep() (linked with -Wl,--wrap=beep), which does port I/O: not allowed in a normal
 * process */
void __wrap_beep(unsigned beep_count);
void __wrap_beep(unsigned beep_count) {
}

#define LOADER_VENDOR_GUID \
        GUID_DEF(0x4a67b082, 0x0a4c, 0x41cf, 0xb6, 0xc7, 0x44, 0x0b, 0x29, 0xbb, 0x8c, 0x4f)
#define SYSTEMD_VENDOR_GUID \
        GUID_DEF(0x8cf2644b, 0x4b0b, 0x428f, 0x93, 0x87, 0x6d, 0x87, 0x60, 0x50, 0xdc, 0x67)
#define SMBIOS_TABLE_GUID \
        GUID_DEF(0xeb9d2d31, 0x2d88, 0x11d3, 0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d)
#define SMBIOS3_TABLE_GUID \
        GUID_DEF(0xf2fd1544, 0x9794, 0x4a2c, 0x99, 0x2e, 0xe5, 0xbb, 0xcf, 0x20, 0xe3, 0x94)
#define ESP_PARTITION_GUID \
        GUID_DEF(0x0e6df1c5, 0x2e4f, 0x4a4b, 0x9c, 0x1c, 0x1d, 0x2d, 0x7a, 0x8f, 0x9e, 0x11)
#define ESP_TYPE_GUID \
        GUID_DEF(0xc12a7328, 0xf81f, 0x11d2, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b)
#define XBOOTLDR_TYPE_GUID \
        GUID_DEF(0xbc13c2ff, 0x59e6, 0x4262, 0xa3, 0x52, 0xb2, 0x75, 0xfd, 0x6f, 0x71, 0x72)
#define FWUPDATE_VENDOR_GUID \
        GUID_DEF(0x0abba7dc, 0xe516, 0x4167, 0xbb, 0xf5, 0x4d, 0x9d, 0x1c, 0x73, 0x94, 0x16)

/* Limits that keep the fake firmware fast and within the fuzzer's memory budget. */
/* Allocations of at least this size are backed by memory that is only committed when written to, so that
 * sd-boot can allocate as much as a real machine would let it, as long as it doesn't touch all of it. */
#define LAZY_ALLOCATION_MIN (64U * 1024U * 1024U)
#define ALLOCATION_MAX ((size_t) MIN((uint64_t) SIZE_MAX / 4, UINT64_C(64) * 1024U * 1024U * 1024U))
#define FILE_SIZE_MAX (16U * 1024U * 1024U)
#define IMAGE_SIZE_MAX (16U * 1024U * 1024U)
#define NODES_MAX 1024U
#define VARIABLES_MAX 256U
#define VARIABLE_SIZE_MAX (64U * 1024U)
#define PROTOCOLS_PER_HANDLE_MAX 16U
#define CONFIG_TABLES_MAX 32U
#define FILE_NAME_MAX 255U
#define DEVICE_PATH_SIZE_MAX (64U * 1024U)
#define DISK_SIZE_MAX (1024U * 1024U)
#define PARTITIONS_MAX 128U
#define POOL_BUCKETS 4096U
#define KEYS_MAX 4096U
/* console_key_read() waits forever if asked to, by rearming its timer. Give up eventually. */
#define TIMER_FIRES_MAX 64U

/* sd-boot only defines these when it is built with its main function (boot.c, stub.c). */
EFI_SYSTEM_TABLE *ST __attribute__((weak));
EFI_BOOT_SERVICES *BS __attribute__((weak));
EFI_RUNTIME_SERVICES *RT __attribute__((weak));

typedef struct Protocol {
        EFI_GUID guid;
        void *interface;
} Protocol;

typedef struct Handle {
        Protocol protocols[PROTOCOLS_PER_HANDLE_MAX];
        size_t n_protocols;
        struct Handle *next;
} Handle;

typedef struct Node {
        char16_t *name;
        bool directory;
        bool read_only;
        uint8_t *data;
        size_t size;
        struct Node *parent;
        struct Node *children; /* In creation order, like on FAT */
        struct Node *next;
} Node;

typedef struct File {
        EFI_FILE file; /* Must be first */
        Node *root;
        Node *node;
        uint64_t position; /* Byte offset for files, entry index for directories */
        bool writable;
        struct File *next;
} File;

typedef struct FileSystem {
        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL protocol; /* Must be first */
        Node *root;
} FileSystem;

typedef struct BlockIo {
        EFI_BLOCK_IO_PROTOCOL protocol; /* Must be first */
        typeof(*((EFI_BLOCK_IO_PROTOCOL*) NULL)->Media) media;
} BlockIo;

typedef struct Variable {
        EFI_GUID vendor;
        char16_t *name;
        uint32_t attributes;
        void *data;
        size_t size;
        struct Variable *next;
} Variable;

typedef struct PageAllocation {
        uint8_t *base;
        size_t n_pages;
        size_t n_freed;
        bool lazy;
        struct PageAllocation *next;
} PageAllocation;

typedef struct Allocation {
        void *p;
        struct Allocation *next;
} Allocation;

typedef struct Mapping {
        void *p;
        size_t size;
        struct Mapping *next;
} Mapping;

typedef struct LoadedImage {
        EFI_LOADED_IMAGE_PROTOCOL protocol; /* Must be first */
        Handle *handle;
        uint8_t *memory;
        struct LoadedImage *next;
} LoadedImage;

typedef struct Event {
        uint32_t type;
        struct Event *next;
} Event;

/* ConIn's WaitForKey event */
static Event key_event;

static struct {
        bool initialized;

        EFI_SYSTEM_TABLE system_table;
        struct {
                EFI_GUID VendorGuid;
                void *VendorTable;
        } config_tables[CONFIG_TABLES_MAX];

        Handle *handles;
        Handle *esp;
        FileSystem esp_fs, xbootldr_fs;
        Node *deleted;
        size_t n_nodes;
        File *files;
        bool esp_read_only;

        Variable *variables;
        size_t n_variables;

        PageAllocation *pages;
        Allocation *pool[POOL_BUCKETS]; /* All pool allocations, sd-boot doesn't free all of them */
        Mapping *mappings;        /* alloc_low() */
        Mapping *lazy;            /* Large pool and page allocations */

        uint8_t *rng_data;
        size_t rng_size, rng_pos;
        EFI_RNG_PROTOCOL rng;
        EFI_EDID_DISCOVERED_PROTOCOL edid;
        uint8_t *boot_url;
        size_t boot_url_size;

        uint8_t *disk;
        size_t disk_size;
        EFI_LBA disk_last_block;
        BlockIo disk_block_io, esp_block_io;
        EFI_DISK_IO_PROTOCOL disk_io;
        BlockIo *partitions;
        size_t n_partitions;

        EFI_GRAPHICS_OUTPUT_PROTOCOL gop;
        struct {
                uint32_t MaxMode;
                uint32_t Mode;
                EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *Info;
                size_t SizeOfInfo;
                EFI_PHYSICAL_ADDRESS FrameBufferBase;
                size_t FrameBufferSize;
        } gop_mode;
        EFI_GRAPHICS_OUTPUT_MODE_INFORMATION gop_info;
        EFI_GRAPHICS_OUTPUT_BLT_PIXEL *framebuffer;

        EFI_TCG2_PROTOCOL tcg2;

        EFI_LOAD_FILE2_PROTOCOL initrd_load_file;
        uint8_t *initrd;
        size_t initrd_size;

        struct LoadedImage *images;
        bool load_images;

        struct Event *events;
        EFI_INPUT_KEY *keys;
        size_t n_keys, keys_pos;
        unsigned timer_fires;

        jmp_buf *reset_jmp;

        uint64_t monotonic_count;
        bool confidential_vm;
} fw;

/* EFI variadic functions use the Microsoft calling convention on x86-64. */
#if defined(__x86_64__)
#  define efi_va_list __builtin_ms_va_list
#  define efi_va_start __builtin_ms_va_start
#  define efi_va_end __builtin_ms_va_end
#else
#  define efi_va_list va_list
#  define efi_va_start va_start
#  define efi_va_end va_end
#endif

/* The last line written to the console, e.g. the assertion message of efi_assert() */
static char console_line[256], console_last_line[256];
static size_t console_line_len;

_noreturn_ static void fail(const char *message) {
        console_line[console_line_len] = 0;
        fprintf(stderr, "efi-fuzz-firmware: %s, aborting. Last console output: %s%s\n",
                message, console_last_line, console_line);
        /* The stack trace of the abort() is cut short at the frames of sd-boot's efi_assert()/freeze(). */
        if (__sanitizer_print_stack_trace)
                __sanitizer_print_stack_trace();
        abort();
}

/* The sd-boot sources built as userspace code (efi-string.c, this file) and src/fuzz/fuzz-network.c use the
 * userspace assertion macros, but libsystemd-shared is not linked in. */
void log_assert_failed(const char *text, const char *file, int line, const char *func) {
        fprintf(stderr, "Assertion '%s' failed at %s:%i, function %s(). Aborting.\n",
                text, file, line, func);
        abort();
}

void log_assert_failed_unreachable(const char *file, int line, const char *func) {
        fprintf(stderr, "Code should not be reached at %s:%i, function %s(). Aborting.\n", file, line, func);
        abort();
}

void log_assert_failed_return(const char *text, const char *file, int line, const char *func) {
        /* As in libsystemd-shared, a failed assert_return() is not fatal by default */
}

bool efi_fuzz_outside_size_range(size_t size, size_t lower, size_t upper) {
        return outside_size_range(size, lower, upper);
}

void efi_fuzz_forbid_network(void) {
        fuzz_forbid_network();
}

static void* xmalloc_fw(size_t size) {
        void *p = malloc(size ?: 1);
        if (!p)
                fail("Out of memory");
        return p;
}

static void* xcalloc_fw(size_t size) {
        void *p = calloc(1, size ?: 1);
        if (!p)
                fail("Out of memory");
        return p;
}

static EFI_STATUS EFIAPI fake_allocate_pool(EFI_MEMORY_TYPE pool_type, size_t size, void **buffer);

void* efi_fuzz_alloc(size_t size) {
        /* From the pool, as sd-boot may free what it is given */
        void *p;
        if (fake_allocate_pool(EfiBootServicesData, size, &p) != EFI_SUCCESS)
                fail("Out of memory");
        memset(p, 0, size);
        return p;
}

void* efi_fuzz_memdup(const void *data, size_t size) {
        void *p = efi_fuzz_alloc(size);
        if (size > 0)
                memcpy(p, data, size);
        return p;
}

static size_t strlen16_fw(const char16_t *s) {
        size_t n = 0;
        if (s)
                while (s[n] != 0)
                        n++;
        return n;
}

static char16_t* strndup16_fw(const char16_t *s, size_t n) {
        char16_t *d = xmalloc_fw((n + 1) * sizeof(char16_t));
        if (n > 0)
                memcpy(d, s, n * sizeof(char16_t));
        d[n] = 0;
        return d;
}

static char16_t tolower16_fw(char16_t c) {
        return c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c;
}

static bool name_equal_fw(const char16_t *a, size_t a_len, const char16_t *b) {
        /* FAT is case-insensitive */
        if (strlen16_fw(b) != a_len)
                return false;
        for (size_t i = 0; i < a_len; i++)
                if (tolower16_fw(a[i]) != tolower16_fw(b[i]))
                        return false;
        return true;
}

static bool streq16_fw(const char16_t *a, const char16_t *b) {
        size_t n = strlen16_fw(a);
        return n == strlen16_fw(b) && memcmp(a, b, n * sizeof(char16_t)) == 0;
}

static bool guid_equal_fw(const EFI_GUID *a, const EFI_GUID *b) {
        return memcmp(a, b, sizeof(EFI_GUID)) == 0;
}

/* Handles and protocols */

static Handle* handle_find(EFI_HANDLE handle) {
        for (Handle *h = fw.handles; h; h = h->next)
                if (h == handle)
                        return h;
        return NULL;
}

static Protocol* handle_find_protocol(Handle *h, const EFI_GUID *guid) {
        if (!h || !guid)
                return NULL;
        for (size_t i = 0; i < h->n_protocols; i++)
                if (guid_equal_fw(&h->protocols[i].guid, guid))
                        return &h->protocols[i];
        return NULL;
}

EFI_HANDLE efi_fuzz_handle_new(void) {
        Handle *h = xcalloc_fw(sizeof(Handle));
        h->next = fw.handles;
        fw.handles = h;
        return h;
}

void efi_fuzz_handle_install(EFI_HANDLE handle, const EFI_GUID *guid, void *interface) {
        assert(guid);

        Handle *h = handle_find(handle);
        if (!h)
                fail("Unknown handle");

        Protocol *p = handle_find_protocol(h, guid);
        if (p) {
                p->interface = interface;
                return;
        }
        if (h->n_protocols >= PROTOCOLS_PER_HANDLE_MAX)
                fail("Too many protocols on handle");
        h->protocols[h->n_protocols++] = (Protocol) {
                .guid = *guid,
                .interface = interface,
        };
}

static void handle_uninstall(Handle *h, const EFI_GUID *guid) {
        Protocol *p = handle_find_protocol(h, guid);
        if (!p)
                return;
        size_t i = p - h->protocols;
        memmove(h->protocols + i, h->protocols + i + 1, (h->n_protocols - i - 1) * sizeof(Protocol));
        h->n_protocols--;
}

static size_t device_path_size(const EFI_DEVICE_PATH *dp) {
        /* Size of a device path including the end node, 0 if it is invalid. */
        const uint8_t *p = (const uint8_t*) dp;
        size_t size = 0;

        if (!dp)
                return 0;

        for (;;) {
                const EFI_DEVICE_PATH *n = (const EFI_DEVICE_PATH*) (p + size);
                if (n->Length < sizeof(EFI_DEVICE_PATH) || size + n->Length > DEVICE_PATH_SIZE_MAX)
                        return 0;
                size += n->Length;
                if (n->Type == END_DEVICE_PATH_TYPE && n->SubType == END_ENTIRE_DEVICE_PATH_SUBTYPE)
                        return size;
        }
}

/* Boot services */

static void* lazy_alloc(size_t size) {
        if (size > ALLOCATION_MAX)
                return NULL;

        void *p = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0);
        if (p == MAP_FAILED)
                return NULL;

        Mapping *m = xmalloc_fw(sizeof(Mapping));
        *m = (Mapping) {
                .p = p,
                .size = size,
                .next = fw.lazy,
        };
        fw.lazy = m;
        return p;
}

static bool lazy_free(void *p) {
        for (Mapping **m = &fw.lazy; *m; m = &(*m)->next)
                if ((*m)->p == p) {
                        Mapping *f = *m;
                        *m = f->next;
                        (void) munmap(f->p, f->size);
                        free(f);
                        return true;
                }
        return false;
}

static void page_allocation_free(PageAllocation *a) {
        if (a->lazy)
                (void) munmap(a->base, a->n_pages * EFI_PAGE_SIZE);
        else
                free(a->base);
        free(a);
}

static EFI_STATUS EFIAPI fake_allocate_pages(
                EFI_ALLOCATE_TYPE type,
                EFI_MEMORY_TYPE memory_type,
                size_t n_pages,
                EFI_PHYSICAL_ADDRESS *memory) {

        if (!memory || memory_type >= EfiMaxMemoryType)
                return EFI_INVALID_PARAMETER;
        if (type == AllocateAddress)
                return EFI_NOT_FOUND; /* We can't place memory at a given address */
        if (n_pages == 0)
                n_pages = 1;
        if (n_pages > ALLOCATION_MAX / EFI_PAGE_SIZE)
                return EFI_OUT_OF_RESOURCES;

        size_t size = n_pages * EFI_PAGE_SIZE;
        bool lazy = size >= LAZY_ALLOCATION_MIN;
        uint8_t *p = lazy ? mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE,
                                 -1, 0) :
                            aligned_alloc(EFI_PAGE_SIZE, size);
        if (lazy && p == MAP_FAILED)
                p = NULL;
        if (!p)
                return EFI_OUT_OF_RESOURCES;

        PageAllocation *a = xmalloc_fw(sizeof(PageAllocation));
        *a = (PageAllocation) {
                .base = p,
                .n_pages = n_pages,
                .lazy = lazy,
                .next = fw.pages,
        };

        EFI_PHYSICAL_ADDRESS addr = (EFI_PHYSICAL_ADDRESS) (uintptr_t) p;
        if (type == AllocateMaxAddress && addr + size - 1 > *memory) {
                page_allocation_free(a);
                return EFI_NOT_FOUND;
        }

        fw.pages = a;

        *memory = addr;
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_free_pages(EFI_PHYSICAL_ADDRESS memory, size_t n_pages) {
        /* Partial frees are allowed (xmalloc_aligned_pages() does that). The memory is only released once
         * all pages of an allocation have been freed. */
        for (PageAllocation **a = &fw.pages; *a; a = &(*a)->next) {
                uintptr_t base = (uintptr_t) (*a)->base;

                if (memory < base || memory >= base + (*a)->n_pages * EFI_PAGE_SIZE)
                        continue;
                if ((memory - base) % EFI_PAGE_SIZE != 0 ||
                    n_pages > (*a)->n_pages - (memory - base) / EFI_PAGE_SIZE)
                        return EFI_INVALID_PARAMETER;

                (*a)->n_freed += n_pages;
                if ((*a)->n_freed >= (*a)->n_pages) {
                        PageAllocation *f = *a;
                        *a = f->next;
                        page_allocation_free(f);
                }
                return EFI_SUCCESS;
        }

        return EFI_NOT_FOUND;
}

static size_t pool_bucket(const void *p) {
        return ((uintptr_t) p >> 4) % POOL_BUCKETS;
}

static EFI_STATUS EFIAPI fake_allocate_pool(EFI_MEMORY_TYPE pool_type, size_t size, void **buffer) {
        if (!buffer || pool_type >= EfiMaxMemoryType)
                return EFI_INVALID_PARAMETER;
        void *p = size >= LAZY_ALLOCATION_MIN ? lazy_alloc(size) : malloc(size ?: 1);
        if (!p)
                return EFI_OUT_OF_RESOURCES;

        Allocation *a = xmalloc_fw(sizeof(Allocation));
        *a = (Allocation) {
                .p = p,
                .next = fw.pool[pool_bucket(p)],
        };
        fw.pool[pool_bucket(p)] = a;

        *buffer = p;
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_free_pool(void *buffer) {
        if (!buffer)
                return EFI_INVALID_PARAMETER;

        for (Allocation **a = &fw.pool[pool_bucket(buffer)]; *a; a = &(*a)->next)
                if ((*a)->p == buffer) {
                        Allocation *f = *a;
                        *a = f->next;
                        free(f);
                        break;
                }

        /* Something that wasn't allocated with AllocatePool() is passed to free() anyway, so that the
         * sanitizers report it. */
        if (!lazy_free(buffer))
                free(buffer);
        return EFI_SUCCESS;
}

/* Events: only timers (which fire as soon as they are waited for) and ConIn's WaitForKey are supported. */

static Event* event_find(EFI_EVENT event) {
        for (Event *e = fw.events; e; e = e->next)
                if (e == event)
                        return e;
        return NULL;
}

static bool keys_pending(void) {
        return fw.keys_pos < fw.n_keys;
}

static EFI_STATUS EFIAPI fake_create_event(
                uint32_t type,
                EFI_TPL notify_tpl,
                void *notify_function,
                void *notify_context,
                EFI_EVENT *event) {

        if (!event)
                return EFI_INVALID_PARAMETER;
        if (type != EVT_TIMER || notify_function)
                return EFI_UNSUPPORTED;

        Event *e = xmalloc_fw(sizeof(Event));
        *e = (Event) {
                .type = type,
                .next = fw.events,
        };
        fw.events = e;
        *event = e;
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_set_timer(EFI_EVENT event, EFI_TIMER_DELAY type, uint64_t trigger_time) {
        return event_find(event) ? EFI_SUCCESS : EFI_INVALID_PARAMETER;
}

static EFI_STATUS EFIAPI fake_wait_for_event(size_t n_events, EFI_EVENT *events, size_t *index) {
        if (n_events == 0 || !events || !index)
                return EFI_INVALID_PARAMETER;

        for (size_t i = 0; i < n_events; i++)
                if (events[i] == &key_event && keys_pending()) {
                        *index = i;
                        return EFI_SUCCESS;
                }

        for (size_t i = 0; i < n_events; i++)
                if (event_find(events[i])) {
                        if (fw.timer_fires++ >= TIMER_FIRES_MAX)
                                return EFI_DEVICE_ERROR;
                        *index = i;
                        return EFI_SUCCESS;
                }

        return EFI_DEVICE_ERROR; /* Would wait forever */
}

static EFI_STATUS EFIAPI fake_close_event(EFI_EVENT event) {
        for (Event **e = &fw.events; *e; e = &(*e)->next)
                if (*e == event) {
                        *e = (*e)->next;
                        free(event);
                        return EFI_SUCCESS;
                }
        return EFI_INVALID_PARAMETER;
}

static EFI_STATUS EFIAPI fake_check_event(EFI_EVENT event) {
        if (event == &key_event)
                return keys_pending() ? EFI_SUCCESS : EFI_NOT_READY;
        return event_find(event) ? EFI_NOT_READY : EFI_INVALID_PARAMETER;
}

static EFI_STATUS EFIAPI fake_reinstall_protocol_interface(
                EFI_HANDLE handle,
                EFI_GUID *protocol,
                void *old_interface,
                void *new_interface) {

        Protocol *p = handle_find_protocol(handle_find(handle), protocol);
        if (!p || p->interface != old_interface)
                return EFI_NOT_FOUND;
        p->interface = new_interface;
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_handle_protocol(EFI_HANDLE handle, EFI_GUID *protocol, void **interface) {
        if (!protocol || !interface)
                return EFI_INVALID_PARAMETER;

        Handle *h = handle_find(handle);
        if (!h)
                return EFI_INVALID_PARAMETER;

        Protocol *p = handle_find_protocol(h, protocol);
        if (!p)
                return EFI_UNSUPPORTED;

        *interface = p->interface;
        return EFI_SUCCESS;
}

static size_t handles_with_protocol(
                EFI_LOCATE_SEARCH_TYPE search_type,
                const EFI_GUID *protocol,
                EFI_HANDLE *ret) {
        size_t n = 0;
        for (Handle *h = fw.handles; h; h = h->next) {
                if (search_type == ByProtocol && !handle_find_protocol(h, protocol))
                        continue;
                if (search_type == AllHandles && h->n_protocols == 0)
                        continue;
                if (ret)
                        ret[n] = h;
                n++;
        }
        return n;
}

static EFI_STATUS EFIAPI fake_locate_handle(
                EFI_LOCATE_SEARCH_TYPE search_type,
                EFI_GUID *protocol,
                void *search_key,
                size_t *buffer_size,
                EFI_HANDLE *buffer) {

        if (!buffer_size || !IN_SET(search_type, AllHandles, ByProtocol) ||
            (search_type == ByProtocol && !protocol))
                return EFI_INVALID_PARAMETER;

        size_t n = handles_with_protocol(search_type, protocol, /* ret= */ NULL);
        if (n == 0)
                return EFI_NOT_FOUND;
        if (*buffer_size < n * sizeof(EFI_HANDLE)) {
                *buffer_size = n * sizeof(EFI_HANDLE);
                return EFI_BUFFER_TOO_SMALL;
        }
        if (!buffer)
                return EFI_INVALID_PARAMETER;

        *buffer_size = n * sizeof(EFI_HANDLE);
        (void) handles_with_protocol(search_type, protocol, buffer);
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_locate_handle_buffer(
                EFI_LOCATE_SEARCH_TYPE search_type,
                EFI_GUID *protocol,
                void *search_key,
                size_t *n_handles,
                EFI_HANDLE **buffer) {

        if (!n_handles || !buffer || !IN_SET(search_type, AllHandles, ByProtocol) ||
            (search_type == ByProtocol && !protocol))
                return EFI_INVALID_PARAMETER;

        size_t n = handles_with_protocol(search_type, protocol, /* ret= */ NULL);
        if (n == 0)
                return EFI_NOT_FOUND;

        EFI_STATUS err = fake_allocate_pool(EfiBootServicesData, n * sizeof(EFI_HANDLE), (void**) buffer);
        if (err != EFI_SUCCESS)
                return err;

        *n_handles = handles_with_protocol(search_type, protocol, *buffer);
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_locate_device_path(
                EFI_GUID *protocol,
                EFI_DEVICE_PATH **device_path,
                EFI_HANDLE *device) {

        if (!protocol || !device_path || !device)
                return EFI_INVALID_PARAMETER;
        if (!*device_path)
                return EFI_INVALID_PARAMETER;

        /* Finds the handle with the given protocol whose device path is the longest prefix of the given
         * one, and advances the device path to the remaining part. */

        size_t size = device_path_size(*device_path);
        if (size == 0)
                return EFI_NOT_FOUND;

        Handle *best = NULL;
        size_t best_size = 0;
        for (Handle *h = fw.handles; h; h = h->next) {
                if (!handle_find_protocol(h, protocol))
                        continue;

                Protocol *p = handle_find_protocol(h, MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL));
                if (!p)
                        continue;

                size_t s = device_path_size(p->interface);
                if (s < sizeof(EFI_DEVICE_PATH))
                        continue;
                s -= sizeof(EFI_DEVICE_PATH); /* Without the end node */
                if (s > size || memcmp(p->interface, *device_path, s) != 0)
                        continue;

                if (!best || s > best_size) {
                        best = h;
                        best_size = s;
                }
        }
        if (!best)
                return EFI_NOT_FOUND;

        *device_path = (EFI_DEVICE_PATH*) ((uint8_t*) *device_path + best_size);
        *device = best;
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_install_configuration_table(EFI_GUID *guid, void *table) {
        if (!guid)
                return EFI_INVALID_PARAMETER;

        size_t n = fw.system_table.NumberOfTableEntries;
        for (size_t i = 0; i < n; i++) {
                if (!guid_equal_fw(&fw.config_tables[i].VendorGuid, guid))
                        continue;

                if (table)
                        fw.config_tables[i].VendorTable = table;
                else {
                        memmove(fw.config_tables + i, fw.config_tables + i + 1,
                                (n - i - 1) * sizeof(fw.config_tables[0]));
                        fw.system_table.NumberOfTableEntries--;
                }
                return EFI_SUCCESS;
        }

        if (!table)
                return EFI_NOT_FOUND;
        if (n >= CONFIG_TABLES_MAX)
                return EFI_OUT_OF_RESOURCES;

        fw.config_tables[n].VendorGuid = *guid;
        fw.config_tables[n].VendorTable = table;
        fw.system_table.NumberOfTableEntries++;
        return EFI_SUCCESS;
}

static uint32_t read_le(const uint8_t *p, size_t n) {
        uint32_t v = 0;
        for (size_t i = 0; i < n; i++)
                v |= (uint32_t) p[i] << (8 * i);
        return v;
}

uint8_t* efi_fuzz_pe_load(const void *data, size_t size, size_t *ret_size) {
        const uint8_t *file = data;

        assert(ret_size);

        /* Lays out a PE image in memory like LoadImage() does, with a minimal parser that is independent of
         * sd-boot's. Like real loaders, it keeps the headers in memory identical to those in the file, at
         * least up to the end of the section table: EDK2 rejects sections below SizeOfHeaders, U-Boot copies
         * the headers after the sections. Otherwise a section could replace SizeOfImage or the section table
         * in memory, and code that trusts the loaded headers (as sd-stub may) would see an image that no
         * firmware produces. */

        if (size < 0x40)
                return NULL;

        size_t pe = read_le(file + 0x3c, 4);
        if (pe > size || size - pe < 24 + 64 || memcmp(file + pe, "PE\0\0", 4) != 0)
                return NULL;

        size_t n_sections = read_le(file + pe + 6, 2), optional = pe + 24,
                optional_size = read_le(file + pe + 20, 2),
                image_size = read_le(file + optional + 56, 4),
                headers_size = read_le(file + optional + 60, 4);
        if (image_size == 0 || image_size > IMAGE_SIZE_MAX)
                return NULL;

        size_t table = optional + optional_size;
        if (table > size || n_sections > (size - table) / 40)
                return NULL;

        uint8_t *image = xcalloc_fw(image_size);

        for (size_t i = 0; i < n_sections; i++) {
                const uint8_t *sh = file + table + i * 40;
                size_t virtual_size = read_le(sh + 8, 4), virtual_address = read_le(sh + 12, 4),
                        raw_size = read_le(sh + 16, 4), raw_pointer = read_le(sh + 20, 4),
                        n = MIN(raw_size, virtual_size);

                if (virtual_address > image_size || virtual_size > image_size - virtual_address ||
                    raw_pointer > size || n > size - raw_pointer) {
                        free(image);
                        return NULL;
                }

                memcpy(image + virtual_address, file + raw_pointer, n);
        }

        /* The headers last, see above (table + n_sections * 40 <= size was checked) */
        memcpy(image, file, MIN3(MAX(headers_size, table + n_sections * 40), size, image_size));

        *ret_size = image_size;
        return image;
}

static Node* node_lookup(
                Node *root,
                Node *start,
                const char16_t *path,
                Node **ret_parent,
                const char16_t **ret_name,
                size_t *ret_name_len);

static bool device_path_file(const EFI_DEVICE_PATH *dp, char16_t *buf, size_t n_buf) {
        /* Returns the path of the first file path node */
        size_t size = device_path_size(dp);
        for (size_t offset = 0; offset < size; ) {
                const EFI_DEVICE_PATH *node = (const EFI_DEVICE_PATH*) ((const uint8_t*) dp + offset);
                if (node->Type == MEDIA_DEVICE_PATH && node->SubType == MEDIA_FILEPATH_DP) {
                        const FILEPATH_DEVICE_PATH *f = (const FILEPATH_DEVICE_PATH*) node;
                        size_t n = MIN((node->Length - sizeof(EFI_DEVICE_PATH)) / sizeof(char16_t),
                                       n_buf - 1), i;
                        for (i = 0; i < n && f->PathName[i] != 0; i++)
                                buf[i] = f->PathName[i];
                        buf[i] = 0;
                        return true;
                }
                offset += node->Length;
        }
        return false;
}

static EFI_STATUS EFIAPI fake_load_image(
                bool boot_policy,
                EFI_HANDLE parent_image_handle,
                EFI_DEVICE_PATH *device_path,
                void *source_buffer,
                size_t source_size,
                EFI_HANDLE *image_handle) {

        if (!image_handle || (!device_path && !source_buffer))
                return EFI_INVALID_PARAMETER;

        /* By default, refuse everything. To the caller this looks like Secure Boot refused the image, which
         * sd-stub handles by trying to trust addons on first use. Otherwise, images are laid out in memory,
         * but StartImage() never runs them. */
        if (!fw.load_images)
                return EFI_SECURITY_VIOLATION;

        const uint8_t *data = source_buffer;
        size_t size = source_size;
        if (!data) {
                char16_t path[4096];
                if (!device_path_file(device_path, path, ELEMENTSOF(path)))
                        return EFI_NOT_FOUND;

                Node *n = node_lookup(fw.esp_fs.root, fw.esp_fs.root, path,
                                      /* ret_parent= */ NULL,
                                      /* ret_name= */ NULL,
                                      /* ret_name_len= */ NULL);
                if (!n || n->directory)
                        return EFI_NOT_FOUND;
                data = n->data;
                size = n->size;
        }

        size_t image_size;
        uint8_t *memory = efi_fuzz_pe_load(data, size, &image_size);
        if (!memory)
                return EFI_LOAD_ERROR;

        LoadedImage *l = xcalloc_fw(sizeof(LoadedImage));
        l->memory = memory;
        l->handle = efi_fuzz_handle_new();
        l->protocol = (EFI_LOADED_IMAGE_PROTOCOL) {
                .Revision = 0x1000,
                .ParentHandle = parent_image_handle,
                .SystemTable = ST,
                .DeviceHandle = source_buffer ? NULL : fw.esp,
                .FilePath = device_path ? efi_fuzz_memdup(device_path, device_path_size(device_path)) : NULL,
                .ImageBase = memory,
                .ImageSize = image_size,
                .ImageCodeType = EfiLoaderCode,
                .ImageDataType = EfiLoaderData,
        };
        efi_fuzz_handle_install(l->handle, MAKE_GUID_PTR(EFI_LOADED_IMAGE_PROTOCOL), &l->protocol);
        l->next = fw.images;
        fw.images = l;

        *image_handle = l->handle;
        return EFI_SUCCESS;
}

void efi_fuzz_set_load_images(bool b) {
        fw.load_images = b;
}

static EFI_STATUS EFIAPI fake_start_image(
                EFI_HANDLE image_handle,
                size_t *exit_data_size,
                char16_t **exit_data) {
        for (LoadedImage *l = fw.images; l; l = l->next)
                if (l->handle == image_handle)
                        return EFI_LOAD_ERROR; /* Never run anything, pretend the image failed */
        return EFI_INVALID_PARAMETER;
}

static EFI_STATUS EFIAPI fake_exit(
                EFI_HANDLE image_handle,
                EFI_STATUS exit_status,
                size_t exit_data_size,
                char16_t *exit_data) {
        fail("Exit() called");
}

static EFI_STATUS EFIAPI fake_unload_image(EFI_HANDLE image_handle) {
        for (LoadedImage **l = &fw.images; *l; l = &(*l)->next)
                if ((*l)->handle == image_handle) {
                        LoadedImage *f = *l;
                        *l = f->next;
                        handle_uninstall(f->handle, MAKE_GUID_PTR(EFI_LOADED_IMAGE_PROTOCOL));
                        free(f->memory);
                        free(f);
                        return EFI_SUCCESS;
                }
        return EFI_INVALID_PARAMETER;
}

static EFI_STATUS EFIAPI fake_get_next_monotonic_count(uint64_t *count) {
        if (!count)
                return EFI_INVALID_PARAMETER;
        *count = fw.monotonic_count++;
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_stall(size_t microseconds) {
        /* sd-boot's freeze() stalls in a loop forever, it's called on assertion failures and panics. */
        if (microseconds >= 60U * 1000U * 1000U)
                fail("EFI code froze (assertion failure or panic)");
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_set_watchdog_timer(
                size_t timeout,
                uint64_t watchdog_code,
                size_t data_size,
                char16_t *watchdog_data) {
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_connect_controller(
                EFI_HANDLE controller_handle,
                EFI_HANDLE *driver_image_handle,
                EFI_DEVICE_PATH *remaining_device_path,
                bool recursive) {
        return EFI_NOT_FOUND;
}

static EFI_STATUS EFIAPI fake_disconnect_controller(
                EFI_HANDLE controller_handle,
                EFI_HANDLE driver_image_handle,
                EFI_HANDLE child_handle) {
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_open_protocol(
                EFI_HANDLE handle,
                EFI_GUID *protocol,
                void **interface,
                EFI_HANDLE agent_handle,
                EFI_HANDLE controller_handle,
                uint32_t attributes) {

        if (!protocol)
                return EFI_INVALID_PARAMETER;

        Handle *h = handle_find(handle);
        if (!h)
                return EFI_INVALID_PARAMETER;

        Protocol *p = handle_find_protocol(h, protocol);
        if (!p)
                return EFI_UNSUPPORTED;

        if (interface && attributes != EFI_OPEN_PROTOCOL_TEST_PROTOCOL)
                *interface = p->interface;
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_close_protocol(
                EFI_HANDLE handle,
                EFI_GUID *protocol,
                EFI_HANDLE agent_handle,
                EFI_HANDLE controller_handle) {

        if (!handle_find_protocol(handle_find(handle), protocol))
                return EFI_NOT_FOUND;
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_protocols_per_handle(
                EFI_HANDLE handle,
                EFI_GUID ***protocol_buffer,
                size_t *protocol_buffer_count) {

        if (!protocol_buffer || !protocol_buffer_count)
                return EFI_INVALID_PARAMETER;

        Handle *h = handle_find(handle);
        if (!h)
                return EFI_INVALID_PARAMETER;

        EFI_STATUS err = fake_allocate_pool(
                        EfiBootServicesData, h->n_protocols * sizeof(EFI_GUID*), (void**) protocol_buffer);
        if (err != EFI_SUCCESS)
                return err;

        for (size_t i = 0; i < h->n_protocols; i++)
                (*protocol_buffer)[i] = &h->protocols[i].guid;
        *protocol_buffer_count = h->n_protocols;
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_locate_protocol(EFI_GUID *protocol, void *registration, void **interface) {
        if (!protocol || !interface)
                return EFI_INVALID_PARAMETER;

        for (Handle *h = fw.handles; h; h = h->next) {
                Protocol *p = handle_find_protocol(h, protocol);
                if (p) {
                        *interface = p->interface;
                        return EFI_SUCCESS;
                }
        }

        *interface = NULL;
        return EFI_NOT_FOUND;
}

static EFI_STATUS EFIAPI fake_install_multiple_protocol_interfaces(EFI_HANDLE *handle, ...) {
        efi_va_list ap;

        if (!handle)
                return EFI_INVALID_PARAMETER;

        Handle *h = *handle ? handle_find(*handle) : efi_fuzz_handle_new();
        if (!h)
                return EFI_INVALID_PARAMETER;

        efi_va_start(ap, handle);
        for (;;) {
                EFI_GUID *guid = __builtin_va_arg(ap, EFI_GUID *);
                if (!guid)
                        break;
                void *interface = __builtin_va_arg(ap, void *);

                if (h->n_protocols >= PROTOCOLS_PER_HANDLE_MAX || handle_find_protocol(h, guid)) {
                        efi_va_end(ap);
                        return EFI_INVALID_PARAMETER;
                }
                efi_fuzz_handle_install(h, guid, interface);
        }
        efi_va_end(ap);

        *handle = h;
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_uninstall_multiple_protocol_interfaces(EFI_HANDLE handle, ...) {
        efi_va_list ap;

        Handle *h = handle_find(handle);
        if (!h)
                return EFI_INVALID_PARAMETER;

        efi_va_start(ap, handle);
        for (;;) {
                EFI_GUID *guid = __builtin_va_arg(ap, EFI_GUID *);
                if (!guid)
                        break;
                void *interface = __builtin_va_arg(ap, void *);

                Protocol *p = handle_find_protocol(h, guid);
                if (!p || p->interface != interface) {
                        efi_va_end(ap);
                        return EFI_INVALID_PARAMETER;
                }
                handle_uninstall(h, guid);
        }
        efi_va_end(ap);

        return EFI_SUCCESS;
}

static uint32_t crc32_fw(const void *data, size_t size) {
        uint32_t crc = UINT32_MAX;
        for (size_t i = 0; i < size; i++) {
                crc ^= ((const uint8_t*) data)[i];
                for (unsigned k = 0; k < 8; k++)
                        crc = (crc >> 1) ^ (UINT32_C(0xedb88320) & -(crc & 1));
        }
        return ~crc;
}

static EFI_STATUS EFIAPI fake_calculate_crc32(void *data, size_t data_size, uint32_t *crc32) {
        if (!data || data_size == 0 || !crc32)
                return EFI_INVALID_PARAMETER;

        *crc32 = crc32_fw(data, data_size);
        return EFI_SUCCESS;
}

static void EFIAPI fake_copy_mem(void *destination, void *source, size_t length) {
        /* Not memcpy(): sd-boot's memcpy(), which replaces libc's in the fuzzers, calls this. */
        memmove(destination, source, length);
}

static void EFIAPI fake_set_mem(void *buffer, size_t size, uint8_t value) {
        /* Not memset(): sd-boot's memset(), which replaces libc's in the fuzzers, calls this. */
        volatile uint8_t *p = buffer;
        for (size_t i = 0; i < size; i++)
                p[i] = value;
}

/* Runtime services */

static EFI_STATUS EFIAPI fake_get_time(EFI_TIME *time, EFI_TIME_CAPABILITIES *capabilities) {
        if (!time)
                return EFI_INVALID_PARAMETER;

        *time = (EFI_TIME) {
                .Year = 2026,
                .Month = 11,
                .Day = 23,
                .Hour = 12,
                .TimeZone = EFI_UNSPECIFIED_TIMEZONE,
        };
        if (capabilities)
                *capabilities = (EFI_TIME_CAPABILITIES) {
                        .Resolution = 1,
                };
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_set_time(EFI_TIME *time) {
        return EFI_UNSUPPORTED;
}

static Variable* variable_find(const char16_t *name, const EFI_GUID *vendor) {
        for (Variable *v = fw.variables; v; v = v->next)
                if (guid_equal_fw(&v->vendor, vendor) && streq16_fw(v->name, name))
                        return v;
        return NULL;
}

static EFI_STATUS EFIAPI fake_get_variable(
                char16_t *name,
                EFI_GUID *vendor,
                uint32_t *attributes,
                size_t *data_size,
                void *data) {

        if (!name || !vendor || !data_size)
                return EFI_INVALID_PARAMETER;

        Variable *v = variable_find(name, vendor);
        if (!v)
                return EFI_NOT_FOUND;

        if (*data_size < v->size) {
                *data_size = v->size;
                return EFI_BUFFER_TOO_SMALL;
        }
        if (!data && v->size > 0)
                return EFI_INVALID_PARAMETER;

        if (v->size > 0)
                memcpy(data, v->data, v->size);
        *data_size = v->size;
        if (attributes)
                *attributes = v->attributes;
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_get_next_variable_name(size_t *name_size, char16_t *name, EFI_GUID *vendor) {
        if (!name_size || !name || !vendor)
                return EFI_INVALID_PARAMETER;

        Variable *next;
        if (name[0] == 0)
                next = fw.variables;
        else {
                Variable *v = variable_find(name, vendor);
                if (!v)
                        return EFI_INVALID_PARAMETER;
                next = v->next;
        }
        if (!next)
                return EFI_NOT_FOUND;

        size_t size = (strlen16_fw(next->name) + 1) * sizeof(char16_t);
        if (*name_size < size) {
                *name_size = size;
                return EFI_BUFFER_TOO_SMALL;
        }

        memcpy(name, next->name, size);
        *vendor = next->vendor;
        *name_size = size;
        return EFI_SUCCESS;
}

static void variable_free(Variable *v) {
        free(v->name);
        free(v->data);
        free(v);
}

static EFI_STATUS variable_set(
                const char16_t *name,
                const EFI_GUID *vendor,
                uint32_t attributes,
                size_t data_size,
                const void *data) {

        if (!name || name[0] == 0 || !vendor || (data_size > 0 && !data))
                return EFI_INVALID_PARAMETER;
        if (data_size > VARIABLE_SIZE_MAX)
                return EFI_OUT_OF_RESOURCES;

        for (Variable **v = &fw.variables; *v; v = &(*v)->next) {
                if (!guid_equal_fw(&(*v)->vendor, vendor) || !streq16_fw((*v)->name, name))
                        continue;

                if (data_size == 0) {
                        Variable *f = *v;
                        *v = f->next;
                        variable_free(f);
                        fw.n_variables--;
                        return EFI_SUCCESS;
                }

                void *d = xmalloc_fw(data_size);
                memcpy(d, data, data_size);
                free((*v)->data);
                (*v)->data = d;
                (*v)->size = data_size;
                (*v)->attributes = attributes;
                return EFI_SUCCESS;
        }

        if (data_size == 0)
                return EFI_NOT_FOUND;
        if (fw.n_variables >= VARIABLES_MAX)
                return EFI_OUT_OF_RESOURCES;

        Variable *n = xmalloc_fw(sizeof(Variable));
        *n = (Variable) {
                .vendor = *vendor,
                .name = strndup16_fw(name, strlen16_fw(name)),
                .attributes = attributes,
                .data = xmalloc_fw(data_size),
                .size = data_size,
        };
        memcpy(n->data, data, data_size);

        /* Append, so that GetNextVariableName() returns them in creation order */
        Variable **tail = &fw.variables;
        while (*tail)
                tail = &(*tail)->next;
        *tail = n;
        fw.n_variables++;
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_set_variable(
                char16_t *name,
                EFI_GUID *vendor,
                uint32_t attributes,
                size_t data_size,
                void *data) {

        if (FLAGS_SET(attributes, EFI_VARIABLE_APPEND_WRITE)) {
                Variable *v = variable_find(name, vendor);
                if (v && data_size > 0) {
                        if (data_size > VARIABLE_SIZE_MAX - v->size)
                                return EFI_OUT_OF_RESOURCES;
                        uint8_t *d = xmalloc_fw(v->size + data_size);
                        memcpy(d, v->data, v->size);
                        memcpy(d + v->size, data, data_size);
                        EFI_STATUS err = variable_set(
                                        name, vendor, attributes & ~EFI_VARIABLE_APPEND_WRITE,
                                        v->size + data_size, d);
                        free(d);
                        return err;
                }
                if (data_size == 0)
                        return EFI_SUCCESS;
        }

        return variable_set(name, vendor, attributes & ~EFI_VARIABLE_APPEND_WRITE, data_size, data);
}

void efi_fuzz_variable_set(const EFI_GUID *vendor, const char16_t *name, const void *data, size_t size) {
        (void) variable_set(name, vendor,
                            EFI_VARIABLE_NON_VOLATILE|EFI_VARIABLE_BOOTSERVICE_ACCESS|
                            EFI_VARIABLE_RUNTIME_ACCESS,
                            size, data);
}

static EFI_STATUS EFIAPI fake_get_next_high_monotonic_count(uint32_t *high_count) {
        if (!high_count)
                return EFI_INVALID_PARAMETER;
        *high_count = 0;
        return EFI_SUCCESS;
}

_noreturn_ static void EFIAPI fake_reset_system(
                EFI_RESET_TYPE reset_type,
                EFI_STATUS reset_status,
                size_t data_size,
                void *reset_data) {

        /* Ends efi_fuzz_run(). What the abandoned stack frames had allocated is released by
         * efi_fuzz_firmware_reset(). */
        if (!fw.reset_jmp)
                fail("ResetSystem() called outside of efi_fuzz_run()");
        longjmp(*fw.reset_jmp, 1);
}

bool efi_fuzz_run(void (*func)(void *userdata), void *userdata) {
        jmp_buf j;

        assert_se(!fw.reset_jmp);

        if (setjmp(j) != 0) {
                fw.reset_jmp = NULL;
                return true;
        }

        fw.reset_jmp = &j;
        func(userdata);
        fw.reset_jmp = NULL;
        return false;
}

static EFI_STATUS check_capsules(EFI_CAPSULE_HEADER **capsules, size_t n) {
        /* Validates what sd-boot passes, like the firmware would, and lets the sanitizers check it */
        if (!capsules || n == 0)
                return EFI_INVALID_PARAMETER;

        for (size_t i = 0; i < n; i++) {
                const EFI_CAPSULE_HEADER *c = capsules[i];
                if (!c || c->HeaderSize > c->CapsuleImageSize ||
                    c->CapsuleImageSize < sizeof(EFI_CAPSULE_HEADER))
                        return EFI_INVALID_PARAMETER;
                const volatile uint8_t *q = (const uint8_t*) c;
                (void) q[c->CapsuleImageSize - 1];
        }

        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_update_capsule(
                EFI_CAPSULE_HEADER **capsule_header_array,
                size_t capsule_count,
                EFI_PHYSICAL_ADDRESS scatter_gather_list) {

        if (scatter_gather_list == 0)
                return EFI_INVALID_PARAMETER;
        return check_capsules(capsule_header_array, capsule_count);
}

static EFI_STATUS EFIAPI fake_query_capsule_capabilities(
                EFI_CAPSULE_HEADER **capsule_header_array,
                size_t capsule_count,
                uint64_t *maximum_capsule_size,
                EFI_RESET_TYPE *reset_type) {

        if (!maximum_capsule_size || !reset_type)
                return EFI_INVALID_PARAMETER;

        *maximum_capsule_size = 64U * 1024U * 1024U;
        *reset_type = EfiResetWarm;
        return check_capsules(capsule_header_array, capsule_count);
}

/* Console */

static struct {
        int32_t MaxMode;
        int32_t Mode;
        int32_t Attribute;
        int32_t CursorColumn;
        int32_t CursorRow;
        bool CursorVisible;
} console_mode;

static EFI_STATUS EFIAPI fake_con_out_reset(
                EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *this,
                bool extended_verification) {
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_con_out_output_string(
                EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *this,
                char16_t *string) {
        static int show = -1;

        if (!string)
                return EFI_INVALID_PARAMETER;

        /* $SYSTEMD_EFI_FUZZ_CONSOLE=1 shows the console output (e.g. sd-boot's log messages) on stderr. */
        if (show < 0) {
                const char *e = getenv("SYSTEMD_EFI_FUZZ_CONSOLE");
                show = e && e[0] == '1';
        }

        /* Walk the string, so that the sanitizers notice if it is not terminated. */
        for (; *string != 0; string++) {
                char c = *string < 128 ? (char) *string : '?';

                if (c == '\n') {
                        console_mode.CursorColumn = 0;
                        if (console_line_len > 0) {
                                memcpy(console_last_line, console_line, console_line_len);
                                console_last_line[console_line_len] = 0;
                                console_line_len = 0;
                        }
                } else if (c != '\r') {
                        console_mode.CursorColumn = (console_mode.CursorColumn + 1) % 80;
                        if (console_line_len < sizeof(console_line) - 1)
                                console_line[console_line_len++] = c;
                }

                if (show && c != '\r')
                        fputc(c, stderr);
        }
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_con_out_test_string(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *this, char16_t *string) {
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_con_out_query_mode(
                EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *this,
                size_t mode_number,
                size_t *columns,
                size_t *rows) {

        if (mode_number != 0)
                return EFI_UNSUPPORTED;
        if (columns)
                *columns = 80;
        if (rows)
                *rows = 25;
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_con_out_set_mode(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *this, size_t mode_number) {
        return mode_number == 0 ? EFI_SUCCESS : EFI_UNSUPPORTED;
}

static EFI_STATUS EFIAPI fake_con_out_set_attribute(
                EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *this,
                size_t attribute) {
        console_mode.Attribute = (int32_t) attribute;
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_con_out_clear_screen(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *this) {
        console_mode.CursorColumn = console_mode.CursorRow = 0;
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_con_out_set_cursor_position(
                EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *this,
                size_t column,
                size_t row) {

        if (column >= 80 || row >= 25)
                return EFI_UNSUPPORTED;
        console_mode.CursorColumn = (int32_t) column;
        console_mode.CursorRow = (int32_t) row;
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_con_out_enable_cursor(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *this, bool visible) {
        console_mode.CursorVisible = visible;
        return EFI_SUCCESS;
}

static EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL con_out = {
        .Reset = fake_con_out_reset,
        .OutputString = fake_con_out_output_string,
        .TestString = fake_con_out_test_string,
        .QueryMode = fake_con_out_query_mode,
        .SetMode = fake_con_out_set_mode,
        .SetAttribute = fake_con_out_set_attribute,
        .ClearScreen = fake_con_out_clear_screen,
        .SetCursorPosition = fake_con_out_set_cursor_position,
        .EnableCursor = fake_con_out_enable_cursor,
        .Mode = (void*) &console_mode,
};

static EFI_STATUS EFIAPI fake_con_in_reset(
                EFI_SIMPLE_TEXT_INPUT_PROTOCOL *this,
                bool extended_verification) {
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_con_in_read_key_stroke(
                EFI_SIMPLE_TEXT_INPUT_PROTOCOL *this,
                EFI_INPUT_KEY *key) {
        if (!key)
                return EFI_INVALID_PARAMETER;
        if (!keys_pending())
                return EFI_NOT_READY;

        *key = fw.keys[fw.keys_pos++];
        fw.timer_fires = 0;
        return EFI_SUCCESS;
}

static EFI_SIMPLE_TEXT_INPUT_PROTOCOL con_in = {
        .Reset = fake_con_in_reset,
        .ReadKeyStroke = fake_con_in_read_key_stroke,
        .WaitForKey = &key_event,
};

void efi_fuzz_set_keys(const void *data, size_t size) {
        /* Each key is a scan code and a UCS-2 character, both 16-bit little-endian */
        const uint8_t *d = data;
        size_t n = MIN(size / 4, (size_t) KEYS_MAX);

        fw.keys = efi_fuzz_alloc(n * sizeof(EFI_INPUT_KEY));
        for (size_t i = 0; i < n; i++)
                fw.keys[i] = (EFI_INPUT_KEY) {
                        .ScanCode = d[4 * i] | (uint16_t) d[4 * i + 1] << 8,
                        .UnicodeChar = d[4 * i + 2] | (char16_t) d[4 * i + 3] << 8,
                };
        fw.n_keys = n;
        fw.keys_pos = 0;
}

/* The file system */

static Node* node_new(Node *parent, const char16_t *name, size_t name_len, bool directory) {
        if (fw.n_nodes >= NODES_MAX)
                return NULL;

        Node *n = xcalloc_fw(sizeof(Node));
        n->name = strndup16_fw(name, name_len);
        n->directory = directory;
        n->parent = parent;
        fw.n_nodes++;

        if (parent) {
                Node **tail = &parent->children;
                while (*tail)
                        tail = &(*tail)->next;
                *tail = n;
        }
        return n;
}

static void node_free(Node *n) {
        while (n->children) {
                Node *c = n->children;
                n->children = c->next;
                node_free(c);
        }
        free(n->name);
        free(n->data);
        free(n);
        fw.n_nodes--;
}

static void node_unlink(Node *n) {
        for (Node **i = &n->parent->children; *i; i = &(*i)->next)
                if (*i == n) {
                        *i = n->next;
                        break;
                }
        n->next = fw.deleted;
        fw.deleted = n;
}

static Node* node_find_child(Node *dir, const char16_t *name, size_t name_len) {
        for (Node *c = dir->children; c; c = c->next)
                if (name_equal_fw(name, name_len, c->name))
                        return c;
        return NULL;
}

/* Resolves 'path' relative to 'start'. If the last component does not exist, returns NULL and the parent
 * directory and last component in *ret_parent, *ret_name and *ret_name_len (if the parent exists). */
static Node* node_lookup(
                Node *root,
                Node *start,
                const char16_t *path,
                Node **ret_parent,
                const char16_t **ret_name,
                size_t *ret_name_len) {

        Node *n = start;
        const char16_t *p = path;

        /* Only set together with ret_parent */
        POINTER_MAY_BE_NULL(ret_name);
        POINTER_MAY_BE_NULL(ret_name_len);

        if (ret_parent)
                *ret_parent = NULL;

        if (*p == '\\') {
                n = root;
                while (*p == '\\')
                        p++;
        }

        while (*p != 0) {
                const char16_t *e = p;
                while (*e != 0 && *e != '\\')
                        e++;
                size_t len = e - p;
                const char16_t *next = e;
                while (*next == '\\')
                        next++;

                if (!n->directory || len > FILE_NAME_MAX)
                        return NULL;

                if (len == 1 && p[0] == '.')
                        ;
                else if (len == 2 && p[0] == '.' && p[1] == '.')
                        n = n->parent ?: n;
                else {
                        Node *c = node_find_child(n, p, len);
                        if (!c) {
                                if (*next == 0 && ret_parent) {
                                        *ret_parent = n;
                                        *ret_name = p;
                                        *ret_name_len = len;
                                }
                                return NULL;
                        }
                        n = c;
                }

                p = next;
        }

        return n;
}

static EFI_FILE file_template;

static EFI_FILE* file_new(Node *root, Node *node, bool writable) {
        File *f = xcalloc_fw(sizeof(File));
        f->file = file_template;
        f->root = root;
        f->node = node;
        f->writable = writable;
        f->next = fw.files;
        fw.files = f;
        return &f->file;
}

static void file_free(File *f) {
        for (File **i = &fw.files; *i; i = &(*i)->next)
                if (*i == f) {
                        *i = f->next;
                        break;
                }
        free(f);
}

static EFI_STATUS EFIAPI fake_file_open(
                EFI_FILE *this,
                EFI_FILE **new_handle,
                char16_t *file_name,
                uint64_t open_mode,
                uint64_t attributes) {

        File *f = (File*) this;

        if (!this || !new_handle || !file_name)
                return EFI_INVALID_PARAMETER;
        if (!IN_SET(open_mode,
                    EFI_FILE_MODE_READ,
                    EFI_FILE_MODE_READ|EFI_FILE_MODE_WRITE,
                    EFI_FILE_MODE_READ|EFI_FILE_MODE_WRITE|EFI_FILE_MODE_CREATE))
                return EFI_INVALID_PARAMETER;

        bool writable = FLAGS_SET(open_mode, EFI_FILE_MODE_WRITE);
        if (writable && fw.esp_read_only)
                return EFI_WRITE_PROTECTED;

        Node *parent;
        const char16_t *name;
        size_t name_len;
        Node *n = node_lookup(f->root, f->node, file_name, &parent, &name, &name_len);
        if (!n) {
                if (!FLAGS_SET(open_mode, EFI_FILE_MODE_CREATE) || !parent)
                        return EFI_NOT_FOUND;

                n = node_new(parent, name, name_len, FLAGS_SET(attributes, EFI_FILE_DIRECTORY));
                if (!n)
                        return EFI_VOLUME_FULL;
                n->read_only = FLAGS_SET(attributes, EFI_FILE_READ_ONLY);
        } else if (writable && n->read_only)
                return EFI_ACCESS_DENIED;

        *new_handle = file_new(f->root, n, writable);
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_file_close(EFI_FILE *this) {
        if (!this)
                return EFI_INVALID_PARAMETER;
        file_free((File*) this);
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_file_delete(EFI_FILE *this) {
        File *f = (File*) this;

        if (!this)
                return EFI_INVALID_PARAMETER;

        bool ok = f->writable && f->node != f->root && !f->node->children;
        if (ok)
                node_unlink(f->node);
        file_free(f);
        return ok ? EFI_SUCCESS : EFI_WARN_DELETE_FAILURE;
}

static size_t file_info_size(const Node *n) {
        return offsetof(EFI_FILE_INFO, FileName) + (strlen16_fw(n->name) + 1) * sizeof(char16_t);
}

static void file_info_fill(const Node *n, EFI_FILE_INFO *info) {
        static const EFI_TIME t = {
                .Year = 2026,
                .Month = 1,
                .Day = 1,
                .TimeZone = EFI_UNSPECIFIED_TIMEZONE,
        };

        assert(info);

        size_t size = file_info_size(n);
        *info = (EFI_FILE_INFO) {
                .Size = size,
                .FileSize = n->size,
                .PhysicalSize = (n->size + 511U) & ~(size_t) 511U,
                .CreateTime = t,
                .LastAccessTime = t,
                .ModificationTime = t,
                .Attribute = (n->directory ? EFI_FILE_DIRECTORY : EFI_FILE_ARCHIVE) |
                             (n->read_only ? EFI_FILE_READ_ONLY : 0),
        };
        memcpy(info->FileName, n->name, size - offsetof(EFI_FILE_INFO, FileName));
}

static EFI_STATUS EFIAPI fake_file_read(EFI_FILE *this, size_t *buffer_size, void *buffer) {
        File *f = (File*) this;

        if (!this || !buffer_size)
                return EFI_INVALID_PARAMETER;
        if (*buffer_size > 0 && !buffer)
                return EFI_INVALID_PARAMETER;

        if (f->node->directory) {
                Node *c = f->node->children;
                for (uint64_t i = 0; c && i < f->position; i++)
                        c = c->next;
                if (!c) {
                        *buffer_size = 0;
                        return EFI_SUCCESS;
                }

                size_t size = file_info_size(c);
                if (*buffer_size < size) {
                        *buffer_size = size;
                        return EFI_BUFFER_TOO_SMALL;
                }
                file_info_fill(c, buffer);
                *buffer_size = size;
                f->position++;
                return EFI_SUCCESS;
        }

        if (f->position > f->node->size)
                return EFI_DEVICE_ERROR;

        size_t n = MIN(*buffer_size, f->node->size - (size_t) f->position);
        if (n > 0)
                memcpy(buffer, f->node->data + f->position, n);
        f->position += n;
        *buffer_size = n;
        return EFI_SUCCESS;
}

static EFI_STATUS node_resize(Node *n, size_t size) {
        if (size > FILE_SIZE_MAX)
                return EFI_VOLUME_FULL;

        uint8_t *d = xmalloc_fw(size);
        if (size > 0 && n->size > 0)
                memcpy(d, n->data, MIN(size, n->size));
        if (size > n->size)
                memset(d + n->size, 0, size - n->size);
        free(n->data);
        n->data = d;
        n->size = size;
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_file_write(EFI_FILE *this, size_t *buffer_size, void *buffer) {
        File *f = (File*) this;
        EFI_STATUS err;

        if (!this || !buffer_size)
                return EFI_INVALID_PARAMETER;
        if (*buffer_size > 0 && !buffer)
                return EFI_INVALID_PARAMETER;
        if (f->node->directory)
                return EFI_UNSUPPORTED;
        if (fw.esp_read_only)
                return EFI_WRITE_PROTECTED;
        if (!f->writable)
                return EFI_ACCESS_DENIED;
        if (f->position > FILE_SIZE_MAX || *buffer_size > FILE_SIZE_MAX - f->position)
                return EFI_VOLUME_FULL;

        size_t end = f->position + *buffer_size;
        if (end > f->node->size) {
                err = node_resize(f->node, end);
                if (err != EFI_SUCCESS)
                        return err;
        }
        if (*buffer_size > 0)
                memcpy(f->node->data + f->position, buffer, *buffer_size);
        f->position = end;
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_file_get_position(EFI_FILE *this, uint64_t *position) {
        File *f = (File*) this;

        if (!this || !position)
                return EFI_INVALID_PARAMETER;
        if (f->node->directory)
                return EFI_UNSUPPORTED;
        *position = f->position;
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_file_set_position(EFI_FILE *this, uint64_t position) {
        File *f = (File*) this;

        if (!this)
                return EFI_INVALID_PARAMETER;
        if (f->node->directory) {
                if (position != 0)
                        return EFI_UNSUPPORTED;
                f->position = 0;
                return EFI_SUCCESS;
        }

        f->position = position == UINT64_MAX ? f->node->size : position;
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_file_get_info(
                EFI_FILE *this,
                EFI_GUID *information_type,
                size_t *buffer_size,
                void *buffer) {

        File *f = (File*) this;

        if (!this || !information_type || !buffer_size)
                return EFI_INVALID_PARAMETER;
        if (*buffer_size > 0 && !buffer)
                return EFI_INVALID_PARAMETER;

        if (guid_equal_fw(information_type, MAKE_GUID_PTR(EFI_FILE_INFO))) {
                size_t size = file_info_size(f->node);
                if (*buffer_size < size) {
                        *buffer_size = size;
                        return EFI_BUFFER_TOO_SMALL;
                }
                file_info_fill(f->node, buffer);
                *buffer_size = size;
                return EFI_SUCCESS;
        }

        if (guid_equal_fw(information_type, MAKE_GUID_PTR(EFI_FILE_SYSTEM_INFO))) {
                static const char16_t label[] = u"ESP";
                size_t size = offsetof(EFI_FILE_SYSTEM_INFO, VolumeLabel) + sizeof(label);
                if (*buffer_size < size) {
                        *buffer_size = size;
                        return EFI_BUFFER_TOO_SMALL;
                }

                EFI_FILE_SYSTEM_INFO *info = buffer;
                *info = (EFI_FILE_SYSTEM_INFO) {
                        .Size = size,
                        .ReadOnly = fw.esp_read_only,
                        .VolumeSize = 512U * 1024U * 1024U,
                        .FreeSpace = 256U * 1024U * 1024U,
                        .BlockSize = 512,
                };
                memcpy(info->VolumeLabel, label, sizeof(label));
                *buffer_size = size;
                return EFI_SUCCESS;
        }

        return EFI_UNSUPPORTED;
}

static EFI_STATUS EFIAPI fake_file_set_info(
                EFI_FILE *this,
                EFI_GUID *information_type,
                size_t buffer_size,
                void *buffer) {

        File *f = (File*) this;
        EFI_STATUS err;

        if (!this || !information_type || !buffer)
                return EFI_INVALID_PARAMETER;
        if (!guid_equal_fw(information_type, MAKE_GUID_PTR(EFI_FILE_INFO)))
                return EFI_UNSUPPORTED;
        if (fw.esp_read_only)
                return EFI_WRITE_PROTECTED;
        if (!f->writable)
                return EFI_ACCESS_DENIED;

        const EFI_FILE_INFO *info = buffer;
        if (buffer_size < offsetof(EFI_FILE_INFO, FileName) + sizeof(char16_t) || info->Size > buffer_size)
                return EFI_BAD_BUFFER_SIZE;

        size_t name_max = (buffer_size - offsetof(EFI_FILE_INFO, FileName)) / sizeof(char16_t), name_len = 0;
        while (name_len < name_max && info->FileName[name_len] != 0)
                name_len++;
        if (name_len >= name_max)
                return EFI_BAD_BUFFER_SIZE;

        if (!f->node->directory && info->FileSize != f->node->size) {
                err = node_resize(f->node, info->FileSize);
                if (err != EFI_SUCCESS)
                        return err;
        }

        if (!name_equal_fw(info->FileName, name_len, f->node->name)) {
                /* Only renames within the same directory are supported */
                if (name_len == 0 || name_len > FILE_NAME_MAX || f->node == f->root)
                        return EFI_ACCESS_DENIED;
                for (size_t i = 0; i < name_len; i++)
                        if (info->FileName[i] == '\\')
                                return EFI_ACCESS_DENIED;
                if (node_find_child(f->node->parent, info->FileName, name_len))
                        return EFI_ACCESS_DENIED;

                free(f->node->name);
                f->node->name = strndup16_fw(info->FileName, name_len);
        }

        f->node->read_only = FLAGS_SET(info->Attribute, EFI_FILE_READ_ONLY);
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_file_flush(EFI_FILE *this) {
        return this ? EFI_SUCCESS : EFI_INVALID_PARAMETER;
}

static EFI_FILE file_template = {
        .Revision = 0x00010000,
        .Open = fake_file_open,
        .Close = fake_file_close,
        .Delete = fake_file_delete,
        .Read = fake_file_read,
        .Write = fake_file_write,
        .GetPosition = fake_file_get_position,
        .SetPosition = fake_file_set_position,
        .GetInfo = fake_file_get_info,
        .SetInfo = fake_file_set_info,
        .Flush = fake_file_flush,
};

static EFI_STATUS EFIAPI fake_open_volume(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *this, EFI_FILE **root) {
        if (!this || !root)
                return EFI_INVALID_PARAMETER;

        FileSystem *fs = (FileSystem*) this;
        *root = file_new(fs->root, fs->root, /* writable= */ true);
        return EFI_SUCCESS;
}

EFI_HANDLE efi_fuzz_esp_handle(void) {
        return fw.esp;
}

EFI_FILE* efi_fuzz_esp_open_root(void) {
        return file_new(fw.esp_fs.root, fw.esp_fs.root, /* writable= */ true);
}

void efi_fuzz_esp_set_read_only(bool b) {
        fw.esp_read_only = b;
}

static Node* fs_add(Node *root, const char16_t *path, bool directory) {
        Node *n = root;

        /* Creates all missing components of path, the last one as a file or directory */
        for (const char16_t *p = path; *p != 0; ) {
                while (*p == '\\' || *p == '/')
                        p++;
                const char16_t *e = p;
                while (*e != 0 && *e != '\\' && *e != '/')
                        e++;
                if (e == p)
                        break;
                if (!n->directory || (size_t) (e - p) > FILE_NAME_MAX)
                        return NULL;

                bool last = true;
                for (const char16_t *q = e; *q != 0; q++)
                        if (*q != '\\' && *q != '/') {
                                last = false;
                                break;
                        }

                Node *c = node_find_child(n, p, e - p);
                if (!c)
                        c = node_new(n, p, e - p, last ? directory : true);
                if (!c)
                        return NULL;
                n = c;
                p = e;
        }

        return n == root || n->directory == directory ? n : NULL;
}

static void fs_add_file(Node *root, const char16_t *path, const void *data, size_t size, bool read_only) {
        if (size > FILE_SIZE_MAX)
                return;

        Node *n = fs_add(root, path, /* directory= */ false);
        if (!n || n == root)
                return;

        free(n->data);
        n->data = xmalloc_fw(size);
        if (size > 0)
                memcpy(n->data, data, size);
        n->size = size;
        n->read_only = read_only;
}

void efi_fuzz_esp_add_file(const char16_t *path, const void *data, size_t size, bool read_only) {
        fs_add_file(fw.esp_fs.root, path, data, size, read_only);
}

void efi_fuzz_xbootldr_add_file(const char16_t *path, const void *data, size_t size, bool read_only) {
        fs_add_file(fw.xbootldr_fs.root, path, data, size, read_only);
}

void efi_fuzz_esp_add_directory(const char16_t *path) {
        (void) fs_add(fw.esp_fs.root, path, /* directory= */ true);
}

EFI_DEVICE_PATH* efi_fuzz_file_device_path(const char16_t *path) {
        size_t len = strlen16_fw(path);
        if (len > 4096)
                len = 4096;
        size_t node_size = offsetof(FILEPATH_DEVICE_PATH, PathName) + (len + 1) * sizeof(char16_t);

        uint8_t *dp = efi_fuzz_alloc(node_size + sizeof(EFI_DEVICE_PATH));
        FILEPATH_DEVICE_PATH *file = (FILEPATH_DEVICE_PATH*) dp;
        file->Header = (EFI_DEVICE_PATH) {
                .Type = MEDIA_DEVICE_PATH,
                .SubType = MEDIA_FILEPATH_DP,
                .Length = node_size,
        };
        memcpy(file->PathName, path, len * sizeof(char16_t));
        file->PathName[len] = 0;

        *(EFI_DEVICE_PATH*) (dp + node_size) = (EFI_DEVICE_PATH) {
                .Type = END_DEVICE_PATH_TYPE,
                .SubType = END_ENTIRE_DEVICE_PATH_SUBTYPE,
                .Length = sizeof(EFI_DEVICE_PATH),
        };
        return (EFI_DEVICE_PATH*) dp;
}

/* SMBIOS, devicetree, EDID, RNG */

typedef struct {
        uint8_t anchor_string[4];
        uint8_t entry_point_structure_checksum;
        uint8_t entry_point_length;
        uint8_t major_version;
        uint8_t minor_version;
        uint16_t max_structure_size;
        uint8_t entry_point_revision;
        uint8_t formatted_area[5];
        uint8_t intermediate_anchor_string[5];
        uint8_t intermediate_checksum;
        uint16_t table_length;
        uint32_t table_address;
        uint16_t number_of_smbios_structures;
        uint8_t smbios_bcd_revision;
} _packed_ SmbiosEntryPoint;

typedef struct {
        uint8_t anchor_string[5];
        uint8_t entry_point_structure_checksum;
        uint8_t entry_point_length;
        uint8_t major_version;
        uint8_t minor_version;
        uint8_t docrev;
        uint8_t entry_point_revision;
        uint8_t reserved;
        uint32_t table_maximum_size;
        uint64_t table_address;
} _packed_ Smbios3EntryPoint;

static void* alloc_low(size_t size) {
        /* SMBIOS 2.1 entry points carry a 32-bit table address. Put the data at the end of a mapping below
         * 4G followed by an inaccessible page, so that reads past the end fault. */
        if (size == 0 || size > 0x10000)
                return NULL;

        size_t mapped = EFI_SIZE_TO_PAGES(size) * EFI_PAGE_SIZE + EFI_PAGE_SIZE;
        int flags = MAP_PRIVATE|MAP_ANONYMOUS;
#ifdef MAP_32BIT
        flags |= MAP_32BIT;
#endif
        uint8_t *p = mmap(NULL, mapped, PROT_READ|PROT_WRITE, flags, -1, 0);
        if (p == MAP_FAILED)
                return NULL;
        if ((uintptr_t) p + mapped - 1 > UINT32_MAX ||
            mprotect(p + mapped - EFI_PAGE_SIZE, EFI_PAGE_SIZE, PROT_NONE) < 0) {
                (void) munmap(p, mapped);
                return NULL;
        }

        Mapping *m = xmalloc_fw(sizeof(Mapping));
        *m = (Mapping) {
                .p = p,
                .size = mapped,
                .next = fw.mappings,
        };
        fw.mappings = m;
        return p + mapped - EFI_PAGE_SIZE - size;
}

void efi_fuzz_set_smbios(const void *data, size_t size, bool smbios3) {
        if (size > 0x10000)
                return;

        if (smbios3) {
                Smbios3EntryPoint *e = efi_fuzz_alloc(sizeof(Smbios3EntryPoint));
                *e = (Smbios3EntryPoint) {
                        .anchor_string = { '_', 'S', 'M', '3', '_' },
                        .entry_point_length = sizeof(Smbios3EntryPoint),
                        .major_version = 3,
                        .minor_version = 6,
                        .entry_point_revision = 1,
                        .table_maximum_size = size,
                        .table_address = (uintptr_t) efi_fuzz_memdup(data, size),
                };
                (void) fake_install_configuration_table(MAKE_GUID_PTR(SMBIOS3_TABLE), e);
        } else {
                uint8_t *t = alloc_low(size);
                if (!t)
                        return;
                memcpy(t, data, size);

                SmbiosEntryPoint *e = efi_fuzz_alloc(sizeof(SmbiosEntryPoint));
                *e = (SmbiosEntryPoint) {
                        .anchor_string = { '_', 'S', 'M', '_' },
                        .entry_point_length = sizeof(SmbiosEntryPoint),
                        .major_version = 2,
                        .minor_version = 8,
                        .intermediate_anchor_string = { '_', 'D', 'M', 'I', '_' },
                        .table_length = size,
                        .table_address = (uint32_t) (uintptr_t) t,
                };
                (void) fake_install_configuration_table(MAKE_GUID_PTR(SMBIOS_TABLE), e);
        }
}

void efi_fuzz_set_devicetree(const void *data, size_t size) {
        /* The devicetree passed by the firmware is trusted to have a complete header (struct FdtHeader) and
         * to be as large as the header says, hence pad it accordingly. */
        if (size < 8 || size > 0x100000)
                return;

        const uint8_t *d = data;
        size_t total = (size_t) d[4] << 24 | (size_t) d[5] << 16 | (size_t) d[6] << 8 | d[7];
        if (total > 0x100000)
                return;

        uint8_t *p = efi_fuzz_alloc(MAX3(size, total, (size_t) 40));
        memcpy(p, data, size);
        (void) fake_install_configuration_table(MAKE_GUID_PTR(EFI_DTB_TABLE), p);
}

void efi_fuzz_set_edid(const void *data, size_t size) {
        fw.edid = (EFI_EDID_DISCOVERED_PROTOCOL) {
                .SizeOfEdid = size,
                .Edid = size > 0 ? efi_fuzz_memdup(data, size) : NULL,
        };
        efi_fuzz_handle_install(efi_fuzz_handle_new(), MAKE_GUID_PTR(EFI_EDID_DISCOVERED_PROTOCOL),
                                &fw.edid);
}

static EFI_STATUS EFIAPI fake_rng_get_info(EFI_RNG_PROTOCOL *this, size_t *list_size, EFI_GUID *list) {
        return EFI_UNSUPPORTED;
}

static EFI_STATUS EFIAPI fake_rng_get_rng(
                EFI_RNG_PROTOCOL *this,
                EFI_GUID *algorithm,
                size_t length,
                uint8_t *value) {
        if (!value || length == 0)
                return EFI_INVALID_PARAMETER;
        if (fw.rng_size == 0)
                return EFI_DEVICE_ERROR;

        for (size_t i = 0; i < length; i++) {
                value[i] = fw.rng_data[fw.rng_pos];
                fw.rng_pos = (fw.rng_pos + 1) % fw.rng_size;
        }
        return EFI_SUCCESS;
}

void efi_fuzz_set_rng(const void *data, size_t size) {
        fw.rng_data = efi_fuzz_memdup(data, size);
        fw.rng_size = size;
        fw.rng_pos = 0;
        fw.rng = (EFI_RNG_PROTOCOL) {
                .GetInfo = fake_rng_get_info,
                .GetRNG = fake_rng_get_rng,
        };
        efi_fuzz_handle_install(efi_fuzz_handle_new(), MAKE_GUID_PTR(EFI_RNG_PROTOCOL), &fw.rng);
}

/* Graphics output: a small framebuffer in memory */

#define GOP_WIDTH 160U
#define GOP_HEIGHT 120U

static EFI_STATUS EFIAPI fake_gop_query_mode(
                EFI_GRAPHICS_OUTPUT_PROTOCOL *this,
                uint32_t mode_number,
                size_t *size_of_info,
                EFI_GRAPHICS_OUTPUT_MODE_INFORMATION **info) {

        if (!size_of_info || !info || mode_number != 0)
                return EFI_INVALID_PARAMETER;

        EFI_STATUS err = fake_allocate_pool(EfiBootServicesData, sizeof(fw.gop_info), (void**) info);
        if (err != EFI_SUCCESS)
                return err;

        **info = fw.gop_info;
        *size_of_info = sizeof(fw.gop_info);
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_gop_set_mode(EFI_GRAPHICS_OUTPUT_PROTOCOL *this, uint32_t mode_number) {
        return mode_number == 0 ? EFI_SUCCESS : EFI_UNSUPPORTED;
}

static EFI_STATUS EFIAPI fake_gop_blt(
                EFI_GRAPHICS_OUTPUT_PROTOCOL *this,
                EFI_GRAPHICS_OUTPUT_BLT_PIXEL *buffer,
                EFI_GRAPHICS_OUTPUT_BLT_OPERATION operation,
                size_t source_x,
                size_t source_y,
                size_t destination_x,
                size_t destination_y,
                size_t width,
                size_t height,
                size_t delta) {

        EFI_GRAPHICS_OUTPUT_BLT_PIXEL *fb = fw.framebuffer;

        if (width == 0 || height == 0)
                return EFI_INVALID_PARAMETER;

        /* Delta is the stride of the buffer in bytes, 0 means width pixels */
        size_t stride = delta == 0 ? width : delta / sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL);

        switch (operation) {

        case EfiBltVideoFill:
                if (!buffer || destination_x > GOP_WIDTH || width > GOP_WIDTH - destination_x ||
                    destination_y > GOP_HEIGHT || height > GOP_HEIGHT - destination_y)
                        return EFI_INVALID_PARAMETER;
                for (size_t y = 0; y < height; y++)
                        for (size_t x = 0; x < width; x++)
                                fb[(destination_y + y) * GOP_WIDTH + destination_x + x] = buffer[0];
                return EFI_SUCCESS;

        case EfiBltVideoToBltBuffer:
                if (!buffer || source_x > GOP_WIDTH || width > GOP_WIDTH - source_x ||
                    source_y > GOP_HEIGHT || height > GOP_HEIGHT - source_y || stride < width)
                        return EFI_INVALID_PARAMETER;
                for (size_t y = 0; y < height; y++)
                        for (size_t x = 0; x < width; x++)
                                buffer[(destination_y + y) * stride + destination_x + x] =
                                        fb[(source_y + y) * GOP_WIDTH + source_x + x];
                return EFI_SUCCESS;

        case EfiBltBufferToVideo:
                if (!buffer || destination_x > GOP_WIDTH || width > GOP_WIDTH - destination_x ||
                    destination_y > GOP_HEIGHT || height > GOP_HEIGHT - destination_y || stride < width)
                        return EFI_INVALID_PARAMETER;
                for (size_t y = 0; y < height; y++)
                        for (size_t x = 0; x < width; x++)
                                fb[(destination_y + y) * GOP_WIDTH + destination_x + x] =
                                        buffer[(source_y + y) * stride + source_x + x];
                return EFI_SUCCESS;

        case EfiBltVideoToVideo:
                if (source_x > GOP_WIDTH || width > GOP_WIDTH - source_x ||
                    source_y > GOP_HEIGHT || height > GOP_HEIGHT - source_y ||
                    destination_x > GOP_WIDTH || width > GOP_WIDTH - destination_x ||
                    destination_y > GOP_HEIGHT || height > GOP_HEIGHT - destination_y)
                        return EFI_INVALID_PARAMETER;
                for (size_t y = 0; y < height; y++)
                        memmove(fb + (destination_y + y) * GOP_WIDTH + destination_x,
                                fb + (source_y + y) * GOP_WIDTH + source_x,
                                width * sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL));
                return EFI_SUCCESS;

        default:
                return EFI_INVALID_PARAMETER;
        }
}

/* A TPM, which checks what is measured and discards it */

static EFI_STATUS EFIAPI fake_tcg2_get_capability(
                EFI_TCG2_PROTOCOL *this,
                EFI_TCG2_BOOT_SERVICE_CAPABILITY *capability) {

        if (!capability || capability->Size < sizeof(EFI_TCG2_BOOT_SERVICE_CAPABILITY))
                return EFI_INVALID_PARAMETER;

        *capability = (EFI_TCG2_BOOT_SERVICE_CAPABILITY) {
                .Size = sizeof(EFI_TCG2_BOOT_SERVICE_CAPABILITY),
                .StructureVersion = { 1, 1 },
                .ProtocolVersion = { 1, 1 },
                .HashAlgorithmBitmap = 0x6,
                .SupportedEventLogs = 0x3,
                .TPMPresentFlag = true,
                .NumberOfPCRBanks = 2,
                .ActivePcrBanks = 0x6,
        };
        return EFI_SUCCESS;
}

static void touch(const void *p, size_t n) {
        /* Let the sanitizers check that a range passed by sd-boot is valid. */
        if (n == 0)
                return;

        const volatile uint8_t *q = p;
        (void) q[0];
        (void) q[n - 1];
}

static EFI_STATUS EFIAPI fake_tcg2_hash_log_extend_event(
                EFI_TCG2_PROTOCOL *this,
                uint64_t flags,
                EFI_PHYSICAL_ADDRESS data_to_hash,
                uint64_t data_to_hash_len,
                EFI_TCG2_EVENT *event) {

        if (!event || event->Size < sizeof(EFI_TCG2_EVENT) ||
            event->Header.HeaderSize != sizeof(EFI_TCG2_EVENT_HEADER) || event->Header.PCRIndex > 23)
                return EFI_INVALID_PARAMETER;

        touch(event, event->Size);
        if (data_to_hash_len > 0) {
                if (data_to_hash == 0 || data_to_hash_len > SIZE_MAX)
                        return EFI_INVALID_PARAMETER;
                touch((const void*) (uintptr_t) data_to_hash, data_to_hash_len);
        }
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_tcg2_get_active_pcr_banks(
                EFI_TCG2_PROTOCOL *this,
                uint32_t *active_pcr_banks) {
        if (!active_pcr_banks)
                return EFI_INVALID_PARAMETER;
        *active_pcr_banks = 0x6; /* SHA1, SHA256 */
        return EFI_SUCCESS;
}

void efi_fuzz_set_tpm(bool b) {
        if (!b)
                return;

        fw.tcg2 = (EFI_TCG2_PROTOCOL) {
                .GetCapability = fake_tcg2_get_capability,
                .HashLogExtendEvent = fake_tcg2_hash_log_extend_event,
                .GetActivePcrBanks = fake_tcg2_get_active_pcr_banks,
        };
        efi_fuzz_handle_install(efi_fuzz_handle_new(), MAKE_GUID_PTR(EFI_TCG2_PROTOCOL), &fw.tcg2);
}

/* An initrd passed by the boot loader, see initrd_register() */

static EFI_STATUS EFIAPI fake_initrd_load_file(
                EFI_LOAD_FILE_PROTOCOL *this,
                EFI_DEVICE_PATH *file_path,
                bool boot_policy,
                size_t *buffer_size,
                void *buffer) {

        if (!this || !buffer_size || !file_path)
                return EFI_INVALID_PARAMETER;
        if (boot_policy)
                return EFI_UNSUPPORTED;
        if (!buffer || *buffer_size < fw.initrd_size) {
                *buffer_size = fw.initrd_size;
                return EFI_BUFFER_TOO_SMALL;
        }

        if (fw.initrd_size > 0)
                memcpy(buffer, fw.initrd, fw.initrd_size);
        *buffer_size = fw.initrd_size;
        return EFI_SUCCESS;
}

void efi_fuzz_set_previous_initrd(const void *data, size_t size) {
        static const struct {
                VENDOR_DEVICE_PATH vendor;
                EFI_DEVICE_PATH end;
        } _packed_ initrd_device_path = {
                .vendor = {
                        .Header = {
                                .Type = MEDIA_DEVICE_PATH,
                                .SubType = MEDIA_VENDOR_DP,
                                .Length = sizeof(initrd_device_path.vendor),
                        },
                        .Guid = GUID_DEF(0x5568e427, 0x68fc, 0x4f3d,
                                         0xac, 0x74, 0xca, 0x55, 0x52, 0x31, 0xcc, 0x68),
                },
                .end = {
                        .Type = END_DEVICE_PATH_TYPE,
                        .SubType = END_ENTIRE_DEVICE_PATH_SUBTYPE,
                        .Length = sizeof(initrd_device_path.end),
                },
        };

        fw.initrd = efi_fuzz_memdup(data, size);
        fw.initrd_size = size;
        fw.initrd_load_file = (EFI_LOAD_FILE2_PROTOCOL) {
                .LoadFile = fake_initrd_load_file,
        };

        EFI_HANDLE h = efi_fuzz_handle_new();
        efi_fuzz_handle_install(h, MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL), (void*) &initrd_device_path);
        efi_fuzz_handle_install(h, MAKE_GUID_PTR(EFI_LOAD_FILE2_PROTOCOL), &fw.initrd_load_file);
}

/* The EFI System Resource Table, which lists firmware updates and their status. */
void efi_fuzz_set_esrt(const void *data, size_t size) {
        size_t n = MIN(size / sizeof(EFI_SYSTEM_RESOURCE_ENTRY), (size_t) 64);
        EFI_SYSTEM_RESOURCE_TABLE *t = efi_fuzz_alloc(offsetof(EFI_SYSTEM_RESOURCE_TABLE, Entries) +
                                                      n * sizeof(EFI_SYSTEM_RESOURCE_ENTRY));

        /* The firmware is trusted to get the count right */
        t->FwResourceCount = t->FwResourceCountMax = n;
        t->FwResourceVersion = 1;
        if (n > 0)
                memcpy(t->Entries, data, n * sizeof(EFI_SYSTEM_RESOURCE_ENTRY));
        (void) fake_install_configuration_table(MAKE_GUID_PTR(EFI_SYSTEM_RESOURCE_TABLE), t);
}

/* vmm.c */

void efi_fuzz_set_confidential_vm(bool b) {
        fw.confidential_vm = b;
}

bool is_confidential_vm(void) {
        return fw.confidential_vm;
}

bool in_hypervisor(void) {
        return fw.confidential_vm || smbios_in_hypervisor();
}

bool is_direct_boot(EFI_HANDLE device) {
        return false;
}

EFI_STATUS vmm_open(EFI_HANDLE *ret_vmm_dev, EFI_FILE **ret_vmm_dir) {
        return EFI_NOT_FOUND;
}

/* Disks and device paths. Without a disk, the ESP's device path is just its partition node, as the
 * firmware's partition driver created it. With one, it is preceded by the disk's (PciRoot/Pci), and the
 * partitions in the disk's GPT get handles too, so that sd-boot can find the ESP and XBOOTLDR on it. */

static size_t disk_device_path(uint8_t *p) {
        /* PciRoot(0x0)/Pci(0x4,0x0) */
        static const uint8_t dp[] = {
                ACPI_DEVICE_PATH, ACPI_DP, 12, 0, 0xd0, 0x41, 0x03, 0x0a, 0, 0, 0, 0,
                HARDWARE_DEVICE_PATH, 1, 6, 0, 0, 4,
        };

        if (!fw.disk)
                return 0;
        if (p)
                memcpy(p, dp, sizeof(dp));
        return sizeof(dp);
}

static EFI_DEVICE_PATH* partition_device_path(const HARDDRIVE_DEVICE_PATH *hd, bool with_url) {
        size_t uri_size = 0, disk_size = disk_device_path(NULL);
        uint8_t *dp, *p;

        if (with_url && fw.boot_url)
                uri_size = MIN(offsetof(URI_DEVICE_PATH, Uri) + fw.boot_url_size, (size_t) UINT16_MAX);

        dp = p = efi_fuzz_alloc(uri_size + disk_size +
                                sizeof(HARDDRIVE_DEVICE_PATH) + sizeof(EFI_DEVICE_PATH));

        if (uri_size > 0) {
                URI_DEVICE_PATH *uri = (URI_DEVICE_PATH*) p;
                uri->Header = (EFI_DEVICE_PATH) {
                        .Type = MESSAGING_DEVICE_PATH,
                        .SubType = MSG_URI_DP,
                        .Length = uri_size,
                };
                memcpy(uri->Uri, fw.boot_url, uri_size - offsetof(URI_DEVICE_PATH, Uri));
                p += uri_size;
        }

        p += disk_device_path(p);
        memcpy(p, hd, sizeof(HARDDRIVE_DEVICE_PATH));
        p += sizeof(HARDDRIVE_DEVICE_PATH);
        *(EFI_DEVICE_PATH*) p = (EFI_DEVICE_PATH) {
                .Type = END_DEVICE_PATH_TYPE,
                .SubType = END_ENTIRE_DEVICE_PATH_SUBTYPE,
                .Length = sizeof(EFI_DEVICE_PATH),
        };
        return (EFI_DEVICE_PATH*) dp;
}

static void esp_update_device_path(void) {
        static const HARDDRIVE_DEVICE_PATH hd = {
                .Header = {
                        .Type = MEDIA_DEVICE_PATH,
                        .SubType = MEDIA_HARDDRIVE_DP,
                        .Length = sizeof(HARDDRIVE_DEVICE_PATH),
                },
                .PartitionNumber = 1,
                .PartitionStart = 2048,
                .PartitionSize = 1024 * 1024,
                .SignatureGuid = ESP_PARTITION_GUID,
                .MBRType = MBR_TYPE_EFI_PARTITION_TABLE_HEADER,
                .SignatureType = SIGNATURE_TYPE_GUID,
        };

        efi_fuzz_handle_install(fw.esp, MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL),
                                partition_device_path(&hd, /* with_url= */ true));
}

void efi_fuzz_set_boot_url(const void *url, size_t url_size) {
        /* Always with a scheme, host and path component, as sd-boot otherwise ends up with a "uki-url" entry
         * without URL and asserts when it is booted. */
        static const char prefix[] = "http://fuzz/boot/";
        size_t n = sizeof(prefix) - 1;

        url_size = MIN(url_size, (size_t) 4096);
        fw.boot_url = efi_fuzz_alloc(n + url_size);
        memcpy(fw.boot_url, prefix, n);
        if (url_size > 0)
                memcpy(fw.boot_url + n, url, url_size);
        fw.boot_url_size = n + url_size;
        esp_update_device_path();
}

static EFI_STATUS EFIAPI fake_block_io_reset(EFI_BLOCK_IO_PROTOCOL *this, bool extended_verification) {
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_block_io_read_blocks(
                EFI_BLOCK_IO_PROTOCOL *this,
                uint32_t media_id,
                EFI_LBA lba,
                size_t buffer_size,
                void *buffer) {

        BlockIo *b = (BlockIo*) this;

        if (!this || (buffer_size > 0 && !buffer))
                return EFI_INVALID_PARAMETER;
        if (media_id != b->media.MediaId)
                return EFI_MEDIA_CHANGED;
        if (buffer_size % b->media.BlockSize != 0)
                return EFI_BAD_BUFFER_SIZE;
        if (lba > b->media.LastBlock || buffer_size / b->media.BlockSize > b->media.LastBlock - lba + 1)
                return EFI_INVALID_PARAMETER;
        if (b != &fw.disk_block_io)
                return EFI_DEVICE_ERROR; /* Partitions have no contents of their own */

        uint64_t offset = lba * b->media.BlockSize;
        size_t n = offset < fw.disk_size ? MIN(buffer_size, fw.disk_size - (size_t) offset) : 0;
        if (n > 0)
                memcpy(buffer, fw.disk + offset, n);
        if (buffer_size > n)
                memset((uint8_t*) buffer + n, 0, buffer_size - n);
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_block_io_write_blocks(
                EFI_BLOCK_IO_PROTOCOL *this,
                uint32_t media_id,
                EFI_LBA lba,
                size_t buffer_size,
                void *buffer) {
        return EFI_WRITE_PROTECTED;
}

static EFI_STATUS EFIAPI fake_block_io_flush_blocks(EFI_BLOCK_IO_PROTOCOL *this) {
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_disk_io_read_disk(
                EFI_DISK_IO_PROTOCOL *this,
                uint32_t media_id,
                uint64_t offset,
                size_t buffer_size,
                void *buffer) {

        if (!this || (buffer_size > 0 && !buffer))
                return EFI_INVALID_PARAMETER;
        if (media_id != fw.disk_block_io.media.MediaId)
                return EFI_MEDIA_CHANGED;

        uint64_t disk_size = (fw.disk_last_block + 1) * fw.disk_block_io.media.BlockSize;
        if (offset > disk_size || buffer_size > disk_size - offset)
                return EFI_INVALID_PARAMETER;

        size_t n = offset < fw.disk_size ? MIN(buffer_size, fw.disk_size - (size_t) offset) : 0;
        if (n > 0)
                memcpy(buffer, fw.disk + offset, n);
        if (buffer_size > n)
                memset((uint8_t*) buffer + n, 0, buffer_size - n);
        return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI fake_disk_io_write_disk(
                EFI_DISK_IO_PROTOCOL *this,
                uint32_t media_id,
                uint64_t offset,
                size_t buffer_size,
                const void *buffer) {
        return EFI_WRITE_PROTECTED;
}

static void block_io_init(BlockIo *b, uint32_t media_id, bool logical_partition, EFI_LBA last_block) {
        assert(b);

        *b = (BlockIo) {
                .protocol = {
                        .Revision = 0x00020001,
                        .Reset = fake_block_io_reset,
                        .ReadBlocks = fake_block_io_read_blocks,
                        .WriteBlocks = fake_block_io_write_blocks,
                        .FlushBlocks = fake_block_io_flush_blocks,
                },
                .media = {
                        .MediaId = media_id,
                        .MediaPresent = true,
                        .LogicalPartition = logical_partition,
                        .BlockSize = 512,
                        .LastBlock = last_block,
                },
        };
        b->protocol.Media = (void*) &b->media;
}

/* Offsets in the GPT header */
#define GPT_HEADER_SIZE 12
#define GPT_HEADER_CRC32 16
#define GPT_ALTERNATE_LBA 32
#define GPT_ENTRY_LBA 72
#define GPT_N_ENTRIES 80
#define GPT_ENTRY_SIZE 84
#define GPT_ENTRY_CRC32 88

static uint64_t read_le64(const uint8_t *p) {
        return read_le(p, 4) | (uint64_t) read_le(p + 4, 4) << 32;
}

static void write_le32(uint8_t *p, uint32_t v) {
        for (size_t i = 0; i < 4; i++)
                p[i] = v >> (8 * i);
}

static bool gpt_entries(const uint8_t *header, size_t *ret_offset, size_t *ret_n, size_t *ret_entry_size) {
        assert(ret_offset);
        assert(ret_n);
        assert(ret_entry_size);

        uint64_t lba = read_le64(header + GPT_ENTRY_LBA);
        size_t n = read_le(header + GPT_N_ENTRIES, 4), entry_size = read_le(header + GPT_ENTRY_SIZE, 4);

        if (lba > fw.disk_size / 512 || entry_size < 128 || entry_size > 4096 || n > 1024 ||
            n * entry_size > fw.disk_size - lba * 512)
                return false;

        *ret_offset = lba * 512;
        *ret_n = n;
        *ret_entry_size = entry_size;
        return true;
}

static void gpt_fix_checksums(uint64_t lba) {
        /* Recalculates the checksums of the GPT header at the given LBA and of its partition entries, so
         * that the fuzzer doesn't need to. */
        if (lba > fw.disk_size / 512 - 1)
                return;

        uint8_t *h = fw.disk + lba * 512;
        size_t header_size = read_le(h + GPT_HEADER_SIZE, 4), offset, n, entry_size;
        if (memcmp(h, "EFI PART", 8) != 0 || header_size < 92 || header_size > 512)
                return;

        if (gpt_entries(h, &offset, &n, &entry_size))
                write_le32(h + GPT_ENTRY_CRC32, crc32_fw(fw.disk + offset, n * entry_size));

        write_le32(h + GPT_HEADER_CRC32, 0);
        write_le32(h + GPT_HEADER_CRC32, crc32_fw(h, header_size));
}

static void gpt_bound_entry_size(uint64_t lba) {
        /* sd-boot's read_gpt_entries() allocates what the GPT header says the entries take, and halts
         * (xmalloc()) if that fails, which it does for entry sizes of more than a few KiB. No real disk has
         * such entries, hence the fake disks don't either. */
        if (lba > fw.disk_size / 512 - 1)
                return;

        uint8_t *h = fw.disk + lba * 512;
        if (memcmp(h, "EFI PART", 8) == 0 && read_le(h + GPT_ENTRY_SIZE, 4) > 4096)
                write_le32(h + GPT_ENTRY_SIZE, 4096);
}

static void gpt_add_partitions(void) {
        static const EFI_GUID esp = ESP_TYPE_GUID, xbootldr = XBOOTLDR_TYPE_GUID;
        size_t offset, n, entry_size;

        /* Like the firmware's partition driver: creates a handle for each partition in the primary GPT,
         * with the ESP's or XBOOTLDR's file system if it is of that type. */
        if (fw.disk_size < 1024 || memcmp(fw.disk + 512, "EFI PART", 8) != 0 ||
            !gpt_entries(fw.disk + 512, &offset, &n, &entry_size))
                return;

        fw.partitions = efi_fuzz_alloc(MIN(n, (size_t) PARTITIONS_MAX) * sizeof(BlockIo));
        for (size_t i = 0; i < n && fw.n_partitions < PARTITIONS_MAX; i++) {
                const uint8_t *e = fw.disk + offset + i * entry_size;
                EFI_GUID type;
                memcpy(&type, e, sizeof(type));
                uint64_t start = read_le64(e + 32), end = read_le64(e + 40);

                static const EFI_GUID unused = {};
                if (guid_equal_fw(&type, &unused) || end < start || end > fw.disk_last_block)
                        continue;

                HARDDRIVE_DEVICE_PATH hd = {
                        .Header = {
                                .Type = MEDIA_DEVICE_PATH,
                                .SubType = MEDIA_HARDDRIVE_DP,
                                .Length = sizeof(HARDDRIVE_DEVICE_PATH),
                        },
                        .PartitionNumber = i + 1,
                        .PartitionStart = start,
                        .PartitionSize = end - start + 1,
                        .MBRType = MBR_TYPE_EFI_PARTITION_TABLE_HEADER,
                        .SignatureType = SIGNATURE_TYPE_GUID,
                };
                memcpy(hd.Signature, e + 16, sizeof(hd.Signature));

                BlockIo *b = &fw.partitions[fw.n_partitions++];
                block_io_init(b, 1, /* logical_partition= */ true, end - start);

                EFI_HANDLE h = efi_fuzz_handle_new();
                efi_fuzz_handle_install(h, MAKE_GUID_PTR(EFI_BLOCK_IO_PROTOCOL), b);
                efi_fuzz_handle_install(h, MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL),
                                        partition_device_path(&hd, /* with_url= */ false));
                if (guid_equal_fw(&type, &esp))
                        efi_fuzz_handle_install(h, MAKE_GUID_PTR(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL),
                                                &fw.esp_fs);
                else if (guid_equal_fw(&type, &xbootldr))
                        efi_fuzz_handle_install(h, MAKE_GUID_PTR(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL),
                                                &fw.xbootldr_fs);
        }
}

void efi_fuzz_set_disk(const void *data, size_t size, bool fix_checksums) {
        if (fw.disk || size > DISK_SIZE_MAX)
                return;

        fw.disk = efi_fuzz_memdup(data, size);
        fw.disk_size = size;
        /* At least the smallest GPT disk: protective MBR, header and 32 blocks of partition entries */
        fw.disk_last_block = MAX(size / 512, (size_t) 34) - 1;

        if (size >= 1024) {
                gpt_bound_entry_size(1);
                gpt_bound_entry_size(read_le64(fw.disk + 512 + GPT_ALTERNATE_LBA));
                gpt_bound_entry_size(fw.disk_last_block);
        }

        if (fix_checksums && size >= 1024) {
                gpt_fix_checksums(1);
                gpt_fix_checksums(read_le64(fw.disk + 512 + GPT_ALTERNATE_LBA));
                gpt_fix_checksums(fw.disk_last_block);
        }

        block_io_init(&fw.disk_block_io, 1, /* logical_partition= */ false, fw.disk_last_block);
        fw.disk_io = (EFI_DISK_IO_PROTOCOL) {
                .Revision = 0x00010000,
                .ReadDisk = fake_disk_io_read_disk,
                .WriteDisk = fake_disk_io_write_disk,
        };

        uint8_t *dp = efi_fuzz_alloc(disk_device_path(NULL) + sizeof(EFI_DEVICE_PATH));
        size_t n = disk_device_path(dp);
        *(EFI_DEVICE_PATH*) (dp + n) = (EFI_DEVICE_PATH) {
                .Type = END_DEVICE_PATH_TYPE,
                .SubType = END_ENTIRE_DEVICE_PATH_SUBTYPE,
                .Length = sizeof(EFI_DEVICE_PATH),
        };

        EFI_HANDLE h = efi_fuzz_handle_new();
        efi_fuzz_handle_install(h, MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL), dp);
        efi_fuzz_handle_install(h, MAKE_GUID_PTR(EFI_BLOCK_IO_PROTOCOL), &fw.disk_block_io);
        efi_fuzz_handle_install(h, MAKE_GUID_PTR(EFI_DISK_IO_PROTOCOL), &fw.disk_io);

        /* The ESP is on this disk now */
        block_io_init(&fw.esp_block_io, 1, /* logical_partition= */ true, 1024 * 1024 - 1);
        efi_fuzz_handle_install(fw.esp, MAKE_GUID_PTR(EFI_BLOCK_IO_PROTOCOL), &fw.esp_block_io);
        esp_update_device_path();

        gpt_add_partitions();
}

/* Setup and teardown */

/* Constant, since sd-boot's memcpy() and memset() use BS, and they replace libc's for all threads of the
 * fuzzer, which may call them at any time. */
static EFI_BOOT_SERVICES boot_services = {
        .Hdr.Revision = (2U << 16) | 70U,
        .Hdr.HeaderSize = sizeof(EFI_BOOT_SERVICES),
        .AllocatePages = fake_allocate_pages,
        .FreePages = fake_free_pages,
        .AllocatePool = fake_allocate_pool,
        .FreePool = fake_free_pool,
        .CreateEvent = fake_create_event,
        .SetTimer = fake_set_timer,
        .WaitForEvent = fake_wait_for_event,
        .CloseEvent = fake_close_event,
        .CheckEvent = fake_check_event,
        .ReinstallProtocolInterface = fake_reinstall_protocol_interface,
        .HandleProtocol = fake_handle_protocol,
        .LocateHandle = fake_locate_handle,
        .LocateDevicePath = fake_locate_device_path,
        .InstallConfigurationTable = fake_install_configuration_table,
        .LoadImage = fake_load_image,
        .StartImage = fake_start_image,
        .Exit = fake_exit,
        .UnloadImage = fake_unload_image,
        .GetNextMonotonicCount = fake_get_next_monotonic_count,
        .Stall = fake_stall,
        .SetWatchdogTimer = fake_set_watchdog_timer,
        .ConnectController = fake_connect_controller,
        .DisconnectController = fake_disconnect_controller,
        .OpenProtocol = fake_open_protocol,
        .CloseProtocol = fake_close_protocol,
        .ProtocolsPerHandle = fake_protocols_per_handle,
        .LocateHandleBuffer = fake_locate_handle_buffer,
        .LocateProtocol = fake_locate_protocol,
        .InstallMultipleProtocolInterfaces = fake_install_multiple_protocol_interfaces,
        .UninstallMultipleProtocolInterfaces = fake_uninstall_multiple_protocol_interfaces,
        .CalculateCrc32 = fake_calculate_crc32,
        .CopyMem = fake_copy_mem,
        .SetMem = fake_set_mem,
};

static EFI_RUNTIME_SERVICES runtime_services = {
        .Hdr.Revision = (2U << 16) | 70U,
        .Hdr.HeaderSize = sizeof(EFI_RUNTIME_SERVICES),
        .GetTime = fake_get_time,
        .SetTime = fake_set_time,
        .GetVariable = fake_get_variable,
        .GetNextVariableName = fake_get_next_variable_name,
        .SetVariable = fake_set_variable,
        .GetNextHighMonotonicCount = fake_get_next_high_monotonic_count,
        .ResetSystem = fake_reset_system,
        .UpdateCapsule = fake_update_capsule,
        .QueryCapsuleCapabilities = fake_query_capsule_capabilities,
};

static void firmware_free(void) {
        while (fw.files) {
                File *f = fw.files;
                fw.files = f->next;
                free(f);
        }

        if (fw.esp_fs.root)
                node_free(fw.esp_fs.root);
        if (fw.xbootldr_fs.root)
                node_free(fw.xbootldr_fs.root);
        while (fw.deleted) {
                Node *n = fw.deleted;
                fw.deleted = n->next;
                node_free(n);
        }

        while (fw.handles) {
                Handle *h = fw.handles;
                fw.handles = h->next;
                free(h);
        }

        while (fw.variables) {
                Variable *v = fw.variables;
                fw.variables = v->next;
                variable_free(v);
        }

        while (fw.pages) {
                PageAllocation *a = fw.pages;
                fw.pages = a->next;
                page_allocation_free(a);
        }

        for (size_t i = 0; i < POOL_BUCKETS; i++)
                while (fw.pool[i]) {
                        Allocation *a = fw.pool[i];
                        fw.pool[i] = a->next;
                        if (!lazy_free(a->p))
                                free(a->p);
                        free(a);
                }

        while (fw.images) {
                LoadedImage *l = fw.images;
                fw.images = l->next;
                free(l->memory);
                free(l);
        }

        while (fw.events) {
                Event *e = fw.events;
                fw.events = e->next;
                free(e);
        }

        while (fw.lazy) {
                Mapping *m = fw.lazy;
                fw.lazy = m->next;
                (void) munmap(m->p, m->size);
                free(m);
        }

        while (fw.mappings) {
                Mapping *m = fw.mappings;
                fw.mappings = m->next;
                (void) munmap(m->p, m->size);
                free(m);
        }
}

void efi_fuzz_firmware_reset(void) {
        if (fw.initialized)
                firmware_free();

        fw = (typeof(fw)) {
                .initialized = true,
        };

        fw.system_table = (EFI_SYSTEM_TABLE) {
                .Hdr.Revision = (2U << 16) | 70U,
                .Hdr.HeaderSize = sizeof(EFI_SYSTEM_TABLE),
                .FirmwareVendor = (char16_t*) u"systemd fuzzer",
                .FirmwareRevision = 1,
                .ConIn = &con_in,
                .ConOut = &con_out,
                .StdErr = &con_out,
                .RuntimeServices = &runtime_services,
                .BootServices = &boot_services,
                .ConfigurationTable = (void*) fw.config_tables,
        };

        console_line_len = 0;
        console_last_line[0] = 0;

        console_mode = (typeof(console_mode)) {
                .MaxMode = 1,
                .Attribute = EFI_TEXT_ATTR(EFI_LIGHTGRAY, EFI_BLACK),
        };

        fw.esp_fs = (FileSystem) {
                .protocol = {
                        .Revision = 0x00010000,
                        .OpenVolume = fake_open_volume,
                },
                .root = node_new(/* parent= */ NULL, u"", /* name_len= */ 0, /* directory= */ true),
        };
        fw.xbootldr_fs = fw.esp_fs;
        fw.xbootldr_fs.root = node_new(/* parent= */ NULL, u"", /* name_len= */ 0, /* directory= */ true);

        fw.esp = efi_fuzz_handle_new();
        efi_fuzz_handle_install(fw.esp, MAKE_GUID_PTR(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL), &fw.esp_fs);
        esp_update_device_path();

        fw.framebuffer = efi_fuzz_alloc(GOP_WIDTH * GOP_HEIGHT * sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL));
        fw.gop_info = (EFI_GRAPHICS_OUTPUT_MODE_INFORMATION) {
                .HorizontalResolution = GOP_WIDTH,
                .VerticalResolution = GOP_HEIGHT,
                .PixelFormat = PixelBlueGreenRedReserved8BitPerColor,
                .PixelsPerScanLine = GOP_WIDTH,
        };
        fw.gop_mode.MaxMode = 1;
        fw.gop_mode.Info = &fw.gop_info;
        fw.gop_mode.SizeOfInfo = sizeof(fw.gop_info);
        fw.gop_mode.FrameBufferBase = (uintptr_t) fw.framebuffer;
        fw.gop_mode.FrameBufferSize = GOP_WIDTH * GOP_HEIGHT * sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL);
        fw.gop = (EFI_GRAPHICS_OUTPUT_PROTOCOL) {
                .QueryMode = fake_gop_query_mode,
                .SetMode = fake_gop_set_mode,
                .Blt = fake_gop_blt,
                .Mode = (void*) &fw.gop_mode,
        };
        efi_fuzz_handle_install(efi_fuzz_handle_new(), MAKE_GUID_PTR(EFI_GRAPHICS_OUTPUT_PROTOCOL), &fw.gop);

        ST = &fw.system_table;
        BS = &boot_services;
        RT = &runtime_services;
}

/* Input records */

bool efi_fuzz_record_next(const uint8_t **data, size_t *size, EfiFuzzRecord *ret) {
        assert(data);
        assert(size);

        const uint8_t *p = *data;
        size_t left = *size;

        if (left == 0)
                return false;

        ret->type = (char) *p;
        p++, left--;

        size_t n = 0;
        while (n < left && n < ELEMENTSOF(ret->name) - 1 && p[n] != 0) {
                ret->name[n] = p[n];
                n++;
        }
        ret->name[n] = 0;
        p += n, left -= n;
        if (left > 0 && *p == 0)
                p++, left--;

        uint32_t len = 0;
        for (unsigned i = 0; i < 4 && left > 0; i++) {
                len |= (uint32_t) *p << (8 * i);
                p++, left--;
        }

        ret->data = p;
        ret->size = MIN((size_t) len, left);
        *data = p + ret->size;
        *size = left - ret->size;
        return true;
}

static const EFI_GUID* record_vendor(char type) {
        static const EFI_GUID loader = LOADER_VENDOR_GUID, global = EFI_GLOBAL_VARIABLE,
                systemd = SYSTEMD_VENDOR_GUID, image_security_database = EFI_IMAGE_SECURITY_DATABASE_GUID,
                shim = SHIM_LOCK_GUID, fwupdate = FWUPDATE_VENDOR_GUID;

        switch (type) {
        case 'v':
                return &loader;
        case 'g':
                return &global;
        case 'y':
                return &systemd;
        case 'i':
                return &image_security_database;
        case 'h':
                return &shim;
        case 'u':
                return &fwupdate;
        default:
                return NULL;
        }
}

bool efi_fuzz_record_apply(const EfiFuzzRecord *record) {
        const EFI_GUID *vendor;

        switch (record->type) {

        case 'f':
        case 'F':
                efi_fuzz_esp_add_file(record->name, record->data, record->size, record->type == 'F');
                return true;

        case 'd':
                efi_fuzz_esp_add_directory(record->name);
                return true;

        case 's':
        case 'S':
                efi_fuzz_set_smbios(record->data, record->size, record->type == 's');
                return true;

        case 't':
                efi_fuzz_set_devicetree(record->data, record->size);
                return true;

        case 'e':
                efi_fuzz_set_edid(record->data, record->size);
                return true;

        case 'r':
                efi_fuzz_set_rng(record->data, record->size);
                return true;

        case 'k':
                if (record->size > 0) {
                        efi_fuzz_set_load_images(FLAGS_SET(record->data[0], 0x01));
                        efi_fuzz_esp_set_read_only(FLAGS_SET(record->data[0], 0x02));
                        efi_fuzz_set_confidential_vm(FLAGS_SET(record->data[0], 0x04));
                        efi_fuzz_set_tpm(FLAGS_SET(record->data[0], 0x08));
                }
                return true;

        case 'K':
                efi_fuzz_set_keys(record->data, record->size);
                return true;

        case 'I':
                efi_fuzz_set_previous_initrd(record->data, record->size);
                return true;

        case 'U':
                efi_fuzz_set_boot_url(record->data, record->size);
                return true;

        case 'R':
                efi_fuzz_set_esrt(record->data, record->size);
                return true;

        case 'G':
                efi_fuzz_set_disk(record->data, record->size, /* fix_checksums= */ record->name[0] == 0);
                return true;

        case 'x':
        case 'X':
                efi_fuzz_xbootldr_add_file(record->name, record->data, record->size, record->type == 'X');
                return true;

        case 'b':
                /* Only accessible before ExitBootServices(), i.e. not written by the OS */
                (void) variable_set(record->name, record_vendor('v'),
                                    EFI_VARIABLE_NON_VOLATILE|EFI_VARIABLE_BOOTSERVICE_ACCESS,
                                    record->size, record->data);
                return true;

        default:
                vendor = record_vendor(record->type);
                if (!vendor)
                        return false;
                efi_fuzz_variable_set(vendor, record->name, record->data, record->size);
                return true;
        }
}
