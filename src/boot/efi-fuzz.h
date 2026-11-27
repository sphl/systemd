/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Interface of the fake UEFI firmware (efi-fuzz-firmware.c) that the sd-boot/sd-stub fuzzers run on. The
 * fuzzers are built as EFI code (SD_BOOT=1), the fake firmware as regular userspace code, hence this header
 * only uses EFI types.
 *
 * The fake firmware never starts images, has no network, and keeps everything (files, disks, variables,
 * configuration tables, a small framebuffer) in memory. ST, BS and RT point to it after
 * efi_fuzz_firmware_reset(). */

#include "efi.h"
#include "proto/file-io.h"

/* The entry point into the fuzzer */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* outside_size_range() from src/fuzz/fuzz.h and fuzz_forbid_network() from src/fuzz/fuzz-network.h, which
 * EFI code can't include. */
bool efi_fuzz_outside_size_range(size_t size, size_t lower, size_t upper);
void efi_fuzz_forbid_network(void);

/* Releases everything set up for the previous input, and installs a fresh fake firmware: an empty ESP, no
 * EFI variables, no configuration tables and no protocols other than the ESP's. */
void efi_fuzz_firmware_reset(void);

/* Memory that lives until the next efi_fuzz_firmware_reset(). */
void* efi_fuzz_alloc(size_t size);
void* efi_fuzz_memdup(const void *data, size_t size);

/* Handles and protocols. LocateProtocol() and LocateHandleBuffer() search all handles. */
EFI_HANDLE efi_fuzz_handle_new(void);
void efi_fuzz_handle_install(EFI_HANDLE handle, const EFI_GUID *guid, void *interface);

/* The ESP: a handle with the simple file system and device path protocols, backed by an in-memory,
 * case-insensitive file system. Paths use '\' (or '/') as separator, parent directories are created as
 * needed. */
EFI_HANDLE efi_fuzz_esp_handle(void);
EFI_FILE* efi_fuzz_esp_open_root(void);
void efi_fuzz_esp_add_file(const char16_t *path, const void *data, size_t size, bool read_only);
void efi_fuzz_esp_add_directory(const char16_t *path);
void efi_fuzz_esp_set_read_only(bool b);

/* Makes the ESP look like it was booted from the given URL (HTTP boot), appended to "http://fuzz/boot/". */
void efi_fuzz_set_boot_url(const void *url, size_t url_size);

/* The file system on the XBOOTLDR partition, which is only found if it is in the GPT of the disk. */
void efi_fuzz_xbootldr_add_file(const char16_t *path, const void *data, size_t size, bool read_only);

/* Puts the ESP on a disk with the given contents (512 byte blocks), and creates handles for the
 * partitions in its GPT. Optionally fixes up the GPT checksums. */
void efi_fuzz_set_disk(const void *data, size_t size, bool fix_checksums);

/* A device path consisting of a single file path node for the given path. */
EFI_DEVICE_PATH* efi_fuzz_file_device_path(const char16_t *path);

/* EFI variables. */
void efi_fuzz_variable_set(const EFI_GUID *vendor, const char16_t *name, const void *data, size_t size);

/* The firmware's SMBIOS tables (the structures, without entry point), devicetree and EDID. */
void efi_fuzz_set_smbios(const void *data, size_t size, bool smbios3);
void efi_fuzz_set_devicetree(const void *data, size_t size);
void efi_fuzz_set_edid(const void *data, size_t size);
/* Installs an RNG protocol that returns the given bytes (repeated). */
void efi_fuzz_set_rng(const void *data, size_t size);
/* The EFI System Resource Table, the data are its entries. */
void efi_fuzz_set_esrt(const void *data, size_t size);
/* An initrd registered by the boot loader for the kernel (LINUX_INITRD_MEDIA). */
void efi_fuzz_set_previous_initrd(const void *data, size_t size);

/* Replaces vmm.c. */
void efi_fuzz_set_confidential_vm(bool b);

/* Installs a TPM, that checks the measured data is accessible, and discards it. */
void efi_fuzz_set_tpm(bool b);

/* Whether LoadImage() succeeds. Either way, StartImage() never runs anything. */
void efi_fuzz_set_load_images(bool b);

/* Lays out a PE image in memory, like LoadImage() does. Returns NULL if that's not possible. */
uint8_t* efi_fuzz_pe_load(const void *data, size_t size, size_t *ret_size);

/* Keyboard input, as pairs of 16-bit little-endian scan code and character. Once they are used up, waiting
 * for a key fails (after a few timer events, if a timer is waited for too). */
void efi_fuzz_set_keys(const void *data, size_t size);

/* Calls func(userdata) and returns false, or true if it reset the system. */
bool efi_fuzz_run(void (*func)(void *userdata), void *userdata);

/* Most fuzzers take a sequence of records as input:
 *     type (1 byte) | name (NUL-terminated, at most 255 bytes) | size (32-bit LE) | data
 * where size is clamped to the remaining input. Records of these types are handled by
 * efi_fuzz_record_apply():
 *     'f'/'F'  file on the ESP (name is the path, 'F' marks it read-only)
 *     'd'      directory on the ESP
 *     'v'/'g'/'y'  EFI variable of the loader/global/systemd vendor
 *     'i'/'h'/'u'  EFI variable of the image security database/shim/fwupd vendor
 *     'b'      EFI variable of the loader vendor, only accessible to boot services
 *     'x'/'X'  file on the XBOOTLDR partition ('X' read-only)
 *     'G'      disk contents, with fixed up GPT checksums unless the name is non-empty
 *     's'/'S'  SMBIOS tables, with a 3.0 ('s') or 2.1 ('S') entry point
 *     't'      devicetree passed by the firmware
 *     'e'      EDID of the display
 *     'r'      RNG protocol output
 *     'K'      keyboard input, see efi_fuzz_set_keys()
 *     'I'      initrd registered by the boot loader
 *     'U'      URL the ESP was booted from (appended to "http://fuzz/boot/")
 *     'R'      entries of the EFI System Resource Table
 *     'k'      flags: 0x01 LoadImage() succeeds, 0x02 read-only ESP, 0x04 confidential VM, 0x08 TPM
 * Bytes of names are taken as Latin-1, '/' is a path separator too for files and directories. */
typedef struct EfiFuzzRecord {
        char type;
        char16_t name[256];
        const uint8_t *data;
        size_t size;
} EfiFuzzRecord;

bool efi_fuzz_record_next(const uint8_t **data, size_t *size, EfiFuzzRecord *ret);
bool efi_fuzz_record_apply(const EfiFuzzRecord *record);
