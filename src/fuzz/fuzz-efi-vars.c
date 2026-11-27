/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Fuzz target for the code that reads EFI variables from efivarfs. The variables are written by the
 * firmware and the boot loader, and Boot#### and BootOrder also by anyone with access to the firmware setup.
 * They are files in a private directory, which $SYSTEMD_EFIVARFS_PATH points to.
 *
 * Bit 1 of byte 0 selects the mode:
 *
 *   clear: the rest of the input is the value of one variable (without the efivarfs attribute header), read
 *          by its getter. Bit 0 selects the variable: Boot0000 (efi_get_boot_option()) or LoaderEntries
 *          (efi_loader_get_entries()).
 *
 *   set:   the rest of the input is a list of variables, which are written to the directory, and then all
 *          readers are called: efivars.c (efi_get_variable() and its string/path variants, Secure Boot
 *          flags), efi-api.c (boot option enumeration, BootOrder, Boot####, OsIndications, PCR banks),
 *          efi-loader.c (boot timestamps, partition UUIDs, features, one-shot timeout and entry,
 *          measurement), and their users in libshared: bootspec's selection of the default and selected
 *          entry, boot_timestamps(), factory_reset_mode(), locale_lang_from_efi() and
 *          vconsole_keymap_from_efi(). Each variable is:
 *
 *            u8 name    index into variables[] below (modulo its size). Index 0 is Boot####: it is followed
 *                       by the 4 characters of ####.
 *            u16 size   little-endian, clamped to what is left of the input
 *            contents   the efivarfs file: 4 bytes of attributes, then the value
 *
 * Some of the readers cache their result in static variables for the lifetime of the process (Secure Boot
 * state, loader and stub features, PCR banks, ...), so only the first input of a process reaches them. */

#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "boot-timestamps.h"
#include "bootspec.h"
#include "efi-api.h"
#include "efi-loader.h"
#include "efivars.h"
#include "factory-reset.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "fuzz.h"
#include "fuzz-network.h"
#include "io-util.h"
#include "locale-setup.h"
#include "path-util.h"
#include "rm-rf.h"
#include "strv.h"
#include "tests.h"
#include "time-util.h"
#include "tmpfile-util.h"
#include "unaligned.h"
#include "vconsole-util.h"

static const char *const variables[] = {
        NULL, /* Boot#### */
        EFI_GLOBAL_VARIABLE_STR("BootOrder"),
        EFI_GLOBAL_VARIABLE_STR("OsIndicationsSupported"),
        EFI_GLOBAL_VARIABLE_STR("OsIndications"),
        EFI_GLOBAL_VARIABLE_STR("SecureBoot"),
        EFI_GLOBAL_VARIABLE_STR("AuditMode"),
        EFI_GLOBAL_VARIABLE_STR("DeployedMode"),
        EFI_GLOBAL_VARIABLE_STR("SetupMode"),
        EFI_GLOBAL_VARIABLE_STR("PlatformLang"),
        EFI_SHIMLOCK_VARIABLE_STR("MokSBStateRT"),
        EFI_LOADER_VARIABLE_STR("LoaderEntries"),
        EFI_LOADER_VARIABLE_STR("LoaderTimeInitUSec"),
        EFI_LOADER_VARIABLE_STR("LoaderTimeExecUSec"),
        EFI_LOADER_VARIABLE_STR("LoaderDevicePartUUID"),
        EFI_LOADER_VARIABLE_STR("StubDevicePartUUID"),
        EFI_LOADER_VARIABLE_STR("LoaderFeatures"),
        EFI_LOADER_VARIABLE_STR("LoaderInfo"),
        EFI_LOADER_VARIABLE_STR("StubFeatures"),
        EFI_LOADER_VARIABLE_STR("StubInfo"),
        EFI_LOADER_VARIABLE_STR("StubPcrKernelImage"),
        EFI_LOADER_VARIABLE_STR("LoaderPcrSMBIOS"),
        EFI_LOADER_VARIABLE_STR("LoaderConfigTimeoutOneShot"),
        EFI_LOADER_VARIABLE_STR("LoaderEntryOneShot"),
        EFI_LOADER_VARIABLE_STR("LoaderEntryPreferred"),
        EFI_LOADER_VARIABLE_STR("LoaderEntryDefault"),
        EFI_LOADER_VARIABLE_STR("LoaderEntrySelected"),
        EFI_LOADER_VARIABLE_STR("LoaderEntrySysFail"),
        EFI_LOADER_VARIABLE_STR("LoaderTpm2ActivePcrBanks"),
        EFI_LOADER_VARIABLE_STR("LoaderKeyboardLayout"),
        EFI_LOADER_VARIABLE_STR("LoaderImageIdentifier"),
        EFI_SYSTEMD_VARIABLE_STR("FactoryResetRequest"),
};

/* A few rows of src/locale/kbd-model-map, with the BCP 47 tags that vconsole_keymap_from_efi() matches */
static const char kbd_model_map[] =
        "# SPDX-License-Identifier: LGPL-2.1-or-later\n"
        "us\tus\tpc105\t-\tterminate:ctrl_alt_bksp\ten-US,en\n"
        "uk\tgb\tpc105\t-\tterminate:ctrl_alt_bksp\ten-GB\n"
        "de\tde\tpc105\t-\tterminate:ctrl_alt_bksp\tde-DE,de-AT,de\n"
        "sg\tch\tpc105\tde_nodeadkeys\tterminate:ctrl_alt_bksp\tde-CH\n"
        "nl\tnl\tpc105\t-\tterminate:ctrl_alt_bksp\tnl-NL,nl\n"
        "mk-utf\tmk,us\tpc105\t-\tterminate:ctrl_alt_bksp,grp:shifts_toggle\tmk-MK,mk\n"
        "fr\tfr\tpc105\t-\tterminate:ctrl_alt_bksp\t-\n";

static char *private_dir = NULL;
static int efivars_fd = -EBADF;

static void cleanup_private_dir(void) {
        efivars_fd = safe_close(efivars_fd);
        private_dir = rm_rf_physical_and_free(private_dir);
}

static void setup(void) {
        _cleanup_free_ char *efivars = NULL, *map = NULL;

        ASSERT_OK(mkdtemp_malloc("/tmp/fuzz-efi-vars-XXXXXX", &private_dir));
        ASSERT_EQ(atexit(cleanup_private_dir), 0);

        efivars = ASSERT_NOT_NULL(path_join(private_dir, "efivars"));
        efivars_fd = ASSERT_OK(open_mkdir(efivars, O_CLOEXEC, 0755));
        ASSERT_OK_ERRNO(setenv("SYSTEMD_EFIVARFS_PATH", efivars, /* overwrite= */ true));

        map = ASSERT_NOT_NULL(path_join(private_dir, "kbd-model-map"));
        ASSERT_OK(write_string_file(map, kbd_model_map, WRITE_STRING_FILE_CREATE));
        ASSERT_OK_ERRNO(setenv("SYSTEMD_KBD_MODEL_MAP", map, /* overwrite= */ true));

        /* Otherwise the readers check for /sys/firmware/efi/ */
        set_efi_boot(true);
}

static void write_variables(const uint8_t *data, size_t size) {
        while (size >= 3) {
                char boot[] = EFI_GLOBAL_VARIABLE_STR("Boot####");
                _cleanup_close_ int fd = -EBADF;
                uint8_t idx = data[0] % ELEMENTSOF(variables);
                const char *name;
                size_t n;

                data++, size--;

                if (idx == 0) {
                        if (size < 4 + 2)
                                return;

                        /* Anything but '/' and NUL, so that boot_id_hex() sees odd characters too */
                        for (size_t i = 0; i < 4; i++)
                                boot[STRLEN("Boot") + i] = IN_SET(data[i], 0, '/') ? 'x' : (char) data[i];

                        name = boot;
                        data += 4, size -= 4;
                } else
                        name = variables[idx];

                n = MIN((size_t) unaligned_read_le16(data), size - 2);
                data += 2, size -= 2;

                fd = ASSERT_OK(xopenat_full(efivars_fd, name, O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW,
                                            /* xopen_flags= */ 0, 0644));
                ASSERT_OK(loop_write(fd, data, n));

                data += n, size -= n;
        }
}

static void call_efi_api(void) {
        _cleanup_free_ uint16_t *options = NULL, *order = NULL;
        int n_options, n_order;
        uint32_t banks;

        /* Like bootctl status: list the Boot#### variables, then show them in BootOrder order */
        n_options = efi_get_boot_options(&options);
        n_order = efi_get_boot_order(&order);

        for (int i = 0; i < n_options; i++) {
                _cleanup_free_ char *title = NULL, *path = NULL;
                sd_id128_t part_uuid;
                bool active;

                (void) efi_get_boot_option(options[i], &title, &part_uuid, &path, &active);
        }
        for (int i = 0; i < n_order; i++) {
                _cleanup_free_ char *title = NULL;

                (void) efi_get_boot_option(order[i], &title, /* ret_part_uuid= */ NULL, /* ret_path= */ NULL,
                                           /* ret_active= */ NULL);
        }

        (void) efi_get_reboot_to_firmware();
        (void) efi_get_active_pcr_banks(&banks);
        (void) efi_has_tpm2();
}

static void call_efi_loader(void) {
        /* A fixed "now", so that every run of an input computes the same timestamps */
        dual_timestamp n = { .realtime = 1700000000 * USEC_PER_SEC, .monotonic = 5 * USEC_PER_SEC };
        dual_timestamp firmware_ts, loader_ts;
        _cleanup_free_ char *oneshot = NULL, *image = NULL;
        struct stat oneshot_stat = {};
        usec_t firmware, loader, timeout;
        uint64_t features;
        sd_id128_t uuid;

        (void) efi_loader_get_boot_usec(&firmware, &loader);
        (void) boot_timestamps(&n, &firmware_ts, &loader_ts);

        (void) efi_loader_get_device_part_uuid(&uuid);
        (void) efi_stub_get_device_part_uuid(&uuid);

        (void) efi_loader_get_features(&features);
        (void) efi_stub_get_features(&features);

        (void) efi_measured_uki(LOG_DEBUG);
        (void) efi_measured_os(LOG_DEBUG);
        (void) efi_measured_smbios(LOG_DEBUG);

        (void) efi_loader_get_config_timeout_one_shot(&timeout);
        (void) efi_loader_update_entry_one_shot_cache(&oneshot, &oneshot_stat);
        (void) efi_get_variable_path(EFI_LOADER_VARIABLE_STR("LoaderImageIdentifier"), &image);

        DO_NOT_OPTIMIZE(is_efi_secure_boot());
        DO_NOT_OPTIMIZE(efi_get_secure_boot_mode());
}

static void call_users(void) {
        _cleanup_(boot_config_free) BootConfig config = BOOT_CONFIG_NULL;
        _cleanup_free_ char *lang = NULL, *lang_no_en = NULL, *keymap = NULL;
        _cleanup_strv_free_ char **entries = NULL;

        /* Like bootctl list and logind: the entries the boot loader reported, plus the EFI variables that
         * point at the default, selected, one-shot … entries */
        if (efi_loader_get_entries(&entries) >= 0)
                (void) boot_config_augment_from_loader(&config, entries, /* auto_only= */ false);
        (void) boot_config_select_special_entries(&config, /* skip_efivars= */ false);
        DO_NOT_OPTIMIZE(boot_config_default_entry(&config));

        DO_NOT_OPTIMIZE(factory_reset_mode());

        (void) locale_lang_from_efi(&lang, /* flags= */ 0);
        (void) locale_lang_from_efi(&lang_no_en, LOCALE_SUPPRESS_EN_US);
        (void) vconsole_keymap_from_efi(&keymap);
}

static void clear_variables(void) {
        int fd;

        /* rm_rf_children() takes ownership of the fd */
        fd = ASSERT_OK_ERRNO(fcntl(efivars_fd, F_DUPFD_CLOEXEC, 3));
        ASSERT_OK(rm_rf_children(fd, REMOVE_PHYSICAL, /* root_dev= */ NULL));
}

static void fuzz_efivarfs(const uint8_t *data, size_t size) {
        write_variables(data, size);

        call_efi_api();
        call_efi_loader();
        call_users();

        clear_variables();
}

static void fuzz_one_variable(bool loader_entries, const uint8_t *data, size_t size) {
        uint32_t attr =
                EFI_VARIABLE_NON_VOLATILE|EFI_VARIABLE_BOOTSERVICE_ACCESS|EFI_VARIABLE_RUNTIME_ACCESS;
        _cleanup_close_ int fd = -EBADF;
        const char *name;

        name = loader_entries ? EFI_LOADER_VARIABLE_STR("LoaderEntries") :
                                EFI_GLOBAL_VARIABLE_STR("Boot0000");
        fd = ASSERT_OK(xopenat_full(efivars_fd, name, O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW,
                                    /* xopen_flags= */ 0, 0644));
        ASSERT_OK(loop_write(fd, &attr, sizeof(attr)));
        ASSERT_OK(loop_write(fd, data, size));
        fd = safe_close(fd);

        if (loader_entries) {
                _cleanup_strv_free_ char **entries = NULL;

                (void) efi_loader_get_entries(&entries);
        } else {
                _cleanup_free_ char *title = NULL, *path = NULL;
                sd_id128_t part_uuid;
                bool active;

                (void) efi_get_boot_option(/* id= */ 0, &title, &part_uuid, &path, &active);
        }

        clear_variables();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        if (outside_size_range(size, /* lower= */ 1, 65536))
                return 0;

        fuzz_forbid_network();
        fuzz_setup_logging();

        if (!private_dir)
                setup();

        if (FLAGS_SET(data[0], 1 << 1))
                fuzz_efivarfs(data + 1, size - 1);
        else
                fuzz_one_variable(/* loader_entries= */ FLAGS_SET(data[0], 1 << 0), data + 1, size - 1);

        return 0;
}
