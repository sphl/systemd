/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Fuzzes systemd-boot with the contents of the ESP: loader.conf, Type #1 entries (including boot counting
 * in their file names), Type #2 entries (UKIs and their profiles), the Windows BCD, Secure Boot keys to
 * enroll, drivers, the random seed and fwupd capsules, together with EFI variables, SMBIOS OEM strings
 * and keyboard input for the menu. It runs the boot loader's main function on the fake firmware, which never
 * starts any image (see efi-fuzz.h).
 *
 * The input is a sequence of records (see efi-fuzz.h). The name of an 'l' record is the path of
 * systemd-boot's own image on the ESP. */

#include "boot.c"
#include "efi-fuzz.h"

/* run() is what efi_main() calls once it has set ST, BS and RT, which efi_fuzz_firmware_reset() does here.
 * The rest of efi_main() (stack protector setup, debugger notification, waiting for the user to read log
 * messages) has no place in a fuzzer. */
static void run_boot_loader(void *userdata) {
        (void) run(userdata);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        if (efi_fuzz_outside_size_range(size, /* lower= */ 0, 1024 * 1024))
                return 0;

        efi_fuzz_forbid_network();
        efi_fuzz_firmware_reset();

        /* loader.conf may change the log level, start over for every input */
        log_set_max_level(LOG_INFO);

        char16_t image_path[256] = u"\\EFI\\systemd\\systemd-boot" EFI_MACHINE_TYPE_NAME ".efi";
        EfiFuzzRecord r;
        assert_cc(sizeof(image_path) == sizeof(r.name));
        while (efi_fuzz_record_next(&data, &size, &r))
                if (r.type == 'l')
                        memcpy(image_path, r.name, sizeof(r.name));
                else
                        (void) efi_fuzz_record_apply(&r);

        /* systemd-boot itself */
        static const uint8_t image[] = { 'M', 'Z' };
        EFI_LOADED_IMAGE_PROTOCOL loaded_image = {
                .Revision = 0x1000,
                .SystemTable = ST,
                .DeviceHandle = efi_fuzz_esp_handle(),
                .FilePath = efi_fuzz_file_device_path(image_path),
                .ImageBase = (void*) image,
                .ImageSize = sizeof(image),
                .ImageCodeType = EfiLoaderCode,
                .ImageDataType = EfiLoaderData,
        };
        EFI_HANDLE handle = efi_fuzz_handle_new();
        efi_fuzz_handle_install(handle, MAKE_GUID_PTR(EFI_LOADED_IMAGE_PROTOCOL), &loaded_image);

        (void) efi_fuzz_run(run_boot_loader, handle);

        efi_fuzz_firmware_reset();
        return 0;
}
