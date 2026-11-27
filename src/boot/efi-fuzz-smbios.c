/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* smbios.c for the sd-boot fuzzers. smbios_raw_info_get_cached() keeps pointers into the SMBIOS tables of
 * the first input, which are gone when the next input is processed, hence parse the tables every time. */

#define smbios_raw_info_get_cached smbios_raw_info_get_cached_unused
#include "smbios.c"
#undef smbios_raw_info_get_cached

void smbios_raw_info_get_cached(RawSmbiosInfo *ret_info);

void smbios_raw_info_get_cached(RawSmbiosInfo *ret_info) {
        smbios_raw_info_populate(ret_info);
}
