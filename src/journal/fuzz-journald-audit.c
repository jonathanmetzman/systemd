/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fuzz.h"
#include "fuzz-journald.h"
#include "journald-audit.h"

#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        Server s;

        uint8_t* array = (uint8_t*) calloc(10, 1);
        free(array);
        dummy_server_init(&s, data, size);
        process_audit_string(&s, 0, s.buffer, size);
        server_done(&s);

        return array[0];
}
