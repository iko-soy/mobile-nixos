/* SPDX-License-Identifier: MIT */
#include "guard.h"

#include <stdio.h>

int main(int argc, char **argv)
{
    (void) argv;
    if (argc != 1) {
        fputs("TITAN_SOURCE_REFUSED arguments\n", stderr);
        return 2;
    }
    struct titan_source source = TITAN_SOURCE_INITIALIZER;
    const char *reason = "state-invalid";
    int result = titan_source_open(&source, &reason);
    if (result == 0)
        result = titan_source_recheck(&source, &reason);
    titan_source_close(&source);
    if (result != 0) {
        printf("TITAN_SOURCE_FAIL %s\n", reason);
        return 1;
    }
    puts("TITAN_SOURCE_PASS");
    return 0;
}
