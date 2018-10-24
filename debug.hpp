#pragma once
#include <switch.h>
#include <inttypes.h>
#include <cstring>

static void LogStr2(const char *str) {
    (void)(str);
    u8 backup[0x100];
    memcpy(backup, armGetTls(), 0x100);
    FILE *file = fopen("sdmc:/space.log", "ab+");
    fwrite(str, 1, strlen(str), file);
    fclose(file);
    memcpy(armGetTls(), backup, 0x100);
}
