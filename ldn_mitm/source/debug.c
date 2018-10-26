/*
 * Copyright (c) 2018 Atmosphère-NX
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
 
#include <switch.h>
#include <string.h>
#include <stdio.h>
#include "debug.h"

const size_t TlsBackupSize = 0x100;
#define BACKUP_TLS() u8 _tls_backup[TlsBackupSize];memcpy(_tls_backup, armGetTls(), TlsBackupSize);
#define RESTORE_TLS() memcpy(armGetTls(), _tls_backup, TlsBackupSize);

#define MIN(a, b) (((a) > (b)) ? (b) : (a))
void Reboot() {
    /* ... */
    LogStr("Reboot\n");
}

void Log(const void *data, int size) {
    (void)(data);
    (void)(size);
    /* ... */
#if 0
    LogHex(data, size);
#endif
}

void LogHex(const void *data, int size) {
    (void)(data);
    (void)(size);
    /* ... */
    u8 *dat = (u8 *)data;
    char buf[128];
    sprintf(buf, "Bin Log: %d (%p)\n", size, data);
    LogStr(buf);
    for (int i = 0; i < size; i += 16) {
        int s = MIN(size - i, 16);
        buf[0] = 0;
        for (int j = 0; j < s; j++) {
            sprintf(buf + strlen(buf), "%02x", dat[i + j]);
        }
        sprintf(buf + strlen(buf), "\n");
        LogStr(buf);
    }
}

void LogStr(const char *str) {
    (void)(str);
    BACKUP_TLS();
    FILE *file = fopen("sdmc:/space.log", "ab+");
    fwrite(str, 1, strlen(str), file);
    fclose(file);
    RESTORE_TLS();
}


struct fatalLaterIpc
{
    u64 magic;
    u64 cmd_id;
    u64 result;
    u64 unknown;
};
void fatalLater(Result err)
{
    Handle srv;

    while (R_FAILED(smGetServiceOriginal(&srv, smEncodeName("fatal:u"))))
    {
        // wait one sec and retry
        svcSleepThread(1000000000L);
    }

    // fatal is here time, fatal like a boss
    IpcCommand c;
    ipcInitialize(&c);
    ipcSendPid(&c);

    struct fatalLaterIpc* raw;

    raw = (struct fatalLaterIpc*) ipcPrepareHeader(&c, sizeof(*raw));

    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 1;
    raw->result = err;
    raw->unknown = 0;

    ipcDispatch(srv);
    svcCloseHandle(srv);
}
bool GetCurrentTime(u64 *out) {
    BACKUP_TLS();
    *out = 0;
    
    /* Verify that pcv isn't dead. */
    {
        Handle dummy;
        if (R_SUCCEEDED(smRegisterService(&dummy, "time:s", false, 0x20))) {
            svcCloseHandle(dummy);
            return false;
        }
    }
    
    /* Try to get the current time. */
    bool success = false;
    if (R_SUCCEEDED(timeInitialize())) {
        if (R_SUCCEEDED(timeGetCurrentTime(TimeType_LocalSystemClock, out))) {
            success = true;
        }
        timeExit();
    }

    RESTORE_TLS();
    return success;
}
