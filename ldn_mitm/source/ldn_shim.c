#include "ldn_shim.h"
#include "debug.h"
#include <string.h>

void NetworkInfo2NetworkConfig(NetworkInfo* info, NetworkConfig* out) {
    out->intentId = info->networkId.intentId;
    out->channel = info->common.channel;
    out->nodeCountMax = info->ldn.nodeCountMax;
    out->localCommunicationVersion = 1;
}

void NetworkInfo2SecurityParameter(NetworkInfo* info, SecurityParameter* out) {
    out->sessionId = info->networkId.sessionId;
    memcpy(out->unkRandom, info->ldn.unkRandom, 16);
}

Result ldnScan(UserLocalCommunicationService* s, u16 channel, void* unk2, u16* unkOut, void* outBuf) {
    IpcCommand c;
    ipcInitialize(&c);
    struct {
        u64 magic;
        u64 cmd_id;
        u16 channel;
        u8 unk2[0x60];
    } *raw;
    ipcAddRecvBuffer(&c, outBuf, 0x6c00, BufferType_Normal);
    ipcAddRecvStatic(&c, 0, 0, BufferType_Normal);
    raw = serviceIpcPrepareHeader(&s->s, &c, sizeof(*raw));
    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 102;
    raw->channel = channel;
    memcpy(raw->unk2, unk2, 0x60);
    LogStr("debug1\n");
    LogHex(armGetTls(), 0x100);

    Result rc = serviceIpcDispatch(&s->s);

    if (R_SUCCEEDED(rc)) {
        IpcParsedCommand r;
        struct {
            u64 magic;
            u64 result;
            u16 unk;
        } *resp;
        serviceIpcParse(&s->s, &r, sizeof(*resp));
        resp = r.Raw;

        rc = resp->result;
        *unkOut = resp->unk;
    }

    return rc;
}

Result ldnGetNetworkInfo(UserLocalCommunicationService* s, void* out) {
    IpcCommand c;
    ipcInitialize(&c);
    struct {
        u64 magic;
        u64 cmd_id;
    } *raw;
    ipcAddRecvStatic(&c, out, 0x480, 0);
    raw = serviceIpcPrepareHeader(&s->s, &c, sizeof(*raw));
    LogHex(armGetTls(), 0x100);

    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 1;
    Result rc = serviceIpcDispatch(&s->s);

    if (R_SUCCEEDED(rc)) {
        IpcParsedCommand r;
        struct {
            u64 magic;
            u64 result;
        } *resp;
        serviceIpcParse(&s->s, &r, sizeof(*resp));
        resp = r.Raw;

        rc = resp->result;
    }

    return rc;
}

Result ldnCreateUserLocalCommunicationService(Service* s, UserLocalCommunicationService* out) {
    IpcCommand c;
    ipcInitialize(&c);

    struct {
        u64 magic;
        u64 cmd_id;
    } *raw;

    raw = serviceIpcPrepareHeader(s, &c, sizeof(*raw));

    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 0;

    Result rc = serviceIpcDispatch(s);

    if (R_SUCCEEDED(rc)) {
        IpcParsedCommand r;
        struct {
            u64 magic;
            u64 result;
        } *resp;
        
        serviceIpcParse(s, &r, sizeof(*resp));
        resp = r.Raw;

        rc = resp->result;

        if (R_SUCCEEDED(rc)) {
            serviceCreateSubservice(&out->s, s, &r, 0);
        }
    }

    return rc;
}
