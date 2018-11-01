#include "lan_discovery.hpp"
#include "debug.h"
#include <algorithm>
#include <vector>
#include <cstring>
#include <mutex>
#include <stratosphere.hpp>

static const size_t TlsBackupSize = 0x100;
static const int ModuleID = 0xFE;
static const int DiscoveryPort = 11452;
static const int BufferSize = 2048;
static const int ScanResultCountMax = 24;
static const u32 LANMagic = 0x114514;
#define BACKUP_TLS() u8 _tls_backup[TlsBackupSize];memcpy(_tls_backup, armGetTls(), TlsBackupSize);
#define RESTORE_TLS() memcpy(armGetTls(), _tls_backup, TlsBackupSize);

static int compress(uint8_t *input, size_t input_size, uint8_t *output, size_t *output_size);
static int decompress(uint8_t *input, size_t input_size, uint8_t *output, size_t *output_size);

namespace LANDiscovery {
    static int fd = 0;
    static bool stop = false;
    static bool is_host = false;
    static bool is_active = false;
    static NetworkInfo network_info = {0};
    static std::vector<NetworkInfo> network_list;
    static HosMutex g_list_mutex;

    struct PayloadScanResponse {
        u16 size;
        u8 data[sizeof(NetworkInfo)];
    };
    enum class LANPacketType : u8 {
        scan,
        scan_resp,
    };
    struct LANPacketHeader {
        u32 magic;
        LANPacketType type;
        u8 compressed;
        u8 _reserved[2];
    };

    int compress(uint8_t *input, size_t input_size, uint8_t *output, size_t *output_size);
    int decompress(uint8_t *input, size_t input_size, uint8_t *output, size_t *output_size);
    int send_broadcast(LANPacketType type);

    Result initialize() {
        Result rc = 0;
        BACKUP_TLS();

        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            rc = MAKERESULT(ModuleID, 1);
        } else {
            sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = INADDR_ANY;
            addr.sin_port = htons(DiscoveryPort);
            if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
                rc = MAKERESULT(ModuleID, 2);
            } else {
                struct timeval t = {1, 0};
                rc = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(t));
                if (rc != 0) {
                    rc = MAKERESULT(ModuleID, 3);
                }
                int b = 1;
                rc = setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &b, sizeof(b));
                if (rc != 0) {
                    rc = MAKERESULT(ModuleID, 4);
                }
            }
        }

        RESTORE_TLS();
        return rc;
    }

    void sleep(int sec) {
        svcSleepThread(1000000000L * sec);
    }

    void set_network_info(NetworkInfo &info) {
        network_info = info;
    }

    void set_active(bool v) {
        is_active = v;
    }

    void set_host(bool v) {
        is_host = v;
    }

    void prepare_header(LANPacketHeader &header, LANPacketType type) {
        header.magic = LANMagic;
        header.type = type;
        header.compressed = false;
        header._reserved[0] = 0;
        header._reserved[1] = 0;
    }

    int send_to(LANPacketType type, const void *data, size_t size, struct sockaddr_in &addr, size_t addr_size) {
        LANPacketHeader header;
        prepare_header(header, type);
        u8 buf[size + sizeof(header)];
        memcpy(buf, &header, sizeof(header));
        if (data == NULL) {
            size = 0;
        }
        if (size > 0) {
            memcpy(buf + sizeof(header), data, size);
        }
        LogStr("Start sendto\n");
        return sendto(fd, buf, size + sizeof(header), 0, (struct sockaddr *)&addr, addr_size);
    }

    u32 get_broadcast() {
        Result rc;
        u32 ret = 0xFFFFFFFF;
        Service nifmSrv;
        Service nifmIGS;

        rc = smGetService(&nifmSrv, "nifm:u");
        if (R_FAILED(rc)) {
            goto quit;
        }

        IpcCommand c;
        IpcParsedCommand r;

        {
            ipcInitialize(&c);
            ipcSendPid(&c);
            struct {
                u64 magic;
                u64 cmd_id;
                u64 param;
            } *raw;

            raw = (decltype(raw))serviceIpcPrepareHeader(&nifmSrv, &c, sizeof(*raw));

            raw->magic = SFCI_MAGIC;
            raw->cmd_id = 5;
            raw->param = 0;
        }

        rc = serviceIpcDispatch(&nifmSrv);

        if (R_FAILED(rc)) {
            goto quit_close_srv;
        }
        {
            struct {
                u64 magic;
                u64 result;
            } *resp;

            serviceIpcParse(&nifmSrv, &r, sizeof(*resp));
            resp = (decltype(resp))r.Raw;

            
            rc = resp->result;

            if (R_FAILED(rc))
                goto quit_close_srv;

            serviceCreateSubservice(&nifmIGS, &nifmSrv, &r, 0);
        }
        {
            ipcInitialize(&c);
            struct {
                u64 magic;
                u64 cmd_id;
            } *raw;

            raw = (decltype(raw))serviceIpcPrepareHeader(&nifmIGS, &c, sizeof(*raw));

            raw->magic = SFCI_MAGIC;
            raw->cmd_id = 15;
            
            rc = serviceIpcDispatch(&nifmIGS);
            if (R_FAILED(rc)) {
                goto quit_close_inf;
            }
            struct {
                u64 magic;
                u64 result;
                u8 _unk;
                u32 address;
                u32 netmask;
                u32 gateway;
            } __attribute__((packed)) *resp;

            serviceIpcParse(&nifmIGS, &r, sizeof(*resp));
            resp = (decltype(resp))r.Raw;

            rc = resp->result;
            if (R_FAILED(rc)) {
                goto quit_close_inf;
            }
            ret = resp->address | ~resp->netmask;
        }

quit_close_inf:
        serviceClose(&nifmIGS);
quit_close_srv:
        serviceClose(&nifmSrv);
quit:
        return ret;
    }

    int send_broadcast(LANPacketType type, const void *data, size_t size) {
        struct sockaddr_in addr;
        char buf[64];
        sprintf(buf, "broadcast %x\n", get_broadcast());
        LogStr(buf);

        addr.sin_family = AF_INET;
        // addr.sin_addr.s_addr = inet_addr("192.168.233.255");
        addr.sin_addr.s_addr = get_broadcast();
        addr.sin_port = htons(DiscoveryPort);

        return send_to(type, data, size, addr, sizeof(addr));
    }

    int send_broadcast(LANPacketType type) {
        return send_broadcast(type, NULL, 0);
    }

    int scan(
        NetworkInfo *outBuffer,
        u16 *pOutCount,
        u16 bufferCount
    ) {
        BACKUP_TLS();

        {
            std::scoped_lock lk{g_list_mutex};
            network_list.clear();
        }

        LogStr("Start send_broadcast\n");
        int rc = send_broadcast(LANPacketType::scan);
        LogStr("End send_broadcast\n");
        if (rc < 0) {
            char buf[64];
            sprintf(buf, "send_broadcast %d\n", rc);
            LogStr(buf);
        }

        LogStr("Start sleep\n");
        sleep(1);
        LogStr("End sleep\n");

        {
            std::scoped_lock lk{g_list_mutex};
            u16 to_copy = std::min((u16)network_list.size(), bufferCount);
            std::copy_n(network_list.begin(), to_copy, outBuffer);
            *pOutCount = to_copy;
        }

        RESTORE_TLS();
        return rc;
    }

    void on_message(LANPacketType type, const void *data, struct sockaddr_in &addr) {
        switch (type) {
            case LANPacketType::scan: {
                if (is_host) {
                    send_to(LANPacketType::scan_resp, &network_info, sizeof(network_info), addr, sizeof(addr));
                }
                break;
            }
            case LANPacketType::scan_resp: {
                if (!is_host) {
                    std::scoped_lock lk{g_list_mutex};
                    NetworkInfo *info = (NetworkInfo *)data;
                    network_list.push_back(*info);
                }
                break;
            }
            default: {
                char buf[64];
                sprintf(buf, "on_message unhandle type %d\n", static_cast<int>(type));
                LogStr(buf);
                break;
            }
        }
    }

    void serve() {
        u8 buffer[BufferSize];
        struct sockaddr_in addr;
        socklen_t addr_len;
        ssize_t len;

        while (!stop) {
            addr_len = sizeof(addr);
            len = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&addr, &addr_len);
            if (len < 0) {
                continue;
            }
            if (!is_active) {
                continue;
            }
            if ((size_t)len >= sizeof(LANPacketHeader)) {
                LANPacketHeader *header = (LANPacketHeader *)buffer;
                if (header->magic == LANMagic) {
                    on_message(header->type, buffer, addr);
                }
            }
        }
        stop = true;
        LogStr("serve stopped\n");
    }

    void Main(void *arg) {
        sleep(2);
        LogStr("LANDiscovery::main\n");
        Result rc = initialize();
        if (R_FAILED(rc)) {
            /* TODO: Panic. */
            char buf[64];
            sprintf(buf, "Error LDNDiscovery::initialize %d\n", rc);
            LogStr(buf);
        }
        LogStr("LANDiscovery::start serve\n");
        serve();
    }
};

#if 0
int compress(uint8_t *in, size_t input_size, uint8_t *output, size_t *output_size) {
    uint8_t *in_end = in + input_size;
    uint8_t *out = output;
    uint8_t *out_end = output + *output_size;

    while (out < out_end && in < in_end) {
        uint8_t c = *in++;
        uint8_t count = 1;

        if (c == 0) {
            while (*in == 0 && in < in_end && count < 0xFF) {
                count += 1;
                in++;
            }
        } else if (c == 0xFF) {
            count = 0xFF;
        }

        if (c == 0x00 || c == 0xFF) {
            *out++ = 0xFF;

            if (out == out_end) 
                return -1;
            *out++ = count;
        } else {
            *out++ = c;
        }
    }

    *output_size = out - output;

    return 0;
}

int decompress(uint8_t *input, size_t input_size, uint8_t *output, size_t *output_size) {
    uint8_t *in = input;
    uint8_t *in_end = input + input_size;
    uint8_t *out = output;
    uint8_t *out_end = output + *output_size;

    while (in < in_end && out < out_end) {
        uint8_t c = *in++;
        uint8_t count = 1;
        if (c == 0xFF) {
            if (in == in_end) {
                return -1;
            }
            count = *in++;
            if (count == 0xFF) {
                c = 0xFF;
            }
        }
        for (int i = 0; i < count; i++) {
            *out++ = c;
            if (out == out_end) {
                return in < in_end ? -1 : 0;
            }
        }
    }

    return 0;
}
#endif