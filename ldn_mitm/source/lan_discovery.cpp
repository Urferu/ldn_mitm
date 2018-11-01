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
        return sendto(fd, buf, size + sizeof(header), 0, (struct sockaddr *)&addr, addr_size);
    }

    int send_broadcast(LANPacketType type, const void *data, size_t size) {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_BROADCAST;
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
        std::scoped_lock lk{g_list_mutex};
        network_list.clear();

        int rc = send_broadcast(LANPacketType::scan, NULL, 0);
        if (rc < 0) {
            char buf[64];
            sprintf(buf, "send_broadcast %d\n", rc);
            LogStr(buf);
        }
        sleep(1);

        u16 to_copy = std::min((u16)network_list.size(), bufferCount);
        std::copy_n(network_list.begin(), to_copy, outBuffer);
        *pOutCount = to_copy;

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
                LogStr("error recvfrom\n");
                break;
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
        if (R_FAILED(initialize())) {
            /* TODO: Panic. */
            LogStr("Error LDNDiscovery::initialize\n");
        }
        serve();
    }
};
