#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <algorithm>
#include <vector>
#include <cstring>
#include <mutex>
#include <stdint.h>
#include <unistd.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef int Result;

static const size_t TlsBackupSize = 0x100;
static const int ModuleID = 0xFE;
static const int DiscoveryPort = 11452;
static const int BufferSize = 2048;
static const int ScanResultCountMax = 24;
static const u32 LANMagic = 0x114514;
#define BACKUP_TLS() ;
#define RESTORE_TLS() ;
#define MAKERESULT(a, b) 0
#define R_FAILED(a) (a != 0)

namespace LANDiscovery {
    struct NetworkInfo {
        int a;
    };
    static int fd = 0;
    static bool stop = false;
    static bool is_host = false;
    static bool is_active = false;
    static NetworkInfo network_info = {0};
    static std::vector<NetworkInfo> network_list;
    static std::mutex g_list_mutex;

    void LogStr(const char *buf) {
        printf("%s", buf);
    }

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
        addr.sin_addr.s_addr = inet_addr("192.168.233.1");
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
            printf("%d %d %s\n", rc, errno, strerror(errno));
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

using namespace LANDiscovery;
int main() {
    int rc = initialize();
    printf("init %d\n", rc);
    u16 a = 0;
    rc = scan(NULL, &a, 0);
    return 0;
}
