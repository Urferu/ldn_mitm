#pragma once
#include <switch.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ldn_shim.h"

namespace LANDiscovery {
    void set_network_info(NetworkInfo &info);
    void set_active(bool v);
    void set_host(bool v);
    int scan(
        NetworkInfo *outBuffer,
        u16 *pOutCount,
        u16 bufferCount
    );
    void Main(void *arg);
};
