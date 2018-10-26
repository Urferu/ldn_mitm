#pragma once
#include <switch.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    Service s;
} UserLocalCommunicationService;

#define SsidLengthMax 32
#define AdvertiseDataSizeMax 384
#define UserNameBytesMax 32
#define NodeCountMax 8

typedef struct {
    uint8_t length;
    char raw[SsidLengthMax + 1];
} Ssid;

typedef struct {
    int16_t channel;
    int8_t linkLevel;
    uint8_t networkType;
    Ssid ssid;
} CommonNetworkInfo;

typedef struct {
    uint8_t raw[4];
} Ipv4Address;

typedef struct {
    Ipv4Address ipv4Address;
    bool isConnected;
    int16_t localCommunicationVersion;
    int8_t nodeId;
    char userName[UserNameBytesMax+1];
} NodeInfo;

typedef struct {
    uint8_t advertiseData[AdvertiseDataSizeMax];
    uint16_t advertiseDataSize;
    int8_t nodeCount;
    int8_t nodeCountMax;
    NodeInfo nodes[NodeCountMax];
    uint16_t securityMode;
    uint8_t stationAcceptPolicy;
} LdnNetworkInfo;

typedef struct {
    uint64_t localCommunicationId;
    uint16_t sceneId;
} IntentId;

typedef struct {
    uint64_t high;
    uint64_t low;
} SessionId;

typedef struct {
    IntentId intendId;
    SessionId sessionId;
} NetworkId;

typedef struct {
    CommonNetworkInfo common;
    LdnNetworkInfo ldn;
    NetworkId networkId;
} NetworkInfo;

Result fuck(NetworkInfo info);
Result ldnGetNetworkInfo(UserLocalCommunicationService* s, void* out);
Result ldnCreateUserLocalCommunicationService(Service* s, UserLocalCommunicationService* out);

#ifdef __cplusplus
}
#endif
