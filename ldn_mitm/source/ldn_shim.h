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
#define PassphraseLengthMax 64

typedef struct {
    uint8_t bssid[6];
    uint8_t ssidLength;
    char ssid[SsidLengthMax + 1];
    int16_t channel;
    int8_t linkLevel;
    uint8_t networkType;
    uint32_t _unk;
} CommonNetworkInfo;

typedef struct {
    uint32_t ipv4Address;
	uint8_t macAddress[6];
    int8_t nodeId;
    int8_t isConnected;
    char userName[UserNameBytesMax+1];
	uint8_t _unk1;
    int16_t localCommunicationVersion;
	uint8_t _unk2[16];
} NodeInfo;

typedef struct {
    uint8_t unkRandom[16];
    uint16_t securityMode;
    uint8_t stationAcceptPolicy;
    uint8_t _unk1[3];
    int8_t nodeCountMax;
    int8_t nodeCount;
    NodeInfo nodes[NodeCountMax];
    uint16_t _unk2;
    uint16_t advertiseDataSize;
    uint8_t advertiseData[AdvertiseDataSizeMax];
	char _unk3[148];
} LdnNetworkInfo;

typedef struct {
    uint64_t localCommunicationId;
    uint16_t sceneId;
    uint16_t localCommunicationVersion;
    uint32_t _unk;
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
    NetworkId networkId;
    CommonNetworkInfo common;
    LdnNetworkInfo ldn;
} NetworkInfo;

typedef struct {
    uint16_t securityMode;
    uint16_t passphraseSize;
    uint8_t passphrase[PassphraseLengthMax];
} SecurityConfig;

typedef struct {
    char userName[UserNameBytesMax + 1];
    uint8_t _unk[15];
} UserConfig;

typedef struct {
    IntentId intentId;
    uint16_t channel;
    uint8_t nodeCountMax;
    uint8_t _unk1;
    uint16_t localCommunicationVersion;
    uint8_t _unk2[10];
} NetworkConfig;

typedef struct {
    SecurityConfig securityConfig;
    UserConfig userConfig;
    uint8_t _unk[4];
    NetworkConfig networkConfig;
} CreateNetworkConfig;

typedef struct {
    SecurityConfig securityConfig;
    UserConfig userConfig;
    uint32_t version;
    uint32_t option;
} ConnectNetworkData;

Result ldnGetNetworkInfo(UserLocalCommunicationService* s, void* out);
Result ldnScan(UserLocalCommunicationService* s, u16 channel, void* unk2, u16* unkOut, void* outBuf);
Result ldnCreateUserLocalCommunicationService(Service* s, UserLocalCommunicationService* out);

#ifdef __cplusplus
}
#endif
