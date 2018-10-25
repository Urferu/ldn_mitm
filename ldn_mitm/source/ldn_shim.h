#pragma once
#include <switch.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    Service s;
} UserLocalCommunicationService;

Result ldnCreateUserLocalCommunicationService(Service* s, UserLocalCommunicationService* out);

#ifdef __cplusplus
}
#endif
