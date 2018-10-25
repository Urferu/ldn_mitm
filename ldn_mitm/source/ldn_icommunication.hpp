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
 
#pragma once
#include <switch.h>
#include <stratosphere.hpp>
#include "ldn_shim.h"
#include "debug.hpp"

enum class CommState {
    None,
    Initialized,
    AccessPoint,
    AccessPointCreated,
    Station,
    StationConnected,
    Error
};

struct CreateNetworkData {
    u8 dat[0x94];
};
struct GetSecurityParameterData {
    u8 dat[0x20];
};

class ICommunicationInterface : public IServiceObject {
    private:
        CommState state;
    public:
        ICommunicationInterface(): state(CommState::None) {
            LogStr("ICommunicationInterface\n");
            /* ... */
        };
        
        ICommunicationInterface *clone() override {
            LogStr("ICommunicationInterface::clone\n");
            return new ICommunicationInterface();
        }
        
        ~ICommunicationInterface() {
            LogStr("~ICommunicationInterface\n");
            /* ... */
        };
        
        Result dispatch(IpcParsedCommand &r, IpcCommand &out_c, u64 cmd_id, u8 *pointer_buffer, size_t pointer_buffer_size) final;
        
        Result handle_deferred() final {
            /* TODO: Panic, we can never defer. */
            return 0;
        };
    private:
        std::tuple<Result> return_success();        
        std::tuple<Result> initialize(u64 unk, PidDescriptor pid);
        std::tuple<Result, u64> get_state();
        std::tuple<Result, u32, u32> get_ipv4_address();
        std::tuple<Result, GetSecurityParameterData> get_security_Parameter();
        std::tuple<Result> open_access_point();
        std::tuple<Result> create_network(CreateNetworkData data);
        std::tuple<Result> set_advertise_data(InPointer<u8> data1, InBuffer<u8> data2);
};

class IMitMCommunicationInterface : public IServiceObject {
    private:
        UserLocalCommunicationService sys_service;
        IpcParsedCommand cur_out_r;
    public:
        IMitMCommunicationInterface(Service* forward_service) {
            LogStr("IMitMCommunicationInterface\n");

            Result rc = ldnCreateUserLocalCommunicationService(forward_service, &sys_service);
            if (R_FAILED(rc)) {
                LogStr("Error ldnCreateUserLocalCommunicationService\n");
            }
        };
        
        IMitMCommunicationInterface *clone() override {
            LogStr("IMitMCommunicationInterface::clone\n");
            return new IMitMCommunicationInterface(sys_service);
        };
        
        ~IMitMCommunicationInterface() {
            LogStr("~IMitMCommunicationInterface\n");
            /* ... */
        };
        
        Result dispatch(IpcParsedCommand &r, IpcCommand &out_c, u64 cmd_id, u8 *pointer_buffer, size_t pointer_buffer_size) final {
            char buf[64];
            sprintf(buf, "mitm dispatch cmd_id %" PRIu64 "\n", cmd_id);
            LogStr(buf);
            LogHex(armGetTls(), 0x100);
            Result retval = serviceIpcDispatch(&sys_service.s);
            LogHex(armGetTls(), 0x100);

            if (R_SUCCEEDED(retval)) {
                if (r.IsDomainRequest) { 
                    /* We never work with out object ids, so this should be fine. */
                    ipcParseDomainResponse(&cur_out_r, 0);
                } else {
                    ipcParse(&cur_out_r);
                }

                struct {
                    u64 magic;
                    u64 result;
                } *resp = (decltype(resp))cur_out_r.Raw;

                retval = resp->result;
            }

            return retval;
        };

        Result handle_deferred() final {
            /* TODO: Panic, we can never defer. */
            return 0;
        };
    private:
        IMitMCommunicationInterface(UserLocalCommunicationService s): sys_service(s) {
            /* ... */
        };
};
