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
#include "debug.h"

enum class CommState {
    None,
    Initialized,
    AccessPoint,
    AccessPointCreated,
    Station,
    StationConnected,
    Error
};

struct GetSecurityParameterData {
    u8 dat[0x20];
};
typedef struct {
    u8 dat[124];
} ConnectData;

class StateWaiter final : public IWaitable {
    private:
        Handle wait_h;
    public:
        StateWaiter(Handle h) : wait_h(h) {
            LogStr("IClientEvent\n");
        }
        Handle get_handle() override {
            return this->wait_h;
        }
        void handle_deferred() {
            LogStr("IClientEvent::handle_deferred\n");
        }
        Result handle_signaled(u64 timeout);
};

class ICommunicationInterface : public IServiceObject {
    private:
        CommState state;
        SystemEvent *state_event;
        NetworkInfo network_info;
        static const char *FakeSsid;
        static const uint8_t FakeMac[6];
    public:
        ICommunicationInterface(): state(CommState::None), state_event(nullptr), network_info({0}) {
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
        void init_network_info() {
            memset(&this->network_info, 0, sizeof(NetworkInfo));
            this->network_info.common.channel = 6;
            this->network_info.common.linkLevel = 3;
            this->network_info.common.networkType = 2;
            this->network_info.common.ssidLength = strlen(FakeSsid);

            memcpy(this->network_info.common.bssid, FakeMac, sizeof(FakeMac));
            strcpy(this->network_info.common.ssid, FakeSsid);
            NodeInfo *nodes = this->network_info.ldn.nodes;
            for (int i = 0; i < NodeCountMax; i++) {
                nodes[i].nodeId = i;
            }
        }
        void set_state(CommState new_state) {
            this->state = new_state;
            if (this->state_event) {
                LogStr("state_event signal_event\n");
                this->state_event->signal_event();
            }
        }
        std::tuple<Result> return_success();        
        std::tuple<Result> initialize(u64 unk, PidDescriptor pid);
        std::tuple<Result, u32> get_state();
        std::tuple<Result> get_network_info(OutPointerWithServerSize<u8, 0x480> buffer);
        std::tuple<Result, u32, u32> get_ipv4_address();
        std::tuple<Result, u16> get_disconnect_reason();
        std::tuple<Result, GetSecurityParameterData> get_security_Parameter();
        std::tuple<Result, NetworkConfig> get_network_config();
        std::tuple<Result> open_access_point();
        std::tuple<Result> close_access_point();
        std::tuple<Result> destroy_network();
        std::tuple<Result> create_network(CreateNetworkConfig data);
        std::tuple<Result> open_station();
        std::tuple<Result> close_station();
        std::tuple<Result> disconnect();
        std::tuple<Result> set_advertise_data(InPointer<u8> data1, InBuffer<u8> data2);
        std::tuple<Result, CopiedHandle> attach_state_change_event();
        std::tuple<Result, u16> scan(OutPointerWithServerSize<u8, 0> buffer, OutBuffer<u8> data);
        std::tuple<Result> connect(ConnectNetworkData dat, InPointer<u8> data);
        std::tuple<Result> get_network_info_latest_update(OutPointerWithServerSize<u8, 0x480> buffer1, OutPointerWithServerSize<u8, 0x8> buffer2);
};

class IMitMCommunicationInterface : public IServiceObject {
    private:
        UserLocalCommunicationService sys_service;
        StateWaiter *sys_event;
    public:
        IMitMCommunicationInterface(UserLocalCommunicationService s): sys_service(s), sys_event(nullptr) {
            LogStr("IMitMCommunicationInterface\n");
        };
        
        IMitMCommunicationInterface *clone() override {
            LogStr("IMitMCommunicationInterface::clone\n");
            return new IMitMCommunicationInterface(sys_service);
        };
        
        ~IMitMCommunicationInterface() {
            LogStr("~IMitMCommunicationInterface\n");
            /* ... */
        };

        Result dispatch(IpcParsedCommand &r, IpcCommand &out_c, u64 cmd_id, u8 *pointer_buffer, size_t pointer_buffer_size) final;

        Result handle_deferred() final {
            /* TODO: Panic, we can never defer. */
            return 0;
        };
    private:
        // IMitMCommunicationInterface(UserLocalCommunicationService s): sys_service(s) {
        //     /* ... */
        // };
        static Result sys_event_callback(void *arg, Handle *handles, size_t num_handles, u64 timeout);
};
