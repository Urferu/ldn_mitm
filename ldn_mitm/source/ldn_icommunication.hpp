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

class IClientEvent : public IEvent {
    public:
        IClientEvent(Handle wait_h): IEvent(wait_h, nullptr, nullptr) {
            LogStr("IClientEvent\n");
        }
        Result signal_event() {
            LogStr("IClientEvent::signal_event\n");
            return 0;
        }
        Result handle_signaled(u64 timeout);
};

class ICommunicationInterface : public IServiceObject {
    private:
        CommState state;
        SystemEvent *state_event;
    public:
        ICommunicationInterface(): state(CommState::None), state_event(nullptr) {
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
        void set_state(CommState new_state) {
            this->state = new_state;
            if (this->state_event) {
                this->state_event->signal_event();
            }
        }
        std::tuple<Result> return_success();        
        std::tuple<Result> initialize(u64 unk, PidDescriptor pid);
        std::tuple<Result, u32> get_state();
        std::tuple<Result, u32, u32> get_ipv4_address();
        std::tuple<Result, u16> get_disconnect_reason();
        std::tuple<Result, GetSecurityParameterData> get_security_Parameter();
        std::tuple<Result> open_access_point();
        std::tuple<Result> create_network(CreateNetworkData data);
        std::tuple<Result> set_advertise_data(InPointer<u8> data1, InBuffer<u8> data2);
        std::tuple<Result, CopiedHandle> attach_state_change_event();
};

class IMitMCommunicationInterface : public IServiceObject {
    private:
        UserLocalCommunicationService sys_service;
        IpcParsedCommand cur_out_r;
        IClientEvent *sys_event;
    public:
        IMitMCommunicationInterface(Service* forward_service): sys_service({0}), sys_event(nullptr) {
            LogStr("IMitMCommunicationInterface\n");

            Result rc = ldnCreateUserLocalCommunicationService(forward_service, &this->sys_service);
            if (R_FAILED(rc)) {
                LogStr("Error ldnCreateUserLocalCommunicationService\n");
            }
            char buf[64];
            sprintf(buf, "handle %x\n", this->sys_service.s.handle);
            LogStr(buf);
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
        IMitMCommunicationInterface(UserLocalCommunicationService s): sys_service(s) {
            /* ... */
        };
        static Result sys_event_callback(void *arg, Handle *handles, size_t num_handles, u64 timeout);
};
