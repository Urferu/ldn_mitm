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

class ICommunicationInterface : public IServiceObject {
    private:
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
        std::tuple<Result> open_access_point();
        std::tuple<Result> set_advertise_data(InPointer<u8> data1, InBuffer<u8> data2);
        std::tuple<Result, u64> get_state();
        CommState state;
};
