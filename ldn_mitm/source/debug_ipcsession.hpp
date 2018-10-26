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
#include <type_traits>

template <typename T>
class DebugIPCSession final : public ISession<T> {    
    static_assert(std::is_base_of<IServiceObject, T>::value, "Service Objects must derive from IServiceObject");
    
    public:
        DebugIPCSession<T>(size_t pbs = 0x400) : ISession<T>(NULL, 0, 0, 0) {
            Result rc;
            if (R_FAILED((rc = svcCreateSession(&this->server_handle, &this->client_handle, 0, 0)))) {
                fatalSimple(rc);
            }
            this->service_object = std::make_shared<T>();
            this->pointer_buffer.resize(pbs);
        }
        
        DebugIPCSession<T>(std::shared_ptr<T> so, size_t pbs = 0x400) : ISession<T>(NULL, 0, 0, so, 0) {
            Result rc;
            if (R_FAILED((rc = svcCreateSession(&this->server_handle, &this->client_handle, 0, 0)))) {
                fatalSimple(rc);
            }
            this->pointer_buffer.resize(pbs);
        }

        Result handle_signaled(u64 timeout) override {
            Result rc;
            int handle_index;
            
            /* Prepare pointer buffer... */
            IpcCommand c_for_reply;
            ipcInitialize(&c_for_reply);
            ipcAddRecvStatic(&c_for_reply, this->pointer_buffer.data(), this->pointer_buffer.size(), 0);
            ipcPrepareHeader(&c_for_reply, 0);
            
            /* Fix libnx bug in serverside C descriptor handling. */
            ((u32 *)armGetTls())[1] &= 0xFFFFC3FF;
            ((u32 *)armGetTls())[1] |= (2) << 10;
            
            if (R_SUCCEEDED(rc = svcReplyAndReceive(&handle_index, &this->server_handle, 1, 0, U64_MAX))) {
                if (handle_index != 0) {
                    /* TODO: Panic? */
                }                                
                IpcParsedCommand r;
                u64 cmd_id;
                
                
                Result retval = ipcParse(&r);
                if (R_SUCCEEDED(retval)) {
                    if (this->is_domain && (r.CommandType == IpcCommandType_Request || r.CommandType == IpcCommandType_RequestWithContext)) {
                        retval = ipcParseDomainRequest(&r);
                        if (!r.IsDomainRequest || r.InThisObjectId >= DOMAIN_ID_MAX) {
                            retval = 0xF601;
                        } else {
                            this->active_object = this->domain->get_domain_object(r.InThisObjectId);
                        }
                    } else {
                        this->active_object = this->service_object;
                    }
                }
                if (R_SUCCEEDED(retval)) {    
                    cmd_id = ((u32 *)r.Raw)[2];
                }
                if (R_SUCCEEDED(retval)) {
                    char buf[64];
                    u64 cmd_id = ((u32 *)r.Raw)[2];
                    sprintf(buf, "handle_message %d %" PRIu64 "\n", r.CommandType, cmd_id);
                    // LogStr(buf);
                    retval = this->handle_message(r);
                } else {
                    LogStr("skip message\n");
                }
                
                if (retval == RESULT_DEFER_SESSION) {
                    /* Session defer. */
                    this->active_object.reset();
                    this->set_deferred(true);
                    rc = retval;
                } else if (retval == 0xF601) {
                    /* Session close. */
                    this->active_object.reset();
                    rc = retval;
                } else {
                    if (R_SUCCEEDED(retval)) {
                        this->postprocess(r, cmd_id);
                    }
                    this->active_object.reset();
                    rc = svcReplyAndReceive(&handle_index, &this->server_handle, 0, this->server_handle, 0);
                    if (rc == 0xEA01) {
                        rc = 0x0;
                    }
                    this->cleanup();
                }
            } else {
                LogStr("Failed fuck\n");
            }
              
            return rc;
        }
};
