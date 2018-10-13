#pragma once
#include <switch.h>
#include "imitmserviceobject.hpp"
#include "fsmitm_utils.hpp"
#include "ldn_icommunication.hpp"

enum class LdnSrvCmd {
    CreateUserLocalCommunicationService = 0,
};

class LdnMitMService : public IMitMServiceObject {      
    private:
        // std::shared_ptr<IStorageInterface> romfs_storage;
        std::shared_ptr<ICommunicationInterface> communication;
    public:
        LdnMitMService(Service *s) : IMitMServiceObject(s) {
            /* ... */
            communication = std::make_shared<ICommunicationInterface>();
        }
        
        static bool should_mitm(u64 pid, u64 tid) {
            return tid >= 0x0100000000010000ULL || Utils::HasSdMitMFlag(tid);
        }
        
        LdnMitMService *clone() override {
            auto new_srv = new LdnMitMService((Service *)&this->forward_service);
            this->clone_to(new_srv);
            return new_srv;
        }
        
        void clone_to(void *o) override {
            // LdnMitMService *other = (LdnMitMService *)o;
        }
        
        virtual Result dispatch(IpcParsedCommand &r, IpcCommand &out_c, u64 cmd_id, u8 *pointer_buffer, size_t pointer_buffer_size);
        virtual void postprocess(IpcParsedCommand &r, IpcCommand &out_c, u64 cmd_id, u8 *pointer_buffer, size_t pointer_buffer_size);
        virtual Result handle_deferred();
    
    protected:
        /* Overridden commands. */
        std::tuple<Result, OutSession<ICommunicationInterface>> create_user_local_communication_service();
        // std::tuple<Result, OutSession<IStorageInterface>> open_data_storage_by_current_process();
        // std::tuple<Result, OutSession<IStorageInterface>> open_data_storage_by_data_id(u64 storage_id, u64 data_id);
};
