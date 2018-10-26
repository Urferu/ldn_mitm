#include "ldn_icommunication.hpp"
#include "ldnmitm_worker.hpp"

// https://reswitched.github.io/SwIPC/ifaces.html#nn::ldn::detail::IUserLocalCommunicationService

enum class LdnCommCmd {
    GetState = 0,
    GetNetworkInfo = 1,
    GetIpv4Address = 2,
    GetDisconnectReason = 3,
    GetSecurityParameter = 4,
    AttachStateChangeEvent = 100,
    OpenAccessPoint = 200,
    CreateNetwork = 202,
    SetAdvertiseData = 206,
    Initialize = 400,
};

static SystemEvent *g_state_event = NULL;

Result ICommunicationInterface::dispatch(IpcParsedCommand &r, IpcCommand &out_c, u64 cmd_id, u8 *pointer_buffer, size_t pointer_buffer_size) {
    Result rc = 0xF601;
    char buf[128];
    u64 t;
    GetCurrentTime(&t);
    sprintf(buf, "[%" PRIu64 "] ICommunicationInterface::dispatch cmd_id: %" PRIu64 "\n", t, cmd_id);
    LogStr(buf);

    if (static_cast<LdnCommCmd>(cmd_id) == LdnCommCmd::CreateNetwork) {
        LogHex(armGetTls(), 0x100);
    }

    switch (static_cast<LdnCommCmd>(cmd_id)) {
        case LdnCommCmd::GetState:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::get_state>(this, r, out_c, pointer_buffer, pointer_buffer_size);
            break;
        case LdnCommCmd::GetNetworkInfo:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::get_network_info>(this, r, out_c, pointer_buffer, pointer_buffer_size);
            break;
        case LdnCommCmd::GetIpv4Address:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::get_ipv4_address>(this, r, out_c, pointer_buffer, pointer_buffer_size);
            break;
        case LdnCommCmd::GetDisconnectReason:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::get_disconnect_reason>(this, r, out_c, pointer_buffer, pointer_buffer_size);
            break;
        case LdnCommCmd::GetSecurityParameter:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::get_security_Parameter>(this, r, out_c, pointer_buffer, pointer_buffer_size);
            break;
        case LdnCommCmd::AttachStateChangeEvent:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::attach_state_change_event>(this, r, out_c, pointer_buffer, pointer_buffer_size);
            break;
        case LdnCommCmd::OpenAccessPoint:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::open_access_point>(this, r, out_c, pointer_buffer, pointer_buffer_size);
            break;
        case LdnCommCmd::CreateNetwork:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::create_network>(this, r, out_c, pointer_buffer, pointer_buffer_size);
            break;
        case LdnCommCmd::SetAdvertiseData:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::set_advertise_data>(this, r, out_c, pointer_buffer, pointer_buffer_size);
            break;
        case LdnCommCmd::Initialize:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::initialize>(this, r, out_c, pointer_buffer, pointer_buffer_size);
            break;
        default:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::return_success>(this, r, out_c, pointer_buffer, pointer_buffer_size);
            break;
    }

    GetCurrentTime(&t);
    sprintf(buf, "[%" PRIu64 "] ICommunicationInterface::dispatch rc: %x\n", t, rc);
    LogStr(buf);

    return rc;
};

std::tuple<Result> ICommunicationInterface::return_success() {
    Result rc = 0;

    return {rc};
}

std::tuple<Result> ICommunicationInterface::initialize(u64 unk, PidDescriptor pid) {
    Result rc = 0;

    char buf[128];
    sprintf(buf, "ICommunicationInterface::initialize unk: %" PRIu64 " pid: %" PRIu64 "\n", unk, pid.pid);
    LogStr(buf);

    this->set_state(CommState::Initialized);
    this->state_event = new SystemEvent(NULL, IEvent::PanicCallback);

    return {rc};
}

std::tuple<Result> ICommunicationInterface::open_access_point() {
    Result rc = 0;

    this->set_state(CommState::AccessPoint);

    return {rc};
}

std::tuple<Result> ICommunicationInterface::create_network(CreateNetworkData data) {
    Result rc = 0;

    LogHex(data.dat, 0x94);
    this->set_state(CommState::AccessPointCreated);

    return {rc};
}

std::tuple<Result> ICommunicationInterface::set_advertise_data(InPointer<u8> data1, InBuffer<u8> data2) {
    Result rc = 0;

    char buf[128];
    sprintf(buf, "ICommunicationInterface::set_advertise_data length data1: %" PRIu64 " data2: %" PRIu64 "\n", data1.num_elements, data2.num_elements);
    LogStr(buf);

    return {rc};
}

std::tuple<Result, u32> ICommunicationInterface::get_state() {
    Result rc = 0;

    return {rc, static_cast<u32>(this->state)};
}

std::tuple<Result, u32, u32> ICommunicationInterface::get_ipv4_address() {
    Result rc = 0;

    return {rc, 0x7F000001, 0xFF000000};
}

std::tuple<Result> ICommunicationInterface::get_network_info(OutPointerWithServerSize<u8, 0x480> buffer) {
    Result rc = 0;

    char buf[128];
    sprintf(buf, "get_network_info %p %" PRIu64 " state: %d\n", buffer.pointer, buffer.num_elements, static_cast<u32>(this->state));
    LogStr(buf);

    if (this->state != CommState::AccessPointCreated && this->state != CommState::StationConnected) {
        rc = 0x40CB; // ResultConnectionFailed
    }

    return {rc};
}

std::tuple<Result, u16> ICommunicationInterface::get_disconnect_reason() {
    Result rc = 0;

    return {rc, 1};
}

std::tuple<Result, GetSecurityParameterData> ICommunicationInterface::get_security_Parameter() {
    Result rc = 0;

    GetSecurityParameterData data;

    return {rc, data};
}

std::tuple<Result, CopiedHandle> ICommunicationInterface::attach_state_change_event() {
    return {0, this->state_event->get_handle()};
}

Result StateWaiter::handle_signaled(u64 timeout) {
    svcClearEvent(this->get_handle());

    LogHex(armGetTls(), 0x100);
    char buf[64];
    sprintf(buf, "sys_event_callback %p\n", g_state_event);
    LogStr(buf);
    LogStr(buf);
    if (g_state_event) {
        LogStr("fire\n");
        g_state_event->signal_event();
    } else {
        LogStr("NULL\n");
    }
    return 0;
}

Result IMitMCommunicationInterface::dispatch(IpcParsedCommand &r, IpcCommand &out_c, u64 cmd_id, u8 *pointer_buffer, size_t pointer_buffer_size) {
    if (g_state_event == NULL) {
        g_state_event = new SystemEvent(NULL, &IEvent::PanicCallback);
    }
    char buf[128];
    IpcParsedCommand cur_out_r;

    // u32 *cmdbuf = (u32 *)armGetTls();
    /* Patch PID Descriptor, if relevant. */
    // if (r.HasPid) {
    //     /* [ctrl 0] [ctrl 1] [handle desc 0] [pid low] [pid high] */
    //     cmdbuf[4] = 0xFFFE0000UL | (cmdbuf[4] & 0xFFFFUL);
    // }
    u64 t = 0;
    GetCurrentTime(&t);
    sprintf(buf, "[%" PRIu64 "] mitm dispatch cmd_id %" PRIu64 " type %d\n", t, cmd_id, r.CommandType);
    LogStr(buf);
    if (cmd_id != 0 && cmd_id != 1 && cmd_id != 3) {
        LogHex(armGetTls(), 0x100);
    }

    Result retval = 0xF601;
    if (cmd_id == 1) {
        u8 info[0x480] = {0};
        retval = ldnGetNetworkInfo(&sys_service, &info);
        sprintf(buf, "ldnGetNetworkInfo %d %lu\n", retval, sizeof(decltype(info)));
        LogStr(buf);
        LogHex(info, 0x480);
    } else {
        retval = serviceIpcDispatch(&(sys_service.s));
    }
    u8 backup[0x100];
    memcpy(backup, armGetTls(), 0x100);
    if (cmd_id != 0 && cmd_id != 1 && cmd_id != 3) {
        LogHex(armGetTls(), 0x100);
    }

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
            u32 state;
        } *resp = (decltype(resp))cur_out_r.Raw;

        if (cmd_id == 0) {
            sprintf(buf, "state %" PRIu64 " %" PRIu32 "\n", resp->result, resp->state);
            LogStr(buf);
        } else if (cmd_id == 3) {
            struct {
                u64 magic;
                u64 result;
                u16 reason;
            } *r2 = (decltype(r2))cur_out_r.Raw;
            sprintf(buf, "reason %" PRIu64 " %" PRIu16 "\n", r2->result, r2->reason);
            LogStr(buf);
        } else if (cmd_id == 1) {
            sprintf(buf, "cmd 1 statics: %" PRIu64 " 0 ptr %p size %" PRIu64 "\n",
                cur_out_r.NumStatics, cur_out_r.Statics[0], cur_out_r.StaticSizes[0]);
            LogStr(buf);

            ipcAddSendStatic(&out_c, cur_out_r.Statics[0], cur_out_r.StaticSizes[0], 0);
            struct {
                u64 magic;
                u64 result;
            } *raw = (decltype(raw))serviceIpcPrepareHeader(&sys_service.s, &out_c, sizeof(*raw));
            raw->magic = SFCO_MAGIC;
            raw->result = 0;
        }

        if (cmd_id == 100) {
            sprintf(buf, "cmd 100 %x\n", cur_out_r.Handles[0]);
            LogStr(buf);

            this->sys_event = new StateWaiter(cur_out_r.Handles[0]);
            LdnMitMWorker::AddWaitable(this->sys_event);

            ipcSendHandleCopy(&out_c, g_state_event->get_handle());
            struct {
                u64 magic;
                u64 result;
            } *raw = (decltype(raw))serviceIpcPrepareHeader(&sys_service.s, &out_c, sizeof(*raw));
            raw->magic = SFCO_MAGIC;
            raw->result = 0;

            LogHex(armGetTls(), 0x100);

            LogStr("end 100\n");
        }

        retval = resp->result;
    }

    GetCurrentTime(&t);
    sprintf(buf, "[%" PRIu64 "] mitm dispatch rc %u\n", t, retval);
    LogStr(buf);

    memcpy(armGetTls(), backup, 0x100);
    return retval;
}