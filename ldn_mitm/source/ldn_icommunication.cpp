#include "ldn_icommunication.hpp"
#include "ldnmitm_worker.hpp"
#include "hardcode_data.h"

static_assert(sizeof(NetworkInfo) == 0x480, "sizeof(NetworkInfo) should be 0x480");

// https://reswitched.github.io/SwIPC/ifaces.html#nn::ldn::detail::IUserLocalCommunicationService

enum class LdnCommCmd {
    GetState = 0,
    GetNetworkInfo = 1,
    GetIpv4Address = 2,
    GetDisconnectReason = 3,
    GetSecurityParameter = 4,
    AttachStateChangeEvent = 100,
    Scan = 102,
    OpenAccessPoint = 200,
    CreateNetwork = 202,
    OpenStation = 300,
    Connect = 302,
    SetAdvertiseData = 206,
    Initialize = 400,
};

static SystemEvent *g_state_event = NULL;

Result ICommunicationInterface::dispatch(IpcParsedCommand &r, IpcCommand &out_c, u64 cmd_id, u8 *pointer_buffer, size_t pointer_buffer_size) {
    Result rc = 0xF601;
    char buf[128];
    u64 t;
    GetCurrentTime(&t);
    sprintf(buf, "[%" PRIu64 "] ICommunicationInterface::dispatch cmd_id: %" PRIu64 " raw size %" PRIu64 "\n", t, cmd_id, r.RawSize);
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
        case LdnCommCmd::Scan:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::scan>(this, r, out_c, pointer_buffer, pointer_buffer_size);
            break;
        case LdnCommCmd::OpenAccessPoint:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::open_access_point>(this, r, out_c, pointer_buffer, pointer_buffer_size);
            break;
        case LdnCommCmd::CreateNetwork:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::create_network>(this, r, out_c, pointer_buffer, pointer_buffer_size);
            break;
        case LdnCommCmd::OpenStation:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::open_station>(this, r, out_c, pointer_buffer, pointer_buffer_size);
            break;
        case LdnCommCmd::Connect:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::connect>(this, r, out_c, pointer_buffer, pointer_buffer_size);
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

    if (cmd_id == 102) {
        LogStr("cmd 102 resp\n");
        LogHex(armGetTls(), 0x100);
    }

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

std::tuple<Result> ICommunicationInterface::open_station() {
    Result rc = 0;

    this->set_state(CommState::Station);

    return {rc};
}

std::tuple<Result> ICommunicationInterface::create_network(CreateNetworkConfig data) {
    Result rc = 0;

    LogHex(&data, 0x94);
    this->set_state(CommState::AccessPointCreated);

    return {rc};
}

std::tuple<Result> ICommunicationInterface::set_advertise_data(InPointer<u8> data1, InBuffer<u8> data2) {
    Result rc = 0;

    char buf[128];
    sprintf(buf, "ICommunicationInterface::set_advertise_data length data1: %" PRIu64 " data2: %" PRIu64 "\n", data1.num_elements, data2.num_elements);
    LogStr(buf);
    sprintf(buf, "data1: %p data2: %p\n", data1.pointer, data2.buffer);
    LogStr(buf);
    LogHex(data1.pointer, data1.num_elements);

    return {rc};
}

std::tuple<Result, u32> ICommunicationInterface::get_state() {
    Result rc = 0;

    return {rc, static_cast<u32>(this->state)};
}

std::tuple<Result, u32, u32> ICommunicationInterface::get_ipv4_address() {
    Result rc = 0;

    return {rc, 0xA9FE6601, 0xFFFFFF00};
}

std::tuple<Result> ICommunicationInterface::get_network_info(OutPointerWithServerSize<u8, sizeof(NetworkInfo)> buffer) {
    Result rc = 0;

    char buf[128];
    sprintf(buf, "get_network_info %p %" PRIu64 " state: %d\n", buffer.pointer, buffer.num_elements, static_cast<u32>(this->state));
    LogStr(buf);

    if (this->state == CommState::AccessPointCreated) {
        memcpy(buffer.pointer, hostNetData, sizeof(NetworkInfo));
    } else if (this->state == CommState::StationConnected) {
        memcpy(buffer.pointer, scanData, sizeof(NetworkInfo));
    } else {
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

std::tuple<Result, u16> ICommunicationInterface::scan(OutPointerWithServerSize<u8, 0> pointer, OutBuffer<u8> buffer) {
    // memcpy(pointer.pointer, scanData, sizeof(scanData));
    memcpy(buffer.buffer, hostNetData, sizeof(NetworkInfo));
    memcpy(buffer.buffer + sizeof(NetworkInfo), scanData, sizeof(NetworkInfo));

    return {0, 2};
}

std::tuple<Result> ICommunicationInterface::connect(InPointer<u8> data) {
    char buf[64];
    sprintf(buf, "ICommunicationInterface::connect %" PRIu64 "\n", data.num_elements);
    LogStr(buf);
    LogHex(data.pointer, sizeof(NetworkInfo));

    this->set_state(CommState::StationConnected);

    return {0};
}

Result StateWaiter::handle_signaled(u64 timeout) {
    svcClearEvent(this->get_handle());
    svcResetSignal(this->get_handle());

    if (g_state_event) {
        LogStr("fire\n");
        g_state_event->signal_event();
    } else {
        LogStr("NULL\n");
    }
    char buf[64];
    sprintf(buf, "sys_event_callback %p\n", g_state_event);
    LogStr(buf);
    LogHex(armGetTls(), 0x100);
    return 0;
}

u8 tmp_info[0x1000] = {0};
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
    if (cmd_id == 1) { // get network info
        u8 info[0x480] = {0};
        retval = ldnGetNetworkInfo(&sys_service, &info);
        sprintf(buf, "ldnGetNetworkInfo %d %lu\n", retval, sizeof(decltype(info)));
        LogStr(buf);
        LogHex(info, 0x480);
    } else if (cmd_id == 102) { // scan
        struct {
            u64 magic;
            u64 result;
            u16 channel;
            u8 unk2[0x60];
        } *resp = (decltype(resp))r.Raw;
        u16 unkOut = 0;
        sprintf(buf, "ldnScan channel %d static %p [1]%p %" PRIu64 " buffer %p %" PRIu64 "\n", resp->channel, r.Statics[0], r.Statics[1], r.NumStaticsOut, r.Buffers[0], r.NumBuffers);
        LogStr(buf);
        retval = ldnScan(&sys_service, resp->channel, resp->unk2, &unkOut, r.Buffers[0]);
        sprintf(buf, "ldnScan %d\n", retval);
        LogStr(buf);
        LogHex(r.Buffers[0], 0x1000);
    } else {
        retval = serviceIpcDispatch(&(sys_service.s));
    }

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
        } else if (cmd_id == 102) {
            struct {
                u64 magic;
                u64 result;
                u16 unk1;
            } *r2 = (decltype(r2))cur_out_r.Raw;
            sprintf(buf, "cmd 102 statics: %" PRIu64 " 0 ptr %p size %" PRIu64 "\n",
                cur_out_r.NumStatics, cur_out_r.Statics[0], cur_out_r.StaticSizes[0]);
            LogStr(buf);
            sprintf(buf, "cmd 102 buffers: %" PRIu64 " 0 ptr %p size %" PRIu64 "\n",
                cur_out_r.NumBuffers, cur_out_r.Buffers[0], cur_out_r.BufferSizes[0]);
            LogStr(buf);

            ipcAddSendStatic(&out_c, cur_out_r.Statics[0], cur_out_r.StaticSizes[0], 0);
            struct {
                u64 magic;
                u64 result;
                u16 unk1;
            } *raw = (decltype(raw))serviceIpcPrepareHeader(&sys_service.s, &out_c, sizeof(*raw));
            raw->magic = SFCO_MAGIC;
            raw->result = 0;
            raw->unk1 = r2->unk1;
            LogStr("my resp\n");
            LogHex(armGetTls(), 0x100);
            sprintf(buf, "end 102 %d\n", r2->unk1);
            LogStr(buf);
        }

        // if (cmd_id == 100) {
        //     sprintf(buf, "cmd 100 %x\n", cur_out_r.Handles[0]);
        //     LogStr(buf);

        //     this->sys_event = new StateWaiter(cur_out_r.Handles[0]);
        //     LdnMitMWorker::AddWaitable(this->sys_event);

        //     ipcSendHandleCopy(&out_c, g_state_event->get_handle());
        //     struct {
        //         u64 magic;
        //         u64 result;
        //     } *raw = (decltype(raw))serviceIpcPrepareHeader(&sys_service.s, &out_c, sizeof(*raw));
        //     raw->magic = SFCO_MAGIC;
        //     raw->result = 0;

        //     LogHex(armGetTls(), 0x100);

        //     LogStr("end 100\n");
        // }

        retval = resp->result;
    }

    GetCurrentTime(&t);
    sprintf(buf, "[%" PRIu64 "] mitm dispatch rc %u\n", t, retval);
    LogStr(buf);

    return retval;
}