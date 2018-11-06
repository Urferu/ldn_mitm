#include "ldn_icommunication.hpp"

static_assert(sizeof(NetworkInfo) == 0x480, "sizeof(NetworkInfo) should be 0x480");
static_assert(sizeof(ConnectNetworkData) == 0x7C, "sizeof(ConnectNetworkData) should be 0x7C");

static const int ModuleID = 0xFE;
static const int DiscoveryPort = 11452;
static const int BufferSize = 2048;
static const int ScanResultCountMax = 24;
static const u32 LANMagic = 0x114514;

// https://reswitched.github.io/SwIPC/ifaces.html#nn::ldn::detail::IUserLocalCommunicationService


Result ICommunicationInterface::nifmInit() {
    Result rc = smGetService(&nifmSrv, "nifm:u");
    if (R_FAILED(rc)) {
        rc = MAKERESULT(ModuleID, 5);
        goto quit;
    }

    IpcCommand c;
    IpcParsedCommand r;

    ipcInitialize(&c);
    ipcSendPid(&c);
    struct {
        u64 magic;
        u64 cmd_id;
        u64 param;
    } *raw;

    raw = (decltype(raw))serviceIpcPrepareHeader(&nifmSrv, &c, sizeof(*raw));

    raw->magic = SFCI_MAGIC;
    raw->cmd_id = 5;
    raw->param = 0;

    rc = serviceIpcDispatch(&nifmSrv);

    if (R_FAILED(rc)) {
        rc = MAKERESULT(ModuleID, 6);
        goto quit;
    }
    struct {
        u64 magic;
        u64 result;
    } *resp;

    serviceIpcParse(&nifmSrv, &r, sizeof(*resp));
    resp = (decltype(resp))r.Raw;

    rc = resp->result;

    if (R_FAILED(rc)) {
        rc = MAKERESULT(ModuleID, 7);
        goto quit;
    }

    serviceCreateSubservice(&nifmIGS, &nifmSrv, &r, 0);

quit:
    return rc;
}

u32 my_get_ipv4_address() {
    u32 ip_address;
    Result rc = nifmGetCurrentIpAddress(&ip_address);
    char buf[64];

    sprintf(buf, "my get_ipv4_address %d %x\n", rc, ip_address);
    LogStr(buf);

    if (R_SUCCEEDED(rc)) {
        return __builtin_bswap32(ip_address);
    } else {
        return 0xFFFFFFFF;
    }
}

const char *ICommunicationInterface::FakeSsid = "12345678123456781234567812345678";

void ICommunicationInterface::get_fake_mac(u8 mac[6]) {
    mac[0] = 0x02;
    mac[1] = 0x00;
    u32 ip = my_get_ipv4_address();
    memcpy(mac + 2, &ip, sizeof(ip));
}

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
        case LdnCommCmd::GetNetworkConfig:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::get_network_config>(this, r, out_c, pointer_buffer, pointer_buffer_size);
            break;
        case LdnCommCmd::GetSecurityParameter:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::get_security_Parameter>(this, r, out_c, pointer_buffer, pointer_buffer_size);
            break;
        case LdnCommCmd::AttachStateChangeEvent:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::attach_state_change_event>(this, r, out_c, pointer_buffer, pointer_buffer_size);
            break;
        case LdnCommCmd::GetNetworkInfoLatestUpdate:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::get_network_info_latest_update>(this, r, out_c, pointer_buffer, pointer_buffer_size);
            break;
        case LdnCommCmd::Scan:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::scan>(this, r, out_c, pointer_buffer, pointer_buffer_size);
            break;
        case LdnCommCmd::OpenAccessPoint:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::open_access_point>(this, r, out_c, pointer_buffer, pointer_buffer_size);
            break;
        case LdnCommCmd::CloseAccessPoint:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::close_access_point>(this, r, out_c, pointer_buffer, pointer_buffer_size);
            break;
        case LdnCommCmd::DestroyNetwork:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::destroy_network>(this, r, out_c, pointer_buffer, pointer_buffer_size);
            break;
        case LdnCommCmd::CreateNetwork:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::create_network>(this, r, out_c, pointer_buffer, pointer_buffer_size);
            break;
        case LdnCommCmd::OpenStation:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::open_station>(this, r, out_c, pointer_buffer, pointer_buffer_size);
            break;
        case LdnCommCmd::CloseStation:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::close_station>(this, r, out_c, pointer_buffer, pointer_buffer_size);
            break;
        case LdnCommCmd::Connect:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::connect>(this, r, out_c, pointer_buffer, pointer_buffer_size);
            break;
        case LdnCommCmd::Disconnect:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::disconnect>(this, r, out_c, pointer_buffer, pointer_buffer_size);
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

    if (cmd_id == 5) {
        LogStr("cmd 5 resp\n");
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
    if (this->state_event == nullptr) {
        this->state_event = new SystemEvent(NULL, IEvent::PanicCallback);
    }

    return {rc};
}

std::tuple<Result> ICommunicationInterface::open_access_point() {
    Result rc = 0;

    this->init_network_info();
    this->set_state(CommState::AccessPoint);

    return {rc};
}

std::tuple<Result> ICommunicationInterface::close_access_point() {
    Result rc = 0;

    this->set_state(CommState::Initialized);

    return {rc};
}

std::tuple<Result> ICommunicationInterface::destroy_network() {
    Result rc = 0;

    LANDiscovery::set_host(false);
    this->set_state(CommState::AccessPoint);

    return {rc};
}

std::tuple<Result> ICommunicationInterface::open_station() {
    Result rc = 0;

    this->init_network_info();
    this->set_state(CommState::Station);

    return {rc};
}

std::tuple<Result> ICommunicationInterface::close_station() {
    Result rc = 0;

    this->set_state(CommState::Initialized);

    return {rc};
}

std::tuple<Result> ICommunicationInterface::disconnect() {
    Result rc = 0;

    this->set_state(CommState::Station);

    return {rc};
}

std::tuple<Result> ICommunicationInterface::create_network(CreateNetworkConfig data) {
    Result rc = 0;

    LogHex(&data, 0x94);

    this->network_info.ldn.nodeCountMax = data.networkConfig.nodeCountMax;
    this->network_info.ldn.securityMode = data.securityConfig.securityMode;
    if (data.networkConfig.channel == 0) {
        this->network_info.common.channel = 6;
    } else {
        this->network_info.common.channel = data.networkConfig.channel;
    }
    this->network_info.networkId.intentId = data.networkConfig.intentId;
    this->network_info.ldn.nodeCount = 1;
    NodeInfo *nodes = this->network_info.ldn.nodes;
    nodes[0].isConnected = 1;
    strcpy(nodes[0].userName, data.userConfig.userName);
    nodes[0].localCommunicationVersion = data.networkConfig.localCommunicationVersion;

    nodes[0].ipv4Address = my_get_ipv4_address();
    get_fake_mac(nodes[0].macAddress);

#if 1
    this->network_info.ldn.nodeCount++;
    nodes[1].isConnected = 1;
    strcpy(nodes[1].userName, "fuck");
    nodes[1].localCommunicationVersion = nodes[0].localCommunicationVersion;

    nodes[1].ipv4Address = 0xC0A8E999;
    get_fake_mac(nodes[1].macAddress);
#endif

    LANDiscovery::set_host(true);
    LANDiscovery::set_network_info(this->network_info);
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

    this->network_info.ldn.advertiseDataSize = data1.num_elements;
    memcpy(&this->network_info.ldn.advertiseData, data1.pointer, data1.num_elements);

    return {rc};
}

std::tuple<Result, u32> ICommunicationInterface::get_state() {
    Result rc = 0;

    return {rc, static_cast<u32>(this->state)};
}

std::tuple<Result, u32, u32> ICommunicationInterface::get_ipv4_address() {
    u32 ip_address = my_get_ipv4_address();
    char buf[64];

    sprintf(buf, "get_ipv4_address %x\n", ip_address);
    LogStr(buf);

    return {0, ip_address, 0xFFFF0000};
}

std::tuple<Result> ICommunicationInterface::get_network_info(OutPointerWithServerSize<u8, sizeof(NetworkInfo)> buffer) {
    Result rc = 0;

    char buf[128];
    sprintf(buf, "get_network_info %p %" PRIu64 " state: %d\n", buffer.pointer, buffer.num_elements, static_cast<u32>(this->state));
    LogStr(buf);

    if (this->state == CommState::AccessPointCreated || this->state == CommState::StationConnected) {
        memcpy(buffer.pointer, &this->network_info, sizeof(NetworkInfo));
    } else {
        rc = 0x40CB; // ResultConnectionFailed
    }

    return {rc};
}

std::tuple<Result, u16> ICommunicationInterface::get_disconnect_reason() {
    Result rc = 0;

    this->state_event->signal_event();

    return {rc, 0};
}

std::tuple<Result> ICommunicationInterface::get_network_info_latest_update(OutPointerWithServerSize<u8, 0x480> buffer1, OutPointerWithServerSize<u8, 0x8> buffer2) {
    Result rc = 0;

    char buf[128];
    sprintf(buf, "get_network_info_latest_update1 %p %" PRIu64 "\n", buffer1.pointer, buffer1.num_elements);
    LogStr(buf);
    sprintf(buf, "get_network_info_latest_update2 %p %" PRIu64 "\n", buffer2.pointer, buffer2.num_elements);
    LogStr(buf);

    NodeLatestUpdate update = {0};
    update.stateChange = 0; // None

    if (this->state == CommState::AccessPointCreated || this->state == CommState::StationConnected) {
        LANDiscovery::get_network_info(&this->network_info);
        memcpy(buffer1.pointer, &this->network_info, sizeof(NetworkInfo));
        memcpy(buffer2.pointer, &update, sizeof(update));
    } else {
        rc = 0x40CB; // ResultConnectionFailed
    }

    return {rc};
}

std::tuple<Result, SecurityParameter> ICommunicationInterface::get_security_Parameter() {
    Result rc = 0;

    SecurityParameter data;
    NetworkInfo2SecurityParameter(&this->network_info, &data);

    return {rc, data};
}

std::tuple<Result, NetworkConfig> ICommunicationInterface::get_network_config() {
    Result rc = 0;

    NetworkConfig data;
    NetworkInfo2NetworkConfig(&this->network_info, &data);

    return {rc, data};
}

std::tuple<Result, CopiedHandle> ICommunicationInterface::attach_state_change_event() {
    return {0, this->state_event->get_handle()};
}

std::tuple<Result, u16> ICommunicationInterface::scan(OutPointerWithServerSize<u8, 0> pointer, OutBuffer<NetworkInfo> buffer, u16 bufferCount) {
    bufferCount = 8;
    u16 outCount = 0;
    LANDiscovery::scan(buffer.buffer, &outCount, bufferCount);
    char buf[128];
    sprintf(buf, "scan %d %d\n", bufferCount, outCount);
    LogStr(buf);

    return {0, outCount};
}

std::tuple<Result> ICommunicationInterface::connect(ConnectNetworkData dat, InPointer<u8> data) {
    char buf[64];
    sprintf(buf, "ICommunicationInterface::connect %" PRIu64 "\n", data.num_elements);
    LogStr(buf);
    LogHex(data.pointer, sizeof(NetworkInfo));
    LogHex(&dat, sizeof(dat));

    memcpy(&this->network_info, data.pointer, sizeof(NetworkInfo));

    this->network_info.ldn.nodeCount++;
    NodeInfo *nodes = this->network_info.ldn.nodes;
    nodes[1].isConnected = 1;
    strcpy(nodes[1].userName, dat.userConfig.userName);
    nodes[1].localCommunicationVersion = nodes[0].localCommunicationVersion;

    nodes[1].ipv4Address = my_get_ipv4_address();
    get_fake_mac(nodes[1].macAddress);

    this->set_state(CommState::StationConnected);

    return {0};
}

Result IMitMCommunicationInterface::dispatch(IpcParsedCommand &r, IpcCommand &out_c, u64 cmd_id, u8 *pointer_buffer, size_t pointer_buffer_size) {
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
    } else if (cmd_id == 101) { // GetNetworkInfoLatestUpdate
        sprintf(buf, "GetNetworkInfoLatestUpdate static %" PRIu64 " buffer %" PRIu64 "\n", r.NumStaticsOut, r.NumBuffers);
        LogStr(buf);
    } else if (cmd_id == 102) { // scan
        struct {
            u64 magic;
            u64 result;
            u16 channel;
            u8 unk2[0x60];
        } *resp = (decltype(resp))r.Raw;
        u16 unkOut = 0;
        retval = ldnScan(&sys_service, resp->channel, resp->unk2, &unkOut, r.Buffers[0]);
        sprintf(buf, "ldnScan %d\n", retval);
        LogStr(buf);
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
            LogHex(out_c.Statics[0], cur_out_r.StaticSizes[0]);
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
        } else if (cmd_id == 202) {
            u8 backup[0x100];
            memcpy(backup, armGetTls(), 0x100);
            u8 info[0x480] = {0};
            retval = ldnGetNetworkInfo(&sys_service, &info);
            sprintf(buf, "ldnGetNetworkInfo %d\n", retval);
            LogStr(buf);
            LogHex(info, 0x480);
            memcpy(armGetTls(), backup, 0x100);
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