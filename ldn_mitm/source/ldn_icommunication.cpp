#include "ldn_icommunication.hpp"

// https://reswitched.github.io/SwIPC/ifaces.html#nn::ldn::detail::IUserLocalCommunicationService

enum class LdnCommCmd {
    GetState = 0,
    GetIpv4Address = 2,
    GetSecurityParameter = 4,
    OpenAccessPoint = 200,
    CreateNetwork = 202,
    SetAdvertiseData = 206,
    Initialize = 400,
};

Result ICommunicationInterface::dispatch(IpcParsedCommand &r, IpcCommand &out_c, u64 cmd_id, u8 *pointer_buffer, size_t pointer_buffer_size) {
    Result rc = 0xF601;
    char buf[128];
    sprintf(buf, "ICommunicationInterface::dispatch cmd_id: %" PRIu64 "\n", cmd_id);
    LogStr(buf);

    if (static_cast<LdnCommCmd>(cmd_id) == LdnCommCmd::CreateNetwork) {
        LogHex(armGetTls(), 0x100);
    }

    switch (static_cast<LdnCommCmd>(cmd_id)) {
        case LdnCommCmd::GetState:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::get_state>(this, r, out_c, pointer_buffer, pointer_buffer_size);
            break;
        case LdnCommCmd::GetIpv4Address:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::get_ipv4_address>(this, r, out_c, pointer_buffer, pointer_buffer_size);
            break;
        case LdnCommCmd::GetSecurityParameter:
            rc = WrapIpcCommandImpl<&ICommunicationInterface::get_security_Parameter>(this, r, out_c, pointer_buffer, pointer_buffer_size);
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

    sprintf(buf, "ICommunicationInterface::dispatch rc: %x\n", rc);
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

    this->state = CommState::Initialized;

    return {rc};
}

std::tuple<Result> ICommunicationInterface::open_access_point() {
    Result rc = 0;

    this->state = CommState::AccessPoint;

    return {rc};
}

std::tuple<Result> ICommunicationInterface::create_network(CreateNetworkData data) {
    Result rc = 0;

    LogHex(data.dat, 0x94);
    this->state = CommState::AccessPointCreated;

    return {rc};
}

std::tuple<Result> ICommunicationInterface::set_advertise_data(InPointer<u8> data1, InBuffer<u8> data2) {
    Result rc = 0;

    char buf[128];
    sprintf(buf, "ICommunicationInterface::set_advertise_data length data1: %" PRIu64 " data2: %" PRIu64 "\n", data1.num_elements, data2.num_elements);
    LogStr(buf);

    return {rc};
}

std::tuple<Result, u64> ICommunicationInterface::get_state() {
    Result rc = 0;

    return {rc, static_cast<u64>(this->state)};
}

std::tuple<Result, u32, u32> ICommunicationInterface::get_ipv4_address() {
    Result rc = 0;

    return {rc, 0x7F000001, 0xFF000000};
}

std::tuple<Result, GetSecurityParameterData> ICommunicationInterface::get_security_Parameter() {
    Result rc = 0;

    GetSecurityParameterData data;

    return {rc, data};
}
