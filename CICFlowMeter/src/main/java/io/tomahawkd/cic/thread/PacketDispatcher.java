package io.tomahawkd.cic.thread;

import io.tomahawkd.cic.packet.PacketInfo;

public interface PacketDispatcher {

    void dispatch(PacketInfo info);

    long getFlowCount();
}
