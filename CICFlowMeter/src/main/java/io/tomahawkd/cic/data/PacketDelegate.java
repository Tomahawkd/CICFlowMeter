package io.tomahawkd.cic.data;

import org.jnetpcap.packet.PcapPacket;

public interface PacketDelegate {

    boolean parse(PacketInfo dst, PcapPacket packet);
}
