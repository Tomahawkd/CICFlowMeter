package io.tomahawkd.cic.packet;

import org.jnetpcap.packet.PcapPacket;

public interface PacketDelegate {

    boolean parse(PacketInfo dst, PcapPacket packet);
}
