package io.tomahawkd.cic.packet;


import io.tomahawkd.cic.pcap.parse.PcapPacket;

public interface PacketDelegate {

    boolean parse(PacketInfo dst, PcapPacket packet);
}
