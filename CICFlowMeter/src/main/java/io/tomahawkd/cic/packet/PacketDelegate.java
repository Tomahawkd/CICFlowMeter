package io.tomahawkd.cic.packet;

import io.tomahawkd.cic.kaitai.Pcap;

public interface PacketDelegate {

    boolean parse(PacketInfo dst, Pcap.Packet packet);
}
