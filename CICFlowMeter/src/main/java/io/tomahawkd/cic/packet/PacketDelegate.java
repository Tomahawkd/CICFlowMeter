package io.tomahawkd.cic.packet;

import io.tomahawkd.cic.kaitai.Packet;

public interface PacketDelegate {

    boolean parse(PacketInfo dst, Packet packet);
}
