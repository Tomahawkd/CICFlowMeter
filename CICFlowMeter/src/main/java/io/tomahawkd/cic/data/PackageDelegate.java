package io.tomahawkd.cic.data;

import org.jnetpcap.packet.PcapPacket;

public interface PackageDelegate {

    boolean canAccept(PcapPacket packet);

    void parse(PackageInfo dst, PcapPacket packet);
}
