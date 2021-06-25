package io.tomahawkd.cic.data;

import org.jnetpcap.packet.PcapPacket;

public interface PackageDelegate {

    boolean parse(PackageInfo dst, PcapPacket packet);
}
