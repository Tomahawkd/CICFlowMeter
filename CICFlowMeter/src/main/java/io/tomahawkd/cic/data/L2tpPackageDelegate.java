package io.tomahawkd.cic.data;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.vpn.L2TP;

public class L2tpPackageDelegate extends AbstractPackageDelegate {

    public L2tpPackageDelegate() {
        super(L2TP.ID);
    }

    @Override
    public void parse(PackageInfo dst, PcapPacket packet) {
        packet.scan(Ethernet.ID);
    }
}
