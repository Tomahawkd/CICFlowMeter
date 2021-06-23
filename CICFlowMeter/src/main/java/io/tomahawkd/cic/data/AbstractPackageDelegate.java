package io.tomahawkd.cic.data;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;

public abstract class AbstractPackageDelegate implements PackageDelegate {

    private final int id;

    public AbstractPackageDelegate(int id) {
        this.id = id;
    }

    @Override
    public boolean canAccept(PcapPacket packet) {
        packet.scan(Ethernet.ID);
        return packet.hasHeader(id);
    }
}
