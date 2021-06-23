package io.tomahawkd.cic.data;

import org.jnetpcap.packet.PcapPacket;

public abstract class AbstractPackageDelegate implements PackageDelegate {

    private final int id;

    public AbstractPackageDelegate(int id) {
        this.id = id;
    }

    @Override
    public boolean canAccept(PcapPacket packet) {
        packet.scan(id);
        return packet.hasHeader(id);
    }
}
