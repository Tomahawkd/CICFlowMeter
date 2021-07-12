package io.tomahawkd.cic.packet;

public abstract class AbstractPacketDelegate implements PacketDelegate {

    private final int id;

    public AbstractPacketDelegate(int id) {
        this.id = id;
    }

}
