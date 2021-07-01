package io.tomahawkd.cic.data;

public abstract class AbstractPacketDelegate implements PacketDelegate {

    private final int id;

    public AbstractPacketDelegate(int id) {
        this.id = id;
    }

}
