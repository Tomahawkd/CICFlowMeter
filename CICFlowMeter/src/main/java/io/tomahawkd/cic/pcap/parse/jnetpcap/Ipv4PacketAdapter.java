package io.tomahawkd.cic.pcap.parse.jnetpcap;

import io.tomahawkd.cic.pcap.data.Ipv4Packet;
import org.jnetpcap.protocol.network.Ip4;

public class Ipv4PacketAdapter implements Ipv4Packet {

    private final Ip4 ip4;

    public Ipv4PacketAdapter(Ip4 ip4) {
        this.ip4 = ip4;
    }

    @Override
    public int version() {
        return ip4.version();
    }

    @Override
    public int ihl() {
        return ip4.hlen();
    }

    @Override
    public int ihlBytes() {
        return ihl() * 4;
    }

    @Override
    public int serviceType() {
        return ip4.type();
    }

    @Override
    public int totalLength() {
        return ip4.length();
    }

    @Override
    public int identification() {
        return ip4.id();
    }

    @Override
    public int ttl() {
        return ip4.ttl();
    }

    // NOT IMPLEMENTED
    @Override
    public int protocol() {
        throw new IllegalArgumentException("Not Implement yet");
    }

    @Override
    public int headerChecksum() {
        return ip4.checksum();
    }

    @Override
    public byte[] source() {
        return ip4.source();
    }

    @Override
    public byte[] destination() {
        return ip4.destination();
    }
}
