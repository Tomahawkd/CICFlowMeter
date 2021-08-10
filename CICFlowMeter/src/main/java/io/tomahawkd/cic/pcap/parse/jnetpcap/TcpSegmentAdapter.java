package io.tomahawkd.cic.pcap.parse.jnetpcap;

import io.tomahawkd.cic.pcap.data.TcpSegment;
import org.jnetpcap.protocol.tcpip.Tcp;

public class TcpSegmentAdapter implements TcpSegment {

    private final Tcp tcp;

    public TcpSegmentAdapter(Tcp tcp) {
        this.tcp = tcp;
    }

    @Override
    public int srcPort() {
        return tcp.source();
    }

    @Override
    public int dstPort() {
        return tcp.destination();
    }

    @Override
    public long seq() {
        return tcp.seq();
    }

    @Override
    public long ack() {
        return tcp.ack();
    }

    @Override
    public int offset() {
        return tcp.hlen();
    }

    @Override
    public int headerLength() {
        return tcp.getHeaderLength();
    }

    @Override
    public int flags() {
        return tcp.flags();
    }

    @Override
    public boolean getFlag(int mask) {
        return (flags() & mask) != 0;
    }

    @Override
    public boolean flag_cwr() {
        return tcp.flags_CWR();
    }

    @Override
    public boolean flag_ece() {
        return tcp.flags_ECE();
    }

    @Override
    public boolean flag_urg() {
        return tcp.flags_URG();
    }

    @Override
    public boolean flag_ack() {
        return tcp.flags_ACK();
    }

    @Override
    public boolean flag_psh() {
        return tcp.flags_PSH();
    }

    @Override
    public boolean flag_rst() {
        return tcp.flags_RST();
    }

    @Override
    public boolean flag_syn() {
        return tcp.flags_SYN();
    }

    @Override
    public boolean flag_fin() {
        return tcp.flags_FIN();
    }

    @Override
    public int window() {
        return tcp.window();
    }

    @Override
    public int checksum() {
        return tcp.checksum();
    }

    @Override
    public int urgentPointer() {
        return tcp.urgent();
    }

    @Override
    public byte[] payload() {
        return tcp.getPayload();
    }

    @Override
    public int payloadLength() {
        return tcp.getPayloadLength();
    }
}
