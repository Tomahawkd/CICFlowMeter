package io.tomahawkd.cic.pcap.parse;

import io.tomahawkd.cic.pcap.data.Ipv4Packet;
import io.tomahawkd.cic.pcap.data.TcpSegment;

public interface PcapPacket {

    Ipv4Packet ip();

    TcpSegment tcp();

    long getTimestamp();
}
