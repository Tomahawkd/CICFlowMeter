package io.tomahawkd.cic.pcap.parse;

public interface PcapPacket {

    EthernetFrame ethernet();

    long getTimestamp();
}
