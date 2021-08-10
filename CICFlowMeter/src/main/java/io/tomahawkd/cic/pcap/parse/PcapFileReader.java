package io.tomahawkd.cic.pcap.parse;

public interface PcapFileReader {

    boolean hasNext();

    PcapPacket next();
}
