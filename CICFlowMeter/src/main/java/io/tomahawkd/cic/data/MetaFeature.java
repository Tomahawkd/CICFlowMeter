package io.tomahawkd.cic.data;

public enum MetaFeature implements PacketFeature {

    // Protocols
    IPV4, IPV6, TCP, UDP, HTTP,

    // Src and Dst information
    SRC, DST, SRC_PORT, DST_PORT, PROTO, PAYLOAD_LEN, HEADER_LEN
}
