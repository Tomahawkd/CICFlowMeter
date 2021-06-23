package io.tomahawkd.cic.data;

public enum MetaFeature implements PackageFeature {

    // Protocols
    IPV4, IPV6, L2TP, TCP, UDP, HTTP,

    // Src and Dst information
    SRC, DST, SRC_PORT, DST_PORT, PROTO
}
