package io.tomahawkd.cic.pcap.data;

public interface TcpSegment {

    int srcPort();

    int dstPort();

    long seq();

    long ack();

    int offset();

    int headerLength();

    int flags();
    boolean getFlag(int mask);
    boolean flag_cwr();
    boolean flag_ece();
    boolean flag_urg();
    boolean flag_ack();
    boolean flag_psh();
    boolean flag_rst();
    boolean flag_syn();
    boolean flag_fin();

    int window();

    int checksum();

    int urgentPointer();

    byte[] payload();

    int payloadLength();

    // flag mask
    int FLAG_CWR = 0b10000000;
    int FLAG_ECE = 0b01000000;
    int FLAG_URG = 0b00100000;
    int FLAG_ACK = 0b00010000;
    int FLAG_PSH = 0b00001000;
    int FLAG_RST = 0b00000100;
    int FLAG_SYN = 0b00000010;
    int FLAG_FIN = 0b00000001;
}
