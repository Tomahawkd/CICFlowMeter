package io.tomahawkd.cic.pcap;

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import io.kaitai.struct.KaitaiStream;
import io.kaitai.struct.KaitaiStruct;


/**
 * TCP is one of the core Internet protocols on transport layer (AKA
 * OSI layer 4), providing stateful connections with error checking,
 * guarantees of delivery, order of segments and avoidance of duplicate
 * delivery.
 */
public class TcpSegment extends KaitaiStruct {

    private int srcPort;
    private int dstPort;
    private long seqNum;
    private long ackNum;
    private int offset;
    private int flags;
    private int windowSize;
    private int checksum;
    private int urgentPointer;
    private byte[] optionsAndPaddings;
    private byte[] body;
    private final TcpSegment _root;
    private final KaitaiStruct _parent;

    public TcpSegment(KaitaiStream _io) {
        this(_io, null, null);
    }

    public TcpSegment(KaitaiStream _io, KaitaiStruct _parent, TcpSegment _root) {
        super(_io);
        this._parent = _parent;
        this._root = _root == null ? this : _root;
        _read();
    }

    private void _read() {
        this.srcPort = this._io.readU2be();
        this.dstPort = this._io.readU2be();
        this.seqNum = this._io.readU4be();
        this.ackNum = this._io.readU4be();

        // copied from https://datatracker.ietf.org/doc/html/rfc3168#section-23.2
        //      0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15
        //   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
        //   |               |               | C | E | U | A | P | R | S | F |
        //   | Header Length |    Reserved   | W | C | R | C | S | S | Y | I |
        //   |               |               | R | E | G | K | H | T | N | N |
        //   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
        //
        int b12 = this._io.readU1();
        this.offset = (b12 & 0b11110000) >> 4;
        this.flags = this._io.readU1();
        this.windowSize = this._io.readU2be();
        this.checksum = this._io.readU2be();
        this.urgentPointer = this._io.readU2be();
        // the first 5 lines (32 bits/4 bytes per line) are mandatory
        if (offset > 5) {
            this.optionsAndPaddings = this._io.readBytes((offset - 5) * 4L);
        }
        this.body = this._io.readBytesFull();
    }

    public int srcPort() {
        return srcPort;
    }

    public int dstPort() {
        return dstPort;
    }

    public long seqNum() {
        return seqNum;
    }

    public long ackNum() {
        return ackNum;
    }

    public int offset() {
        return offset;
    }

    public int flags() {
        return flags;
    }

    public boolean getFlag(int mask) {
        return (flags & mask) != 0;
    }

    public boolean flag_cwr() {
        return getFlag(FLAG_CWR);
    }

    public boolean flag_ece() {
        return getFlag(FLAG_ECE);
    }

    public boolean flag_urg() {
        return getFlag(FLAG_URG);
    }

    public boolean flag_ack() {
        return getFlag(FLAG_ACK);
    }

    public boolean flag_psh() {
        return getFlag(FLAG_PSH);
    }

    public boolean flag_rst() {
        return getFlag(FLAG_RST);
    }

    public boolean flag_syn() {
        return getFlag(FLAG_SYN);
    }

    public boolean flag_fin() {
        return getFlag(FLAG_FIN);
    }

    public int windowSize() {
        return windowSize;
    }

    public int checksum() {
        return checksum;
    }

    public int urgentPointer() {
        return urgentPointer;
    }

    public byte[] optionsAndPaddings() {
        return optionsAndPaddings;
    }

    public byte[] body() {
        return body;
    }

    public TcpSegment _root() {
        return _root;
    }

    public KaitaiStruct _parent() {
        return _parent;
    }

    // flag mask
    public static final int FLAG_CWR = 0b10000000;
    public static final int FLAG_ECE = 0b01000000;
    public static final int FLAG_URG = 0b00100000;
    public static final int FLAG_ACK = 0b00010000;
    public static final int FLAG_PSH = 0b00001000;
    public static final int FLAG_RST = 0b00000100;
    public static final int FLAG_SYN = 0b00000010;
    public static final int FLAG_FIN = 0b00000001;
}
