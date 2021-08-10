package io.tomahawkd.cic.pcap.parse;

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import io.kaitai.struct.ByteBufferKaitaiStream;
import io.kaitai.struct.KaitaiStream;
import io.kaitai.struct.KaitaiStruct;

import java.util.ArrayList;

public class Ipv4Packet extends KaitaiStruct {

    private int b1;
    private int b2;
    private int totalLength;
    private int identification;
    private int b67;
    private int ttl;
    private int protocol;
    private int headerChecksum;
    private byte[] srcIpAddr;
    private byte[] dstIpAddr;
    private Ipv4Options options;
    private TcpSegment body;
    private final Ipv4Packet _root;
    private final KaitaiStruct _parent;

    private Integer version;
    private Integer ihl;
    private Integer ihlBytes;

    public Ipv4Packet(KaitaiStream _io) {
        this(_io, null, null);
    }

    public Ipv4Packet(KaitaiStream _io, KaitaiStruct _parent, Ipv4Packet _root) {
        super(_io);
        this._parent = _parent;
        this._root = _root == null ? this : _root;
        _read();
    }

    private void _read() {
        this.b1 = this._io.readU1();
        this.b2 = this._io.readU1();
        this.totalLength = this._io.readU2be();
        this.identification = this._io.readU2be();
        this.b67 = this._io.readU2be();
        this.ttl = this._io.readU1();
        this.protocol = this._io.readU1();
        this.headerChecksum = this._io.readU2be();
        this.srcIpAddr = this._io.readBytes(4);
        this.dstIpAddr = this._io.readBytes(4);
        byte[] _raw_options = this._io.readBytes((ihlBytes() - 20));
        this.options = new Ipv4Options(new ByteBufferKaitaiStream(_raw_options), this, _root);
        byte[] _raw_body = this._io.readBytes((totalLength() - ihlBytes()));
        Protocol protocol = Protocol.byId(protocol());
        if (protocol == Protocol.TCP) {
            this.body = new TcpSegment(new ByteBufferKaitaiStream(_raw_body));
        }
    }

    public static class Ipv4Options extends KaitaiStruct {

        private ArrayList<Ipv4Option> entries;
        private final Ipv4Packet _root;
        private final Ipv4Packet _parent;

        public Ipv4Options(KaitaiStream _io, Ipv4Packet _parent, Ipv4Packet _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }

        private void _read() {
            this.entries = new ArrayList<>();
            while (!this._io.isEof()) {
                this.entries.add(new Ipv4Option(this._io, this, _root));
            }
        }

        public ArrayList<Ipv4Option> entries() {
            return entries;
        }

        public Ipv4Packet _root() {
            return _root;
        }

        public Ipv4Packet _parent() {
            return _parent;
        }
    }

    public static class Ipv4Option extends KaitaiStruct {

        private Integer copy;
        private Integer optClass;
        private Integer number;
        private int b1;
        private int len;
        private byte[] body;
        private final Ipv4Packet _root;
        private final Ipv4Packet.Ipv4Options _parent;

        public Ipv4Option(KaitaiStream _io, Ipv4Packet.Ipv4Options _parent, Ipv4Packet _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }

        private void _read() {
            this.b1 = this._io.readU1();
            this.len = this._io.readU1();
            this.body = this._io.readBytes((len() > 2 ? (len() - 2) : 0));
        }

        public Integer copy() {
            if (this.copy != null)
                return this.copy;
            this.copy = ((b1() & 128) >> 7);
            return this.copy;
        }

        public Integer optClass() {
            if (this.optClass != null)
                return this.optClass;
            this.optClass = ((b1() & 96) >> 5);
            return this.optClass;
        }

        public Integer number() {
            if (this.number != null)
                return this.number;
            this.number = (b1() & 31);
            return this.number;
        }

        public int b1() {
            return b1;
        }

        public int len() {
            return len;
        }

        public byte[] body() {
            return body;
        }

        public Ipv4Packet _root() {
            return _root;
        }

        public Ipv4Packet.Ipv4Options _parent() {
            return _parent;
        }
    }

    public Integer version() {
        if (this.version != null) return this.version;
        this.version = ((b1() & 240) >> 4);
        return this.version;
    }

    public Integer ihl() {
        if (this.ihl != null) return this.ihl;
        this.ihl = (b1() & 15);
        return this.ihl;
    }

    public Integer ihlBytes() {
        if (this.ihlBytes != null) return this.ihlBytes;
        this.ihlBytes = (ihl() * 4);
        return this.ihlBytes;
    }

    public int b1() {
        return b1;
    }

    public int b2() {
        return b2;
    }

    public int totalLength() {
        return totalLength;
    }

    public int identification() {
        return identification;
    }

    public int b67() {
        return b67;
    }

    public int ttl() {
        return ttl;
    }

    public int protocol() {
        return protocol;
    }

    public int headerChecksum() {
        return headerChecksum;
    }

    public byte[] srcIpAddr() {
        return srcIpAddr;
    }

    public byte[] dstIpAddr() {
        return dstIpAddr;
    }

    public Ipv4Options options() {
        return options;
    }

    public TcpSegment body() {
        return body;
    }

    public Ipv4Packet _root() {
        return _root;
    }

    public KaitaiStruct _parent() {
        return _parent;
    }
}
