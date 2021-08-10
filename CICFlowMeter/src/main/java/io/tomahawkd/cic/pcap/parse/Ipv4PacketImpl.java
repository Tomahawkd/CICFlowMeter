package io.tomahawkd.cic.pcap.parse;

import io.kaitai.struct.ByteBufferKaitaiStream;
import io.kaitai.struct.KaitaiStream;
import io.kaitai.struct.KaitaiStruct;
import io.tomahawkd.cic.pcap.data.Ipv4Packet;

import java.util.ArrayList;

public class Ipv4PacketImpl extends KaitaiStruct implements Ipv4Packet {

    private int version;
    private int ihl;
    private int ihlBytes;
    private int serviceType;
    private int totalLength;
    private int identification;
    private int b67;
    private int ttl;
    private int protocol;
    private int headerChecksum;
    private byte[] srcIpAddr;
    private byte[] dstIpAddr;
    private Ipv4Options options;
    private TcpSegmentImpl body;

    private final Ipv4PacketImpl _root;
    private final KaitaiStruct _parent;

    public Ipv4PacketImpl(KaitaiStream _io) {
        this(_io, null, null);
    }

    public Ipv4PacketImpl(KaitaiStream _io, KaitaiStruct _parent, Ipv4PacketImpl _root) {
        super(_io);
        this._parent = _parent;
        this._root = _root == null ? this : _root;
        _read();
    }

    private void _read() {
        int b1 = this._io.readU1();
        this.version = (b1 & 0b11110000) >> 4;
        this.ihl = b1 & 0b00001111;
        this.ihlBytes = ihl * 4;
        this.serviceType = this._io.readU1();
        this.totalLength = this._io.readU2be();
        this.identification = this._io.readU2be();
        this.b67 = this._io.readU2be();
        this.ttl = this._io.readU1();
        this.protocol = this._io.readU1();
        this.headerChecksum = this._io.readU2be();
        this.srcIpAddr = this._io.readBytes(4);
        this.dstIpAddr = this._io.readBytes(4);
        byte[] _raw_options = this._io.readBytes((ihlBytes - 20));
        this.options = new Ipv4Options(new ByteBufferKaitaiStream(_raw_options), this, _root);
        byte[] _raw_body = this._io.readBytes((totalLength - ihlBytes));
        Protocol protocol = Protocol.byId(protocol());
        if (protocol == Protocol.TCP) {
            this.body = new TcpSegmentImpl(new ByteBufferKaitaiStream(_raw_body));
        }
    }

    public static class Ipv4Options extends KaitaiStruct {

        private ArrayList<Ipv4Option> entries;
        private final Ipv4PacketImpl _root;
        private final Ipv4PacketImpl _parent;

        public Ipv4Options(KaitaiStream _io, Ipv4PacketImpl _parent, Ipv4PacketImpl _root) {
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

        public Ipv4PacketImpl _root() {
            return _root;
        }

        public Ipv4PacketImpl _parent() {
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
        private final Ipv4PacketImpl _root;
        private final Ipv4PacketImpl.Ipv4Options _parent;

        public Ipv4Option(KaitaiStream _io, Ipv4PacketImpl.Ipv4Options _parent, Ipv4PacketImpl _root) {
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

        public Ipv4PacketImpl _root() {
            return _root;
        }

        public Ipv4PacketImpl.Ipv4Options _parent() {
            return _parent;
        }
    }

    @Override
    public int version() {
        return this.version;
    }

    @Override
    public int ihl() {
        return this.ihl;
    }

    @Override
    public int ihlBytes() {
        return this.ihlBytes;
    }

    @Override
    public int serviceType() {
        return serviceType;
    }

    @Override
    public int totalLength() {
        return totalLength;
    }

    @Override
    public int identification() {
        return identification;
    }

    public int b67() {
        return b67;
    }

    @Override
    public int ttl() {
        return ttl;
    }

    @Override
    public int protocol() {
        return protocol;
    }

    @Override
    public int headerChecksum() {
        return headerChecksum;
    }

    @Override
    public byte[] source() {
        return srcIpAddr;
    }

    @Override
    public byte[] destination() {
        return dstIpAddr;
    }

    public Ipv4Options options() {
        return options;
    }

    public TcpSegmentImpl body() {
        return body;
    }

    public Ipv4PacketImpl _root() {
        return _root;
    }

    public KaitaiStruct _parent() {
        return _parent;
    }
}
