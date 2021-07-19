package io.tomahawkd.cic.kaitai;

// This is a generated file but has some modifications.

import io.kaitai.struct.ByteBufferKaitaiStream;
import io.kaitai.struct.KaitaiStream;
import io.kaitai.struct.KaitaiStruct;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;


/**
 * PCAP (named after libpcap / winpcap) is a popular format for saving
 * network traffic grabbed by network sniffers. It is typically
 * produced by tools like [tcpdump](https://www.tcpdump.org/) or
 * [Wireshark](https://www.wireshark.org/).
 *
 * @see <a href="http://wiki.wireshark.org/Development/LibpcapFileFormat">Source</a>
 */
public class Pcap extends KaitaiStruct {

    private final Header hdr;
    private final Pcap _root;

    public static Pcap fromFile(String fileName) throws IOException {
        return new Pcap(new ByteBufferKaitaiStream(fileName));
    }

    public Pcap(KaitaiStream _io) {
        super(_io);
        this._root = this;
        this.hdr = new Header(this._io, this, _root);
    }

    public boolean hasNext() {
        return !this._io.isEof();
    }

    public Packet next() {
        return hasNext() ? new Packet(this._io, this, _root) : null;
    }

    // for compatibility leave empty here
    @SuppressWarnings("unused")
    private void _read() {
    }

    public Header hdr() {
        return hdr;
    }

    public KaitaiStruct _parent() {
        return null;
    }

    /**
     * @see <a href="https://wiki.wireshark.org/Development/LibpcapFileFormat#Global_Header">Source</a>
     */
    public static class Header extends KaitaiStruct {

        private byte[] magicNumber;

        /**
         * Major version, currently 2.
         */
        private int versionMajor;

        /**
         * Minor version, currently 4.
         */
        private int versionMinor;

        /**
         * the correction time in seconds between GMT (UTC) and the local timezone of
         * the following packet header timestamps. In practice, time stamps are always in GMT, so thiszone is always 0.
         */
        private int thiszone;

        /**
         * in theory, the accuracy of time stamps in the capture; in practice, all tools set it to 0.
         */
        private long sigfigs;

        /**
         * the snapshot length for the capture (typically 65535 or even more, but might be limited by the user).
         */
        private long snaplen;

        /**
         * link-layer header type.
         */
        private Linktype network;

        private final Pcap _root;
        private final Pcap _parent;

        public Header(KaitaiStream _io, Pcap _parent, Pcap _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }

        private void _read() {
            this.magicNumber = this._io.readBytes(4);
            if (!(Arrays.equals(magicNumber(), new byte[] {-44, -61, -78, -95}))) {
                throw new KaitaiStream.ValidationNotEqualError(new byte[] {-44, -61, -78, -95}, magicNumber(), _io(), "/types/header/seq/0");
            }
            this.versionMajor = this._io.readU2le();
            this.versionMinor = this._io.readU2le();
            this.thiszone = this._io.readS4le();
            this.sigfigs = this._io.readU4le();
            this.snaplen = this._io.readU4le();
            this.network = Pcap.Linktype.byId(this._io.readU4le());
        }

        public byte[] magicNumber() {
            return magicNumber;
        }

        public int versionMajor() {
            return versionMajor;
        }

        public int versionMinor() {
            return versionMinor;
        }

        /**
         * Correction time in seconds between UTC and the local
         * timezone of the following packet header timestamps.
         */
        public int thiszone() {
            return thiszone;
        }

        /**
         * In theory, the accuracy of time stamps in the capture; in
         * practice, all tools set it to 0.
         */
        public long sigfigs() {
            return sigfigs;
        }

        /**
         * The "snapshot length" for the capture (typically 65535 or
         * even more, but might be limited by the user), see: incl_len
         * vs. orig_len.
         */
        public long snaplen() {
            return snaplen;
        }

        /**
         * Link-layer header type, specifying the type of headers at
         * the beginning of the packet.
         */
        public Linktype network() {
            return network;
        }

        public Pcap _root() {
            return _root;
        }

        public Pcap _parent() {
            return _parent;
        }
    }

    /**
     * @see <a href="https://wiki.wireshark.org/Development/LibpcapFileFormat#Record_.28Packet.29_Header">Source</a>
     */
    public static class Packet extends KaitaiStruct {

        /**
         * The date and time when this packet was captured. This value is in seconds since January 1, 1970 00:00:00 GMT.
         */
        private long tsSec;

        /**
         * the microseconds when this packet was captured, as an offset to ts_sec.
         */
        private long tsUsec;

        /**
         * the number of bytes of packet data actually captured and saved in the file.
         * This value should never become larger than orig_len or the snaplen value of the global header.
         */
        private long inclLen;

        /**
         * the length in bytes of the packet as it appeared on the network when it was captured.
         * If incl_len and orig_len differ, the actually saved packet size was limited by snaplen.
         */
        private long origLen;

        /**
         * Parsed Packet body/content
         */
        private Object body;
        private byte[] _raw_body;

        private final Pcap _root;
        private final Pcap _parent;

        public Packet(KaitaiStream _io, Pcap _parent, Pcap _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }

        private void _read() {
            this.tsSec = this._io.readU4le();
            this.tsUsec = this._io.readU4le();
            this.inclLen = this._io.readU4le();
            this.origLen = this._io.readU4le();
            {
                Linktype on = _root.hdr().network();
                if (on != null) {
                    if (_root.hdr().network() == Linktype.ETHERNET) {
                        this._raw_body = this._io.readBytes(inclLen());
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new EthernetFrame(_io__raw_body);
                    } else {
                        this.body = this._io.readBytes(inclLen());
                    }
                } else {
                    this.body = this._io.readBytes(inclLen());
                }
            }
        }

        public boolean isEthernetPacket() {
            return _root.hdr().network() == Linktype.ETHERNET;
        }

        public EthernetFrame getEthernetPacket() {
            if (isEthernetPacket()) return (EthernetFrame) this.body;
            else return null;
        }

        /**
         * @see Packet#tsSec
         */
        public long tsSec() {
            return tsSec;
        }

        /**
         * @see Packet#tsUsec
         */
        public long tsUsec() {
            return tsUsec;
        }

        /**
         * Number of bytes of packet data actually captured and saved in the file.
         */
        public long inclLen() {
            return inclLen;
        }

        /**
         * Length of the packet as it appeared on the network when it was captured.
         */
        public long origLen() {
            return origLen;
        }

        /**
         * @see <a href="https://wiki.wireshark.org/Development/LibpcapFileFormat#Packet_Data">Source</a>
         */
        public Object body() {
            return body;
        }

        public Pcap _parent() {
            return _parent;
        }

        public byte[] _raw_body() {
            return _raw_body;
        }
    }

    public enum Linktype {
        NULL_LINKTYPE(0),
        ETHERNET(1),
        AX25(3),
        IEEE802_5(6),
        ARCNET_BSD(7),
        SLIP(8),
        PPP(9),
        FDDI(10),
        PPP_HDLC(50),
        PPP_ETHER(51),
        ATM_RFC1483(100),
        RAW(101),
        C_HDLC(104),
        IEEE802_11(105),
        FRELAY(107),
        LOOP(108),
        LINUX_SLL(113),
        LTALK(114),
        PFLOG(117),
        IEEE802_11_PRISM(119),
        IP_OVER_FC(122),
        SUNATM(123),
        IEEE802_11_RADIOTAP(127),
        ARCNET_LINUX(129),
        APPLE_IP_OVER_IEEE1394(138),
        MTP2_WITH_PHDR(139),
        MTP2(140),
        MTP3(141),
        SCCP(142),
        DOCSIS(143),
        LINUX_IRDA(144),
        USER0(147),
        USER1(148),
        USER2(149),
        USER3(150),
        USER4(151),
        USER5(152),
        USER6(153),
        USER7(154),
        USER8(155),
        USER9(156),
        USER10(157),
        USER11(158),
        USER12(159),
        USER13(160),
        USER14(161),
        USER15(162),
        IEEE802_11_AVS(163),
        BACNET_MS_TP(165),
        PPP_PPPD(166),
        GPRS_LLC(169),
        GPF_T(170),
        GPF_F(171),
        LINUX_LAPD(177),
        BLUETOOTH_HCI_H4(187),
        USB_LINUX(189),
        PPI(192),
        IEEE802_15_4(195),
        SITA(196),
        ERF(197),
        BLUETOOTH_HCI_H4_WITH_PHDR(201),
        AX25_KISS(202),
        LAPD(203),
        PPP_WITH_DIR(204),
        C_HDLC_WITH_DIR(205),
        FRELAY_WITH_DIR(206),
        IPMB_LINUX(209),
        IEEE802_15_4_NONASK_PHY(215),
        USB_LINUX_MMAPPED(220),
        FC_2(224),
        FC_2_WITH_FRAME_DELIMS(225),
        IPNET(226),
        CAN_SOCKETCAN(227),
        IPV4(228),
        IPV6(229),
        IEEE802_15_4_NOFCS(230),
        DBUS(231),
        DVB_CI(235),
        MUX27010(236),
        STANAG_5066_D_PDU(237),
        NFLOG(239),
        NETANALYZER(240),
        NETANALYZER_TRANSPARENT(241),
        IPOIB(242),
        MPEG_2_TS(243),
        NG40(244),
        NFC_LLCP(245),
        INFINIBAND(247),
        SCTP(248),
        USBPCAP(249),
        RTAC_SERIAL(250),
        BLUETOOTH_LE_LL(251),
        NETLINK(253),
        BLUETOOTH_LINUX_MONITOR(254),
        BLUETOOTH_BREDR_BB(255),
        BLUETOOTH_LE_LL_WITH_PHDR(256),
        PROFIBUS_DL(257),
        PKTAP(258),
        EPON(259),
        IPMI_HPM_2(260),
        ZWAVE_R1_R2(261),
        ZWAVE_R3(262),
        WATTSTOPPER_DLM(263),
        ISO_14443(264);

        private final long id;

        Linktype(long id) {
            this.id = id;
        }

        public long id() {
            return id;
        }

        private static final Map<Long, Linktype> byId = new HashMap<>(104);

        static {
            for (Linktype e : Linktype.values())
                byId.put(e.id(), e);
        }

        public static Linktype byId(long id) {
            return byId.get(id);
        }
    }
}
