package io.tomahawkd.cic.pcap.parse;

import java.util.HashMap;
import java.util.Map;

public enum LinkType {

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

    LinkType(long id) {
        this.id = id;
    }

    public long id() {
        return id;
    }

    private static final Map<Long, LinkType> byId = new HashMap<>(104);

    static {
        for (LinkType e : LinkType.values())
            byId.put(e.id(), e);
    }

    public static LinkType byId(long id) {
        return byId.get(id);
    }
}
