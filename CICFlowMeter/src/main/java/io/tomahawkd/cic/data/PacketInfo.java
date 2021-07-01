package io.tomahawkd.cic.data;

import org.jnetpcap.packet.format.FormatUtils;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class PacketInfo {

    private final long id;
    private String flowId = "";
    private final Map<PacketFeature, Object> data;
    private long timestamp;
    private int payloadPacket = 0;

    // Cached Meta-data of the package
    // typically we use the map above to store data, however, to make it
    // more faster we use pre-defined fields instead
    private byte[] src;
    private byte[] dst;
    private int srcPort;
    private int dstPort;
    private int protocol;
    private int payloadLen;
    private int headerLen;

    // tcp data
    private int tcpWindow;
    private int flags;

    // http data


    public PacketInfo(long id) {
        data = new HashMap<>();
        this.id = id;
    }

    public void addFeature(PacketFeature feature, Object data) {
        this.data.put(feature, data);
    }

    @SuppressWarnings("all")
    private <T> T get(PacketFeature feature, Class<T> type) {
        return (T) Objects.requireNonNull(data.get(feature));
    }

    public void finishParse() {
        this.src = get(MetaFeature.SRC, byte[].class);
        this.dst = get(MetaFeature.DST, byte[].class);
        this.srcPort = get(MetaFeature.SRC_PORT, int.class);
        this.dstPort = get(MetaFeature.DST_PORT, int.class);
        this.protocol = get(MetaFeature.PROTO, int.class);
        this.payloadLen = get(MetaFeature.PAYLOAD_LEN, int.class);
        this.headerLen = get(MetaFeature.HEADER_LEN, int.class);
        this.tcpWindow = get(TcpPacketDelegate.Feature.TCP_WINDOW, int.class);
        this.flags = get(TcpPacketDelegate.Feature.FLAG, int.class);
        generateFlowId();
    }

    private void generateFlowId() {
        this.flowId = this.getSourceIP() + "-" + this.getDestinationIP() + "-" +
                this.srcPort + "-" + this.dstPort + "-" + this.protocol;
    }

    public String getSourceIP() {
        return FormatUtils.ip(this.src);
    }

    public String getDestinationIP() {
        return FormatUtils.ip(this.dst);
    }

    public String fwdFlowId() {
        return this.getSourceIP() + "-" + this.getDestinationIP() + "-" +
                this.srcPort + "-" + this.dstPort + "-" + this.protocol;
    }

    public String bwdFlowId() {
        return this.getDestinationIP() + "-" + this.getSourceIP() + "-" +
                this.dstPort + "-" + this.srcPort + "-" + this.protocol;
    }

    public PacketInfo setFwd() {
        this.flowId = fwdFlowId();
        return this;
    }

    public PacketInfo setBwd() {
        this.flowId = bwdFlowId();
        return this;
    }

    public long getId() {
        return id;
    }

    public String getFlowId() {
        return flowId;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public byte[] getSrc() {
        return Arrays.copyOf(this.src, this.src.length);
    }

    public byte[] getDst() {
        return Arrays.copyOf(this.dst, this.dst.length);
    }

    public int getSrcPort() {
        return this.srcPort;
    }

    public int getDstPort() {
        return this.dstPort;
    }

    public int getProtocol() {
        return this.protocol;
    }

    public long getPayloadBytes() {
        return this.payloadLen;
    }

    public long getHeaderBytes() {
        return this.headerLen;
    }

    public int getPayloadPacket() {
        return payloadPacket += 1;
    }

    public int getTcpWindow() {
        return tcpWindow;
    }

    public boolean getFlag(int id) {
        return (flags & id) != 0;
    }

    // Copied from org.jnetpcap.protocol.tcpip.Tcp
    /**
     * The Constant FLAG_ACK.
     */
    public static final int FLAG_ACK = 0x10;

    /**
     * The Constant FLAG_CWR.
     */
    public static final int FLAG_CWR = 0x80;

    /**
     * The Constant FLAG_ECE.
     */
    public static final int FLAG_ECE = 0x40;

    /**
     * The Constant FLAG_FIN.
     */
    public static final int FLAG_FIN = 0x01;

    /**
     * The Constant FLAG_PSH.
     */
    public static final int FLAG_PSH = 0x08;

    /**
     * The Constant FLAG_RST.
     */
    public static final int FLAG_RST = 0x04;

    /**
     * The Constant FLAG_SYN.
     */
    public static final int FLAG_SYN = 0x02;

    /**
     * The Constant FLAG_URG.
     */
    public static final int FLAG_URG = 0x20;
}
