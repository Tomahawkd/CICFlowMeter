package io.tomahawkd.cic.data;

import org.jnetpcap.packet.format.FormatUtils;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class PackageInfo {

    private final long id;
    private String flowId = "";
    private final Map<PackageFeature, Object> data;
    private long timestamp;
    private int payloadPacket = 0;

    // Cached Meta-data of the package
    private byte[] src;
    private byte[] dst;
    private int srcPort;
    private int dstPort;
    private int protocol;
    private int payloadLen;
    private int headerLen;

    public PackageInfo(long id) {
        data = new HashMap<>();
        this.id = id;
    }

    public Map<PackageFeature, Object> getMap() {
        return data;
    }

    public void addFeature(PackageFeature feature, Object data) {
        this.data.put(feature, data);
    }

    @SuppressWarnings("all")
    public <T> T getFeature(PackageFeature feature, Class<T> type) {
        Object o = data.get(feature);
        return (T) o;
    }

    @SuppressWarnings("all")
    public <T> T getFeatureOrDefault(PackageFeature feature, Class<T> type, T deflt) {
        try {
            T res = getFeature(feature, type);
            if (res == null) return deflt;
            else return res;
        } catch (RuntimeException e) {
            return deflt;
        }
    }

    public boolean hasFeature(PackageFeature feature) {
        return data.containsKey(feature);
    }

    public void finishParse() {
        // check compulsory elements
        if ((hasFeature(MetaFeature.IPV4) || hasFeature(MetaFeature.IPV6)) &&
                (hasFeature(MetaFeature.TCP) || hasFeature(MetaFeature.UDP)) &&
                //hasFeature(MetaFeature.HTTP, boolean.class) &&
                hasFeature(MetaFeature.SRC) &&
                hasFeature(MetaFeature.DST) &&
                hasFeature(MetaFeature.SRC_PORT) &&
                hasFeature(MetaFeature.DST_PORT) &&
                hasFeature(MetaFeature.PROTO) &&
                hasFeature(MetaFeature.HEADER_LEN) &&
                hasFeature(MetaFeature.PAYLOAD_LEN)) {

            this.src = getFeature(MetaFeature.SRC, byte[].class);
            this.dst = getFeature(MetaFeature.DST, byte[].class);
            this.srcPort = getFeature(MetaFeature.SRC_PORT, int.class);
            this.dstPort = getFeature(MetaFeature.DST_PORT, int.class);
            this.protocol = getFeature(MetaFeature.PROTO, int.class);
            this.payloadLen = getFeature(MetaFeature.PAYLOAD_LEN, int.class);
            this.headerLen = getFeature(MetaFeature.HEADER_LEN, int.class);
            generateFlowId();
        } else {
            throw new RuntimeException("Package is not complete.");
        }
    }

    private void generateFlowId() {
        boolean forward = true;

        for (int i = 0; i < this.src.length; i++) {
            if (((Byte) (this.src[i])).intValue() != ((Byte) (this.dst[i])).intValue()) {
                if (((Byte) (this.src[i])).intValue() > ((Byte) (this.dst[i])).intValue()) {
                    forward = false;
                }
                i = this.src.length;
            }
        }

        if (forward) {
            this.flowId = this.getSourceIP() + "-" + this.getDestinationIP() + "-" +
                    this.srcPort + "-" + this.dstPort + "-" + this.protocol;
        } else {
            this.flowId = this.getDestinationIP() + "-" + this.getSourceIP() + "-" +
                    this.dstPort + "-" + this.srcPort + "-" + this.protocol;
        }
    }

    public String getSourceIP() {
        return FormatUtils.ip(this.src);
    }

    public String getDestinationIP() {
        return FormatUtils.ip(this.dst);
    }

    public String fwdFlowId() {
        this.flowId = this.getSourceIP() + "-" + this.getDestinationIP() + "-" +
                this.srcPort + "-" + this.dstPort + "-" + this.protocol;
        return this.flowId;
    }

    public String bwdFlowId() {
        this.flowId = this.getDestinationIP() + "-" + this.getSourceIP() + "-" +
                this.dstPort + "-" + this.srcPort + "-" + this.protocol;
        return this.flowId;
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

    public boolean isForwardPacket(byte[] sourceIP) {
        return Arrays.equals(sourceIP, this.src);
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
}
