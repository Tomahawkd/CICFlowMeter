package io.tomahawkd.cic.data;

import com.google.common.primitives.Primitives;
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
        if (o == null) return null;
        if (type.isPrimitive()) {
            type = Primitives.wrap(type);
        }
        if (type.isAssignableFrom(o.getClass())) {
            return (T) o;
        } else {
            throw new RuntimeException("The expecting type " + type + " is not match with the object " + o.getClass());
        }
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

    public <T> boolean hasFeature(PackageFeature feature, Class<T> type) {
        if (!data.containsKey(feature)) return false;
        if (type.isPrimitive()) {
            type = Primitives.wrap(type);
        }
        return type.isAssignableFrom(data.get(feature).getClass());
    }

    public void finishParse() {
        // check compulsory elements
        if ((hasFeature(MetaFeature.IPV4, boolean.class) || hasFeature(MetaFeature.IPV6, boolean.class)) &&
                (hasFeature(MetaFeature.TCP, boolean.class) || hasFeature(MetaFeature.UDP, boolean.class)) &&
                //hasFeature(MetaFeature.HTTP, boolean.class) &&
                hasFeature(MetaFeature.SRC, byte[].class) &&
                hasFeature(MetaFeature.DST, byte[].class) &&
                hasFeature(MetaFeature.SRC_PORT, int.class) &&
                hasFeature(MetaFeature.DST_PORT, int.class) &&
                hasFeature(MetaFeature.PROTO, int.class) &&
                hasFeature(MetaFeature.HEADER_LEN, int.class) &&
                hasFeature(MetaFeature.PAYLOAD_LEN, int.class)) {

            generateFlowId();
        } else {
            throw new RuntimeException("Package is not complete.");
        }
    }

    private void generateFlowId() {
        boolean forward = true;
        byte[] src = getFeature(MetaFeature.SRC, byte[].class);
        byte[] dst = getFeature(MetaFeature.DST, byte[].class);
        int srcPort = getFeature(MetaFeature.SRC_PORT, int.class);
        int dstPort = getFeature(MetaFeature.DST_PORT, int.class);
        int protocol = getFeature(MetaFeature.PROTO, int.class);

        for (int i = 0; i < src.length; i++) {
            if (((Byte) (src[i])).intValue() != ((Byte) (dst[i])).intValue()) {
                if (((Byte) (src[i])).intValue() > ((Byte) (dst[i])).intValue()) {
                    forward = false;
                }
                i = src.length;
            }
        }

        if (forward) {
            this.flowId = this.getSourceIP() + "-" + this.getDestinationIP() + "-" + srcPort + "-" + dstPort + "-" + protocol;
        } else {
            this.flowId = this.getDestinationIP() + "-" + this.getSourceIP() + "-" + dstPort + "-" + srcPort + "-" + protocol;
        }
    }

    public String getSourceIP() {
        return FormatUtils.ip(getFeature(MetaFeature.SRC, byte[].class));
    }

    public String getDestinationIP() {
        return FormatUtils.ip(getFeature(MetaFeature.DST, byte[].class));
    }

    public String fwdFlowId() {
        int srcPort = getFeature(MetaFeature.SRC_PORT, int.class);
        int dstPort = getFeature(MetaFeature.DST_PORT, int.class);
        int protocol = getFeature(MetaFeature.PROTO, int.class);
        this.flowId = this.getSourceIP() + "-" + this.getDestinationIP() + "-" + srcPort + "-" + dstPort + "-" + protocol;
        return this.flowId;
    }

    public String bwdFlowId() {
        int srcPort = getFeature(MetaFeature.SRC_PORT, int.class);
        int dstPort = getFeature(MetaFeature.DST_PORT, int.class);
        int protocol = getFeature(MetaFeature.PROTO, int.class);
        this.flowId = this.getDestinationIP() + "-" + this.getSourceIP() + "-" + dstPort + "-" + srcPort + "-" + protocol;
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
        byte[] src = getFeature(MetaFeature.SRC, byte[].class);
        return Arrays.copyOf(src, src.length);
    }

    public byte[] getDst() {
        byte[] dst = getFeature(MetaFeature.DST, byte[].class);
        return Arrays.copyOf(dst, dst.length);
    }

    public int getSrcPort() {
        return getFeature(MetaFeature.SRC_PORT, int.class);
    }

    public int getDstPort() {
        return getFeature(MetaFeature.DST_PORT, int.class);
    }

    public int getProtocol() {
        return getFeature(MetaFeature.PROTO, int.class);
    }

    public boolean isForwardPacket(byte[] sourceIP) {
        return Arrays.equals(sourceIP, getFeature(MetaFeature.SRC, byte[].class));
    }

    public long getPayloadBytes() {
        return getFeature(MetaFeature.PAYLOAD_LEN, int.class);
    }

    public long getHeaderBytes() {
        return getFeature(MetaFeature.HEADER_LEN, int.class);
    }

    public int getPayloadPacket() {
        return payloadPacket += 1;
    }
}
