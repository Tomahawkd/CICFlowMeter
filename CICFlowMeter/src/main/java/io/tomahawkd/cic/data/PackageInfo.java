package io.tomahawkd.cic.data;

import org.jnetpcap.packet.format.FormatUtils;

import java.util.HashMap;
import java.util.Map;

public class PackageInfo {

    private long id;
    private String flowId = "";
    private final Map<PackageFeature, Object> data;
    private long timestamp;

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
        if (type.isAssignableFrom(o.getClass())) {
            return (T) o;
        } else {
            throw new RuntimeException("The expecting type " + type + " is not match with the object " + o.getClass());
        }
    }

    public <T> boolean hasFeature(PackageFeature feature, Class<T> type) {
        if (!data.containsKey(feature)) return false;
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
                hasFeature(MetaFeature.PROTO, int.class)) {

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
}
