package io.tomahawkd.cic.data;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.tcpip.Http;

public class HttpPacketDelegate extends AbstractPacketDelegate {

    public HttpPacketDelegate() {
        super(Http.ID);
    }

    @Override
    public boolean parse(PacketInfo dst, PcapPacket packet) {
        Http http = new Http();
        if (!packet.hasHeader(http)) {
            return false;
        }

        dst.addFeature(MetaFeature.HTTP, true);
        if (!http.isResponse()) {
            dst.addFeature(Feature.REQUEST, true);
            try {
                dst.addFeature(Feature.CONTENT_LEN, Integer.parseInt(http.fieldValue(Http.Request.Content_Length)));
            } catch (NumberFormatException e) {
                dst.addFeature(Feature.CONTENT_LEN, 0);
            }
            dst.addFeature(Feature.METHOD, http.fieldValue(Http.Request.RequestMethod));
            dst.addFeature(Feature.UA, http.fieldValue(Http.Request.User_Agent));
            dst.addFeature(Feature.CONNECTION, http.fieldValue(Http.Request.Connection));
            dst.addFeature(Feature.CACHE, http.fieldValue(Http.Request.Cache_Control));
            dst.addFeature(Feature.URL, http.fieldValue(Http.Request.RequestUrl));
            dst.addFeature(Feature.CHARSET, http.fieldValue(Http.Request.Accept_Charset));
            dst.addFeature(Feature.REFERER, http.fieldValue(Http.Request.Referer));

        } else {
            dst.addFeature(Feature.REQUEST, false);
            try {
                dst.addFeature(Feature.CONTENT_LEN, Integer.parseInt(http.fieldValue(Http.Response.Content_Length)));
            } catch (NumberFormatException e) {
                dst.addFeature(Feature.CONTENT_LEN, 0);
            }
            dst.addFeature(Feature.STATUS, http.fieldValue(Http.Response.ResponseCode));
            dst.addFeature(Feature.CONTENT_TYPE, http.fieldValue(Http.Response.Content_Type));
        }
        return true;
    }

    public enum Feature implements PacketFeature {
        // Common
        CONTENT_LEN(Integer.class), REQUEST(Boolean.class),

        // Request
        UA(String.class), CONNECTION(String.class), CACHE(String.class), URL(String.class), CHARSET(String.class),
        REFERER(String.class), METHOD(String.class),

        // Response
        STATUS(Integer.class), CONTENT_TYPE(String.class);

        private final Class<?> type;

        Feature(Class<?> type) {
            this.type = type;
        }

        @Override
        public Class<?> getType() {
            return type;
        }
    }
}
