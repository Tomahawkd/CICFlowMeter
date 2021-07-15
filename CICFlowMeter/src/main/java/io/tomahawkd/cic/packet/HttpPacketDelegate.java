package io.tomahawkd.cic.packet;

import nl.basjes.parse.useragent.UserAgent;
import nl.basjes.parse.useragent.UserAgentAnalyzer;
import org.apache.commons.lang3.math.NumberUtils;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.tcpip.Http;

public class HttpPacketDelegate extends AbstractPacketDelegate {

    private static final UserAgentAnalyzer uaa = UserAgentAnalyzer.newBuilder().hideMatcherLoadStats()
            .withCache(10000).build();

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
        dst.addFeature(Feature.HEADER, http.header());
        if (!http.isResponse()) {
            dst.addFeature(Feature.REQUEST, true);
            dst.addFeature(Feature.CONTENT_LEN, NumberUtils.toInt(http.fieldValue(Http.Request.Content_Length)));
            dst.addFeature(Feature.METHOD, http.fieldValue(Http.Request.RequestMethod));
            dst.addFeature(Feature.UA, parseUserAgent(http.fieldValue(Http.Request.User_Agent)));
            dst.addFeature(Feature.CONNECTION, http.fieldValue(Http.Request.Connection));
            dst.addFeature(Feature.CACHE, http.fieldValue(Http.Request.Cache_Control));
            dst.addFeature(Feature.URL, http.fieldValue(Http.Request.RequestUrl));
            dst.addFeature(Feature.HOST, http.fieldValue(Http.Request.Host));
            dst.addFeature(Feature.CHARSET, http.fieldValue(Http.Request.Accept_Charset));
            dst.addFeature(Feature.REFERER, http.fieldValue(Http.Request.Referer));
            dst.addFeature(Feature.LANGUAGE, http.fieldValue(Http.Request.Accept_Language));
            dst.addFeature(Feature.ENCODING, http.fieldValue(Http.Request.Accept_Encoding));
            dst.addFeature(Feature.PROXY, http.fieldValue(Http.Request.Proxy_Connection));
            dst.addFeature(Feature.CONTENT_TYPE, http.fieldValue(Http.Request.Accept));
        } else {
            dst.addFeature(Feature.REQUEST, false);
            dst.addFeature(Feature.CONTENT_LEN, NumberUtils.toInt(http.fieldValue(Http.Response.Content_Length)));
            dst.addFeature(Feature.STATUS, http.fieldValue(Http.Response.ResponseCode));
            dst.addFeature(Feature.CONTENT_TYPE, http.fieldValue(Http.Response.Content_Type));
        }
        return true;
    }

    public enum Feature implements PacketFeature {
        // Common
        CONTENT_LEN(Integer.class), REQUEST(Boolean.class), HEADER(String.class),

        // for request it refers header Accept
        CONTENT_TYPE(String.class),

        // Request
        UA(UserAgent.class), CONNECTION(String.class), CACHE(String.class), CHARSET(String.class),
        REFERER(String.class), METHOD(String.class), LANGUAGE(String.class), ENCODING(String.class),
        PROXY(String.class), URL(String.class), HOST(String.class),

        // Response
        STATUS(String.class);

        private final Class<?> type;

        Feature(Class<?> type) {
            this.type = type;
        }

        @Override
        public Class<?> getType() {
            return type;
        }
    }

    private UserAgent parseUserAgent(String ua) {
        return ua != null? uaa.parse(ua): null;
    }
}
