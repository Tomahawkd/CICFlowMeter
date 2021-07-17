package io.tomahawkd.cic.packet;

import nl.basjes.parse.useragent.UserAgent;
import nl.basjes.parse.useragent.UserAgentAnalyzer;
import org.apache.commons.lang3.math.NumberUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.tcpip.Http;

import java.util.HashMap;
import java.util.Map;

public class HttpPacketDelegate extends AbstractPacketDelegate {

    private static final Logger logger = LogManager.getLogger(HttpPacketDelegate.class);

    private final UserAgentAnalyzer uaa = UserAgentAnalyzer.newBuilder().hideMatcherLoadStats()
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

        String header = http.header();
        if (header == null) {
            logger.warn("Http Protocol with no header.");
            return false;
        }

        dst.addFeature(MetaFeature.HTTP, true);
        boolean request = !header.startsWith("HTTP");
        dst.addFeature(Feature.REQUEST, request);
        String[] headers = header.trim().split("\r\n");

        // first line
        String[] firstLineElements = headers[0].split(" ", 3);
        if (firstLineElements.length < 2) return false;

        // remaining headers
        Map<String, String> headerMap = new HashMap<>();
        for (int i = 1; i < headers.length; i++) {
            String[] keyVal = headers[i].split(": ", 2);
            if (keyVal.length < 2) {
                logger.warn("Invalid header segment {}", headers[i]);
            } else {
                headerMap.put(keyVal[0].trim(), keyVal[1].trim());
            }
        }
        dst.addFeature(Feature.HEADER, headerMap);

        if (request) {
            dst.addFeature(Feature.CONTENT_LEN, NumberUtils.toInt(http.fieldValue(Http.Request.Content_Length)));
            dst.addFeature(Feature.METHOD, firstLineElements[0]);
            dst.addFeature(Feature.UA, parseUserAgent(http.fieldValue(Http.Request.User_Agent)));
            dst.addFeature(Feature.CONNECTION, http.fieldValue(Http.Request.Connection));
            dst.addFeature(Feature.CACHE, http.fieldValue(Http.Request.Cache_Control));
            dst.addFeature(Feature.PATH, firstLineElements[1]);
            dst.addFeature(Feature.HOST, http.fieldValue(Http.Request.Host));
            dst.addFeature(Feature.CHARSET, http.fieldValue(Http.Request.Accept_Charset));
            dst.addFeature(Feature.REFERER, http.fieldValue(Http.Request.Referer));
            dst.addFeature(Feature.LANGUAGE, http.fieldValue(Http.Request.Accept_Language));
            dst.addFeature(Feature.ENCODING, http.fieldValue(Http.Request.Accept_Encoding));
            dst.addFeature(Feature.PROXY, http.fieldValue(Http.Request.Proxy_Connection));
            dst.addFeature(Feature.CONTENT_TYPE, http.fieldValue(Http.Request.Accept));
        } else {
            dst.addFeature(Feature.CONTENT_LEN, NumberUtils.toInt(http.fieldValue(Http.Response.Content_Length)));
            dst.addFeature(Feature.STATUS, firstLineElements[1]);
            dst.addFeature(Feature.CONTENT_TYPE, http.fieldValue(Http.Response.Content_Type));
        }
        return true;
    }

    public enum Feature implements PacketFeature {
        // Common
        CONTENT_LEN(Integer.class), REQUEST(Boolean.class), HEADER(Map.class),

        // for request it refers header Accept
        CONTENT_TYPE(String.class),

        // Request
        UA(UserAgent.class), CONNECTION(String.class), CACHE(String.class), CHARSET(String.class),
        REFERER(String.class), METHOD(String.class), LANGUAGE(String.class), ENCODING(String.class),
        PROXY(String.class), PATH(String.class), HOST(String.class),

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
