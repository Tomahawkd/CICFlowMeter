package io.tomahawkd.cic.packet;

import io.tomahawkd.cic.util.UserAgentAnalyzerHelper;
import nl.basjes.parse.useragent.UserAgent;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.tcpip.Http;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

@Layer(LayerType.APPLICATION)
public class HttpPacketDelegate extends AbstractPacketDelegate {

    private static final Logger logger = LogManager.getLogger(HttpPacketDelegate.class);

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

        return parseFeatures(dst, header, false);
    }

    // return is valid
    public static boolean parseFeatures(PacketInfo dst, String header, boolean force) {
        boolean incomplete = false;
        String[] headers = header.trim().split("\r\n");
        String[] firstLineElements = headers[0].split(" ", 3);
        if (firstLineElements.length != 3) {
            logger.warn("Not a legal header [{}]", header);
            incomplete = true;
        }

        boolean request = !header.startsWith("HTTP");
        if (request) {
            String method = header.substring(0, HTTP_METHODS_STRING_MAX_LEN).split(" ", 2)[0]
                    .toUpperCase(Locale.ROOT);
            if (!ArrayUtils.contains(HTTP_METHODS, method)) {
                logger.warn("Not a legal request header [{}]", header);
                return false;
            }
        }

        // remaining headers
        Map<String, String> headerMap = new HashMap<>();
        for (int i = 1; i < headers.length; i++) {
            String[] keyVal = headers[i].split(": ", 2);
            if (keyVal.length < 2) {
                logger.warn("Invalid header segment {}", headers[i]);
                incomplete = true;
            } else {
                headerMap.put(keyVal[0].trim().toUpperCase(Locale.ROOT).replace('-', '_'), keyVal[1].trim());
            }
        }

        dst.addFeature(MetaFeature.HTTP, true);
        dst.addFeature(Feature.REQUEST, request);
        dst.addFeature(Feature.HEADER, headerMap);
        if (incomplete) {
            dst.addFeature(Feature.INCOMPLETE, true);
            dst.addFeature(Feature.INCOM_SEGMENT, header);
            if (!force) return true;
        } else {
            dst.addFeature(Feature.INCOMPLETE, false);
        }

        if (request) {
            dst.addFeature(Feature.CONTENT_LEN, NumberUtils.toInt(getField(headerMap, Http.Request.Content_Length)));
            dst.addFeature(Feature.METHOD, firstLineElements[0]);
            dst.addFeature(Feature.UA, UserAgentAnalyzerHelper.INSTANCE.parseUserAgent(getField(headerMap, Http.Request.User_Agent)));
            dst.addFeature(Feature.CONNECTION, getField(headerMap, Http.Request.Connection));
            dst.addFeature(Feature.CACHE, getField(headerMap, Http.Request.Cache_Control));
            dst.addFeature(Feature.PATH, firstLineElements[1]);
            dst.addFeature(Feature.HOST, getField(headerMap, Http.Request.Host));
            dst.addFeature(Feature.CHARSET, getField(headerMap, Http.Request.Accept_Charset));
            dst.addFeature(Feature.REFERER, getField(headerMap, Http.Request.Referer));
            dst.addFeature(Feature.LANGUAGE, getField(headerMap, Http.Request.Accept_Language));
            dst.addFeature(Feature.ENCODING, getField(headerMap, Http.Request.Accept_Encoding));
            // dst.addFeature(Feature.PROXY, getField(headerMap, Http.Request.Proxy_Connection));
            dst.addFeature(Feature.CONTENT_TYPE, getField(headerMap, Http.Request.Accept));
        } else {
            dst.addFeature(Feature.CONTENT_LEN, NumberUtils.toInt(getField(headerMap, Http.Response.Content_Length)));
            dst.addFeature(Feature.STATUS, firstLineElements[1]);
            dst.addFeature(Feature.CONTENT_TYPE, getField(headerMap, Http.Response.Content_Type));
        }
        return true;
    }

    private static String getField(Map<String, String> headers, Http.Request type) {
        return headers.get(type.name().toUpperCase(Locale.ROOT));
    }

    private static String getField(Map<String, String> headers, Http.Response type) {
        return headers.get(type.name().toUpperCase(Locale.ROOT));
    }

    public enum Feature implements PacketFeature {
        // Common
        CONTENT_LEN(Integer.class), REQUEST(Boolean.class), HEADER(Map.class),

        // resolve TCP reassemble
        INCOMPLETE(Boolean.class), INCOM_SEGMENT(String.class),

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

    // hard-coded
    private static final int HTTP_METHODS_STRING_MAX_LEN = 7;
    private static final String[] HTTP_METHODS = {
            "GET", "POST", "HEAD", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"
    };
}
