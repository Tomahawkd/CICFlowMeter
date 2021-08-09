package io.tomahawkd.cic.flow.features.http;

import io.tomahawkd.cic.packet.PacketInfo;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jnetpcap.protocol.tcpip.Http;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public class HttpPacketParser {

    private static final Logger logger = LogManager.getLogger(HttpPacketParser.class);

    public enum Status {
        INVALID, OK, INCOMPLETE
    }

    /**
     * Parse HTTP header
     *
     * @param dst features to be stored in
     * @param header header string
     * @param force if forcibly, the result should be {@link Status#INVALID} or {@link Status#OK}.
     *              Otherwise, it could be {@link Status#INCOMPLETE} and parse procedure would
     *              immediately stop while meet {@link Status#INCOMPLETE} condition.
     * @return Parse status.
     */
    public Status parseFeatures(PacketInfo dst, String header, boolean force) {
        if (header == null || header.isEmpty()) return Status.INVALID;

        // header should end with double CRLF (\r\n\r\n)
        // if forcibly, continue parsing
        boolean incomplete = header.endsWith("\r\n\r\n");
        if (!force && incomplete) return Status.INCOMPLETE;

        String[] headers = header.trim().split("\r\n");

        // the first line is not complete
        if (headers.length == 1 && !header.contains("\r\n")) {
            // forcibly parse incomplete header
            logger.warn("First line [{}] is not complete.", headers[0]);
            return incompleteHeader(force);
        }

        // first line elements should be 3 (2 for response since MESSAGE could be "")
        // Request: <METHOD> <PATH> HTTP/<VERSION>
        // Response: HTTP/<VERSION> <CODE> [<MESSAGE>]
        boolean request = !header.startsWith("HTTP");
        String[] firstLineElements = headers[0].split(" ", 3);
        if (firstLineElements.length != 3) {
            // request first line element must be 3
            if (request) {
                logger.warn("Request first line must be 3 but got {}", firstLineElements.length);
                return Status.INVALID;
            }

            // response first line element could be 2 and 3 but no other possibility
            if (firstLineElements.length != 2) {
                logger.warn("Response first line must be 2 or 3 but got {}", firstLineElements.length);
                return Status.INVALID;
            }
        }

        // since we ensure that the first line is complete, we could do other checks
        if (request) {
            String method = firstLineElements[0].toUpperCase(Locale.ROOT);
            if (!ArrayUtils.contains(HTTP_METHODS, method)) {
                logger.warn("Not a legal request header [{}]", header);
                return Status.INVALID;
            }
        }

        // remaining headers
        // here whether the first line is complete or
        // we parse it forcibly
        Map<String, String> headerMap = new HashMap<>();
        for (int i = 1; i < headers.length; i++) {
            String[] keyVal = headers[i].split(": ", 2);
            if (keyVal.length < 2) {
                logger.warn("Invalid header segment {}", headers[i]);
                if (!force) return Status.INCOMPLETE;
            } else {
                headerMap.put(keyVal[0].trim().toUpperCase(Locale.ROOT).replace('-', '_'), keyVal[1].trim());
            }
        }

        dst.addFeature(HttpPacketFeature.REQUEST, request);
        dst.addFeature(HttpPacketFeature.HEADER, headerMap);
        dst.addFeature(HttpPacketFeature.HEADER_LINE_COUNT, headerMap.size() + 1);

        if (request) {
            dst.addFeature(HttpPacketFeature.CONTENT_LEN, NumberUtils.toInt(getField(headerMap, Http.Request.Content_Length)));
            dst.addFeature(HttpPacketFeature.METHOD, firstLineElements[0]);
            dst.addFeature(HttpPacketFeature.UA, getField(headerMap, Http.Request.User_Agent));
            dst.addFeature(HttpPacketFeature.CONNECTION, getField(headerMap, Http.Request.Connection));
            dst.addFeature(HttpPacketFeature.CACHE, getField(headerMap, Http.Request.Cache_Control));
            dst.addFeature(HttpPacketFeature.PATH, firstLineElements[1]);
            dst.addFeature(HttpPacketFeature.HOST, getField(headerMap, Http.Request.Host));
            dst.addFeature(HttpPacketFeature.CHARSET, getField(headerMap, Http.Request.Accept_Charset));
            dst.addFeature(HttpPacketFeature.REFERER, getField(headerMap, Http.Request.Referer));
            dst.addFeature(HttpPacketFeature.LANGUAGE, getField(headerMap, Http.Request.Accept_Language));
            dst.addFeature(HttpPacketFeature.ENCODING, getField(headerMap, Http.Request.Accept_Encoding));
            // dst.addFeature(HttpPacketFeature.PROXY, getField(headerMap, Http.Request.Proxy_Connection));
            dst.addFeature(HttpPacketFeature.ACCEPT, getField(headerMap, Http.Request.Accept));
            dst.addFeature(HttpPacketFeature.CONTENT_TYPE, getField(headerMap, Http.Request.Content_Type));
            dst.addFeature(HttpPacketFeature.COOKIE, getField(headerMap, Http.Request.Cookie));
        } else {
            dst.addFeature(HttpPacketFeature.CONTENT_LEN, NumberUtils.toInt(getField(headerMap, Http.Response.Content_Length)));
            dst.addFeature(HttpPacketFeature.STATUS, firstLineElements[1]);
            dst.addFeature(HttpPacketFeature.CONTENT_TYPE, getField(headerMap, Http.Response.Content_Type));
            dst.addFeature(HttpPacketFeature.SET_COOKIE, getField(headerMap, Http.Response.Set_Cookie));
        }
        return Status.OK;
    }

    public Status incompleteHeader(boolean force) {
        if (force) return Status.INVALID;
        else return Status.INCOMPLETE;
    }

    private static String getField(Map<String, String> headers, Http.Request type) {
        return headers.get(type.name().toUpperCase(Locale.ROOT));
    }

    private static String getField(Map<String, String> headers, Http.Response type) {
        return headers.get(type.name().toUpperCase(Locale.ROOT));
    }

    // hard-coded
    private static final String[] HTTP_METHODS = {
            "GET", "POST", "HEAD", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"
    };
}
