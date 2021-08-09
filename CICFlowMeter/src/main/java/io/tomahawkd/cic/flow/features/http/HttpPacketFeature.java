package io.tomahawkd.cic.flow.features.http;

import io.tomahawkd.cic.packet.PacketFeature;

import java.util.Map;

public enum HttpPacketFeature implements PacketFeature {

    INVALID(Boolean.class),

    // Common
    CONTENT_LEN(Integer.class), REQUEST(Boolean.class), HEADER(Map.class), HEADER_LINE_COUNT(Integer.class),

    // for request it refers header Accept
    CONTENT_TYPE(String.class),

    // Request
    UA(String.class), CONNECTION(String.class), CACHE(String.class), CHARSET(String.class),
    REFERER(String.class), METHOD(String.class), LANGUAGE(String.class), ENCODING(String.class),
    PROXY(String.class), PATH(String.class), HOST(String.class), COOKIE(String.class), ACCEPT(String.class),

    // Response
    STATUS(String.class), SET_COOKIE(String.class);

    private final Class<?> type;

    HttpPacketFeature(Class<?> type) {
        this.type = type;
    }

    @Override
    public Class<?> getType() {
        return type;
    }
}
