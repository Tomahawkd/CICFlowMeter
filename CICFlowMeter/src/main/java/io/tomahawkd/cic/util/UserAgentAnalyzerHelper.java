package io.tomahawkd.cic.util;

import nl.basjes.parse.useragent.UserAgent;
import nl.basjes.parse.useragent.UserAgentAnalyzer;

public enum UserAgentAnalyzerHelper {

    INSTANCE;

    private final UserAgentAnalyzer uaa;

    UserAgentAnalyzerHelper() {
        this.uaa = UserAgentAnalyzer.newBuilder().hideMatcherLoadStats()
                .withCache(10000).build();
    }

    public UserAgentAnalyzer getUaa() {
        return uaa;
    }

    public UserAgent parseUserAgent(String ua) {
        return ua != null? uaa.parse(ua): null;
    }
}
