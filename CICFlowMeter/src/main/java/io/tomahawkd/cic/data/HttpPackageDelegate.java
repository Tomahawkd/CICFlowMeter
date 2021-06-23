package io.tomahawkd.cic.data;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.tcpip.Http;

public class HttpPackageDelegate extends AbstractPackageDelegate {

    public HttpPackageDelegate() {
        super(Http.ID);
    }

    @Override
    public void parse(PackageInfo dst, PcapPacket packet) {
        packet.scan(Ethernet.ID);
        Http http = new Http();
        if (!packet.hasHeader(http)) {
            throw new IllegalArgumentException("Not an HTTP header.");
        }

        dst.addFeature(MetaFeature.HTTP, true);
    }

    public enum Feature implements PackageFeature {

    }
}
