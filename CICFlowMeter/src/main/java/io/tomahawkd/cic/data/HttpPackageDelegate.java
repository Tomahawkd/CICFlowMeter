package io.tomahawkd.cic.data;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.tcpip.Http;

public class HttpPackageDelegate extends AbstractPackageDelegate {

    public HttpPackageDelegate() {
        super(Http.ID);
    }

    @Override
    public boolean parse(PackageInfo dst, PcapPacket packet) {
        Http http = new Http();
        if (!packet.hasHeader(http)) {
            return false;
        }

        dst.addFeature(MetaFeature.HTTP, true);
        return true;
    }

    public enum Feature implements PackageFeature {

    }
}
