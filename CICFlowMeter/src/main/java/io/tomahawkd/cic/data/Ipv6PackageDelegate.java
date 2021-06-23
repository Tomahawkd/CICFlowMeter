package io.tomahawkd.cic.data;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Ip6;

public class Ipv6PackageDelegate extends AbstractPackageDelegate {

    public Ipv6PackageDelegate() {
        super(Ip6.ID);
    }

    @Override
    public void parse(PackageInfo dst, PcapPacket packet) {
        packet.scan(Ip6.ID);
        Ip6 ipv6 = new Ip6();
        if (!packet.hasHeader(ipv6)) {
            throw new IllegalArgumentException("Not an IPv6 header.");
        }

        dst.addFeature(MetaFeature.SRC, ipv6.source());
        dst.addFeature(MetaFeature.DST, ipv6.destination());
        dst.addFeature(MetaFeature.IPV6, true);
    }

    enum Feature implements PackageFeature {
        SRC, DST
    }

}
